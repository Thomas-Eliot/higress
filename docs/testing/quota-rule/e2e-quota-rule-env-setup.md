# QuotaRule e2e 环境准备 Runbook

**适用场景**：在新 namespace（或被清理过的 ns）里从 0 准备 QuotaRule e2e 测试环境。

**目标**：依次跑完后，[测试报告](./e2e-quota-rule-test-report-20260615.md)里的所有测试用例可直接复跑。

---

## 0. 前置假设

下文 `$NS` 指目标 namespace（如 `ls-test2`）。

集群层面已具备：
- `higress-system` ns 有 `redis-builtin-0`（auth 已知）+ `higress-plugin-server`
- 目标 `$NS` 通过 helm 部署了 higress 基础栈：`deploy/higress-controller`、`deploy/higress-gateway`、`svc/envoy-hs`（headless 8081）、`svc/higress-gateway`（含 SLB 80）、`cm/higress-config`、`wasmplugin/key-auth.internal`

如果连 helm 部署都没做过，先按 helm chart 拉起来再回到本 doc。

---

## 1. 关键变量

```bash
NS=ls-test2
CLUSTER_ID=Kubernetes                                       # 必须大写 K
REDIS_HOST=redis-builtin.higress-system.svc.cluster.local
REDIS_PORT=6379
REDIS_AUTH=1905b762fd25c8a5
QUOTA_SERVER_IMAGE=registry.cn-shanghai.aliyuncs.com/daofeng/ratelimit-quota-server:clientid-unify-20260615
# digest: sha256:7301f97eb1be9e7f632a3ba909e7fd0ccdf2d7804572192275c47fb02f478929
DOMAIN="${CLUSTER_ID}-quotarule"                            # = Kubernetes-quotarule
RATELIMIT_CM="$(echo $CLUSTER_ID | tr A-Z a-z)-ratelimit-config"  # = kubernetes-ratelimit-config
```

---

## 2. Controller patch（一次性，helm upgrade 后需重打）

```bash
# 2.1 把 --clusterID args 改成大写
IDX=$(kubectl get deploy -n $NS higress-controller -o json | \
  python3 -c 'import json,sys; d=json.load(sys.stdin); a=d["spec"]["template"]["spec"]["containers"][0]["args"]; print([i for i,x in enumerate(a) if "clusterID" in x][0])')
kubectl patch deploy higress-controller -n $NS --type=json \
  -p="[{\"op\":\"replace\",\"path\":\"/spec/template/spec/containers/0/args/${IDX}\",\"value\":\"--clusterID=${CLUSTER_ID}\"}]"

# 2.2 必备 env
kubectl set env -n $NS deploy/higress-controller -c higress \
  QUOTA_GATEWAY_ENDPOINTS_NAME=envoy-hs \
  WATCH_RESOURCES_BY_NAMESPACE_FOR_PRIMARY_CLUSTER=$NS

kubectl rollout status -n $NS deploy/higress-controller --timeout=180s
```

**为什么**：
- `--clusterID` args 优先级高于 env `CLUSTER_ID`，不对齐会导致 ConfigMap 名 / Redis domain 三方不一致
- 不设 `QUOTA_GATEWAY_ENDPOINTS_NAME=envoy-hs`，controller 报 `envoy endpoints length is 0` 啥都不下发（`GetEndpointsName()` 用 `strings.Replace(features.ClusterName, "istio", "envoy-hs", 1)` 处理非 istio cluster-id 时返回原值）

校验：
```bash
kubectl logs -n $NS -l app=higress-controller -c higress --since=2m \
  | grep -E "envoy endpoints length|gatewayEnvoyEndpoint"
# 期待：gatewayEnvoyEndpointCount=1
# 不期待：envoy endpoints length is 0
```

如有一个 pod 持续报 0：直接 `kubectl delete pod` 让 endpoints informer 重新 warmup。

---

## 3. Gateway readinessProbe 改 tcpSocket

```bash
kubectl patch deploy higress-gateway -n $NS --type=json -p='[
  {"op":"replace","path":"/spec/template/spec/containers/0/readinessProbe","value":{
    "tcpSocket":{"port":80},
    "initialDelaySeconds":5,
    "periodSeconds":3,
    "timeoutSeconds":3,
    "failureThreshold":10,
    "successThreshold":1
  }}
]'
```

**为什么**：默认 readinessProbe 走 `curl localhost:15000/ready`，envoy listener 80 等 wasm filter init（key-auth.internal ECDS + 跨 ns wasm fetch）常卡 INITIALIZING ≥ 5 分钟，rolling update 不收敛。改 tcpSocket 80 一 bind 端口就 ready。

---

## 4. 跨 ns ExternalName

```bash
kubectl apply -n $NS -f - <<EOF
apiVersion: v1
kind: Service
metadata:
  name: higress-plugin-server
spec:
  type: ExternalName
  externalName: higress-plugin-server.higress-system.svc.cluster.local
  ports:
    - port: 80
      protocol: TCP
      targetPort: 80
EOF
```

**为什么**：controller 拉 wasm bytes 用短名 `http://higress-plugin-server/...`，新 ns 没这个 svc → DNS 失败 → ECDS 推不出去 → listener 80 init 卡死。

---

## 5. 关掉拖死 listener 的 wasmplugin

```bash
kubectl patch wasmplugin -n $NS key-auth.internal --type=merge \
  -p='{"spec":{"defaultConfigDisable":true}}'
```

**为什么**：`key-auth.internal` defaultConfig 缺 `consumers` → wasm parseConfig 失败 → envoy `Unable to create Wasm HTTP filter` → 整个 listener 80 update 被拒（quota filter 也连带进不去）。如业务需要 key-auth，给 defaultConfig 补一个 dummy consumer 让 parse 过。

---

## 6. higress-config 的 mcpServer redis 改可达地址

```bash
TMP=$(mktemp)
kubectl get cm -n $NS higress-config -o yaml > $TMP

sed -i.bak \
  -e "s|address: redis-builtin\..*\.svc\.cluster\.local:6379|address: ${REDIS_HOST}:${REDIS_PORT}|g" \
  -e "/mcpServer:/,/match_list:/{ s|password: .*|password: ${REDIS_AUTH}|; }" \
  $TMP

kubectl apply -f $TMP
kubectl rollout restart -n $NS deploy/higress-gateway
kubectl rollout status -n $NS deploy/higress-gateway --timeout=180s
```

**为什么**：helm chart 默认 `mcpServer.redis.address` 可能写的是历史 ns（如 `redis-builtin.ls-test`），目标 ns 没那个 svc，gateway 反复刷 `Failed to reconnect to Redis: no such host`，污染日志（但 curl 仍能通）。

---

## 7. 部署 quota-server

```bash
QIDX=$(kubectl get deploy -n $NS higress-gateway -o json | \
  python3 -c 'import json,sys; d=json.load(sys.stdin); print([i for i,c in enumerate(d["spec"]["template"]["spec"]["containers"]) if c["name"]=="quota-server"][0])')

kubectl set image -n $NS deploy/higress-gateway quota-server=$QUOTA_SERVER_IMAGE

kubectl patch deploy higress-gateway -n $NS --type=json \
  -p="[{\"op\":\"replace\",\"path\":\"/spec/template/spec/containers/${QIDX}/imagePullPolicy\",\"value\":\"Always\"}]"

kubectl rollout status -n $NS deploy/higress-gateway --timeout=180s
```

**镜像选择**：必须用 immutable tag（不要 `:latest`，digest 历史飘动过）。当前推荐 `clientid-unify-20260615`，包含：
- IANA tzdata 嵌入 binary（不依赖系统包）
- SyncCheck / AllocQuotas client ID 统一（修复非 sidecar 模式的 HGET miss 漏洞）

源码改动 + build 流程见 [incident-replay §六 quota-server 镜像 build & 部署](../../operations/incident-replay-6.10-flow-on-ls-test2-20260615.md#六quota-server-镜像-build--部署已沉淀)。

---

## 8. 测试后端

```bash
kubectl apply -n $NS -f - <<'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: echo-server
spec:
  replicas: 1
  selector: { matchLabels: { app: echo-server } }
  template:
    metadata: { labels: { app: echo-server } }
    spec:
      containers:
        - name: echo-server
          image: ealen/echo-server:latest
          ports: [{ containerPort: 3000 }]
---
apiVersion: v1
kind: Service
metadata:
  name: echo-server
spec:
  selector: { app: echo-server }
  ports: [{ port: 80, targetPort: 3000 }]
EOF
```

> ⚠️ **echo-server 在高并发请求下会返回 400**（对 hey 默认 headers 不友好）。**测试用串行请求**而非 `hey -c N` 并发，避开后端干扰。详见 [测试报告 §测试方法](./e2e-quota-rule-test-report-20260615.md#测试方法学)。

---

## 9. 手工 Gateway + VirtualService（绕开 controller bug）

```bash
kubectl apply -n $NS -f - <<EOF
apiVersion: networking.istio.io/v1alpha3
kind: Gateway
metadata:
  name: echo-server-gateway
spec:
  selector:
    higress: ${NS}-higress-gateway
  servers:
    - hosts: ["*"]
      port: { name: http-80, number: 80, protocol: HTTP }
---
apiVersion: networking.istio.io/v1alpha3
kind: VirtualService
metadata:
  name: echo-server-vs
spec:
  gateways: [${NS}/echo-server-gateway]
  hosts: ["*"]
  http:
    - name: echo-server
      match: [{ uri: { prefix: /echo } }]
      route:
        - destination:
            host: echo-server.${NS}.svc.cluster.local
            port: { number: 80 }
EOF
```

**为什么**：higress controller 把 ingress 转 VS 时，VS 的 `gateways` 字段引用名是 `$NS/<hash>`，但实际生成的 Gateway 资源叫 `${CLUSTER_ID}-<hash>`（带 cluster_id 前缀），名字对不上 → pilot SRDS 生成不出 scope → listener 80 没 route → SLB 全 404。controller 修好后本节可删。

---

## 10. QuotaRule CR（动态 consumer 形态）

```bash
kubectl apply -n $NS -f - <<EOF
apiVersion: networking.istio.io/v1alpha3
kind: QuotaRule
metadata:
  name: test-quota
spec:
  redis_info:
    redis_url: "${REDIS_HOST}:${REDIS_PORT}"
    redis_auth: "${REDIS_AUTH}"
  rules:
    - match:
        - name: consumer-limit
          headers:
            items:
              - name: x-consumer
                match_type: ANY
      rate_limit:
        requests_per_unit: 100
        unit: MINUTE
        quota_dimension: request
        dynamic: true
      dimensions:
        - short_name: cu
          source:
            request_header: x-consumer
          limit:
            dynamic: true
            fallback:
              requests_per_unit: 100
              unit: MINUTE
              quota_dimension: request
      target:
        routes:
          - echo-server
EOF
```

**为什么是动态形态**：静态形态（无 `dimensions`）controller 走 legacy path **不生成 bucket_matchers**，envoy quota filter 没法 bucket request，限流逻辑空转。动态形态走 multi-dim path 生成 per-route override 含 bucket_matchers。

---

## 11. Redis 写动态配额

```bash
kubectl exec -n higress-system redis-builtin-0 -- redis-cli -a "${REDIS_AUTH}" --no-auth-warning HSET \
  "rl_dc:${DOMAIN}:cu_alice" unit MINUTE requests_per_unit 50 quota_dimension request

kubectl exec -n higress-system redis-builtin-0 -- redis-cli -a "${REDIS_AUTH}" --no-auth-warning HSET \
  "rl_dc:${DOMAIN}:cu_bob" unit MINUTE requests_per_unit 200 quota_dimension request
```

---

## 12. Sanity Check（每条不通就别往下走）

```bash
GW_POD=$(kubectl get pod -n $NS -l app=higress-gateway -o jsonpath='{.items[0].metadata.name}')

# 12.1 controller reconcile 正常
kubectl logs -n $NS -l app=higress-controller -c higress --since=2m \
  | grep -E "quotarule Conversion summary"
# 期待：quotaRuleCRs=1 gatewayEnvoyEndpointCount=1 envoyFilterResources=2

# 12.2 ConfigMap 有完整 dynamic 配置
kubectl get cm -n $NS $RATELIMIT_CM -o jsonpath='{.data.config\.yaml}'
# 期待：bucket_id: {cu: '*'}、limit_source: remote、parallel_dimensions

# 12.3 envoy listener 80 有 quota filter
kubectl exec -n $NS $GW_POD -c higress-gateway -- curl -s http://localhost:15000/config_dump \
  | grep -c rate_limit_quota_apig
# 期待：≥ 2

# 12.4 envoy admin listeners 含 80
kubectl exec -n $NS $GW_POD -c higress-gateway -- curl -s http://localhost:15000/listeners
# 期待：0.0.0.0_80::0.0.0.0:80

# 12.5 quota-server 加载了 cu_* bucket_action
kubectl logs -n $NS $GW_POD -c quota-server | grep "Loaded config:" | tail -3
# 期待：cu_*_100_minute_request

# 12.6 envoy 状态 LIVE
kubectl exec -n $NS $GW_POD -c higress-gateway -- curl -s http://localhost:15000/ready
# 期待：LIVE

# 12.7 SLB 探测
SLB_IP=$(kubectl get svc -n $NS higress-gateway -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
curl -s -o /dev/null -w "%{http_code}\n" -H "x-consumer: alice" http://$SLB_IP/echo
# 期待：200
```

若 12.7 返 429 + `response_code_details: quota_rate_limited`：
- 看 12.5 是否加载了正确 bucket_action
- 若 quota-server log 报 `unknown bucket_id 'cu_alice'` → ConfigMap 改后 watcher 只 reload 了 control-plane 部分，**重启 gateway pod 触发全量 reload**：`kubectl delete pod -n $NS $GW_POD`

---

## 13. 已知问题速查表

| 症状 | 原因 | 处理 |
|---|---|---|
| controller `envoy endpoints length is 0` | 第 2 节 env 漏配 | 补 `QUOTA_GATEWAY_ENDPOINTS_NAME=envoy-hs` |
| 一个 controller pod 正常一个不正常 | endpoints informer 没 warmup | `kubectl delete pod` 异常 pod |
| envoy listener 80 不存在或 reject | wasm 拖死 LDS | 第 4 节 ExternalName + 第 5 节 disable wasmplugin |
| envoy `/ready` INITIALIZING ≥ 5min | readinessProbe + wasm dep | 第 3 节 tcpSocket + 第 4 节 ExternalName |
| SLB 打 /echo 全 404 | SRDS scope=0（VS gateways 名字对不上 Gateway） | 第 9 节手工 apply |
| listener 上 quota filter 不见 | controller global EnvoyFilter push 不稳 | 手工 apply 等价 K8s EnvoyFilter |
| quota-server log `unknown bucket_id 'cu_alice'` | ConfigMap 改后 watcher 部分 reload | `kubectl delete pod` gateway 触发全量 reload |
| 并发压测看到很多 400 | echo-server 后端在并发下返 400 | **改用串行测试**（见测试报告 §测试方法） |

---

## 附录：完整脚本化方向

把第 2-11 节命令塞进 `setup-quota-rule.sh`，变量化 `$NS` / `$CLUSTER_ID` / `$REDIS_*` / `$QUOTA_SERVER_IMAGE`，下次新 ns 一键拉起。

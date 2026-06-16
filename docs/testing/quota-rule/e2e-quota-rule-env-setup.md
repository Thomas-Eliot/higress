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

# 2.3 ⚠️ 改完 env 后必须删 controller pod，让 endpoints informer 重新 warmup（见下方"为什么"）
kubectl delete pod -n $NS -l app=higress-controller
```

> `QUOTA_GATEWAY_ENDPOINTS_NAME` 取值 = **Endpoints 资源含网关 envoy Pod IP 的 Service 名**。有 headless `envoy-hs` 用它；若该 ns 没有（如裸部署），用 `higress-gateway`（LB Service 的 Endpoints 即网关 Pod）。校验：`kubectl get endpoints -n $NS <name>` 有 Pod IP。

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

> ⚠️ **先升级网关/控制器镜像到 quota-rule 形态**（helm 默认基线镜像如 `daofeng/*:2.1.12` 不含 `rate_limit_quota_apig` filter / 不认 QuotaRule CRD）：
> ```bash
> REG=registry.cn-shanghai.aliyuncs.com/daofeng
> kubectl set image -n $NS deploy/higress-controller higress=$REG/higress:quota-rule discovery=$REG/pilot:quota-rule
> kubectl set image -n $NS deploy/higress-gateway   higress-gateway=$REG/gateway:quota-rule
> kubectl rollout status -n $NS deploy/higress-controller --timeout=180s
> kubectl rollout status -n $NS deploy/higress-gateway   --timeout=180s
> ```

### 7.1 quota-server 容器已存在（helm 部署过）→ 仅换镜像

```bash
QIDX=$(kubectl get deploy -n $NS higress-gateway -o json | \
  python3 -c 'import json,sys; d=json.load(sys.stdin); print([i for i,c in enumerate(d["spec"]["template"]["spec"]["containers"]) if c["name"]=="quota-server"][0])')
kubectl set image -n $NS deploy/higress-gateway quota-server=$QUOTA_SERVER_IMAGE
kubectl patch deploy higress-gateway -n $NS --type=json \
  -p="[{\"op\":\"replace\",\"path\":\"/spec/template/spec/containers/${QIDX}/imagePullPolicy\",\"value\":\"Always\"}]"
kubectl rollout status -n $NS deploy/higress-gateway --timeout=180s
```

### 7.2 quota-server 容器不存在（裸部署）→ 手动加 sidecar

helm 基线若未带 quota-server 容器（`kubectl get pod … -o jsonpath` 只看到 `higress-gateway nginx`），需手动 strategic patch 加入。**关键：用 `subPath` 把 ratelimit ConfigMap 的 `config.yaml` 精确覆盖到镜像自带的空默认配置文件**，否则 quota-server 读到空配置、报 `config file cannot have empty domain` 并回落 `localhost:6379`。RLQS cluster 固定 `STRICT_DNS → 127.0.0.1:8081`，故必须以 sidecar 形态跑在网关 Pod 内、监听 8081。

```bash
kubectl patch deploy higress-gateway -n $NS --type=strategic -p '{
  "spec":{"template":{"spec":{
    "containers":[{
      "name":"quota-server",
      "image":"registry.cn-shanghai.aliyuncs.com/daofeng/ratelimit-quota-server:clientid-unify-20260615",
      "imagePullPolicy":"Always",
      "ports":[{"containerPort":8081}],
      "env":[
        {"name":"SIDECAR_MOD","value":"gateway-1"},
        {"name":"RUNTIME_ROOT","value":"/data/ratelimit-quota"},
        {"name":"RUNTIME_SUBDIRECTORY","value":"config"},
        {"name":"RUNTIME_APPDIRECTORY","value":"config"},
        {"name":"RUNTIME_WATCH_ROOT","value":"true"},
        {"name":"RUNTIME_IGNOREDOTFILES","value":"true"},
        {"name":"ZONEINFO","value":"/usr/share/zoneinfo"},
        {"name":"LOG_LEVEL","value":"info"},
        {"name":"USE_STATSD","value":"false"}
      ],
      "volumeMounts":[{"name":"ratelimit-config","mountPath":"/data/ratelimit-quota/config/config.yaml","subPath":"config.yaml"}]
    }],
    "volumes":[{"name":"ratelimit-config","configMap":{"name":"'"$RATELIMIT_CM"'"}}]
  }}}
}'
kubectl rollout status -n $NS deploy/higress-gateway --timeout=180s
```
> 注意 `$RATELIMIT_CM`（= `kubernetes-ratelimit-config`）需先由 QuotaRule CR 触发 controller 生成（见 §10）；若先于 CR 加 sidecar，挂载会失败，待 CR reconcile 出 ConfigMap 后再 `kubectl rollout restart`。

校验：
```bash
kubectl logs -n $NS <gw-pod> -c quota-server | grep -iE "Redis URL|empty domain"
# 期待：Redis URL: <data-redis> (from config file)；不期待：empty domain / localhost:6379
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

### 10.1 ⭐ 控制台驱动（per-consumer 全局，不绑路由）→ 用 `application_scope: GLOBAL_DEFAULT`

上面 §10 是 `ROUTE` 形态（默认，需 `target.routes`，按路由限流）。**控制台的配额是 per-consumer、实例全局、与路由无关**，应改用 `GLOBAL_DEFAULT`（HCM 级全局 bucket_matchers，**无 `target.routes`**），消费者 header 用鉴权注入的 `x-mse-consumer`：

```bash
kubectl apply -n $NS -f - <<EOF
apiVersion: networking.istio.io/v1alpha3
kind: QuotaRule
metadata: { name: test-quota }
spec:
  redis_info: { redis_url: "${REDIS_HOST}:${REDIS_PORT}", redis_auth: "${REDIS_AUTH}" }
  rules:
    - application_scope: GLOBAL_DEFAULT          # 全局，无 target.routes
      match:
        - name: all-consumers
          headers: { items: [{ name: x-mse-consumer, value: ".*", match_type: REGEX }] }
      dimensions:
        - short_name: cu                         # 必须与控制台 rl_dc:{domain}:cu_{id} 前缀一致
          source: { request_header: x-mse-consumer }
          priority: 100
          limit:
            dynamic: true
            fallback: { requests_per_unit: 5, unit: DAY, quota_dimension: token }  # 设小，见下注
EOF
```

| `application_scope` | 作用 | `target.routes` |
|---|---|:---:|
| `ROUTE`（默认） | per-route override | 需要 |
| **`GLOBAL_DEFAULT`** | HCM 级全局 | **不需要** |
| `GLOBAL_INFRASTRUCTURE` | 仅 redis_info/control | — |

> ⚠️ **fallback 要设小**：配额降到约 limit 的 20%（降级阈值）后进 `[DEGRADED]`，envoy 改用此 `fallback`。fallback 设大（如 100000/month）会导致近限额时被 fallback 放行、永远到不了 429。
> `unit` 枚举支持 `SECOND/MINUTE/HOUR/DAY/WEEK/MONTH/YEAR`，控制台日/周/月配额均可。
> token 维度 429 需路由是 AI/Model 路由（网关 ai-statistics 从响应抽 token 用量上报），echo-server 只能测 `request` 维度。完整 console e2e 见 [console-driven-token-quota-e2e-20260616.md](./console-driven-token-quota-e2e-20260616.md)。

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
| 请求 200 但 quota-server 无 SyncCheck / filter 不在 HCM | controller 报 `envoy endpoints length is 0`（env 设了也报） | 删 controller pod warmup endpoints informer（§2.3）；确认 `QUOTA_GATEWAY_ENDPOINTS_NAME` 指向有 Pod IP 的 Service |
| quota-server `config file cannot have empty domain` + 连 `localhost:6379` | ConfigMap 挂载路径差一层，读到镜像空默认 config.yaml | 用 **subPath** 覆盖到 `/data/ratelimit-quota/config/config.yaml`（§7.2） |
| token 维度配额耗尽却不返 429（一直 200） | 近限额进 `[DEGRADED]`，envoy 用 CR `fallback`（设太大）放行 | CR `fallback` 设小（§10.1）；确认路由是 AI/Model 路由能抽 token |
| 集群内 quota-server `dial tcp …:6379 i/o timeout` | 外部/云 Redis 未放通集群出口 | Redis 白名单加集群 NAT 出口 IP（见 §1 外部 Redis 注） |

---

## 附录 A：外部/共享 Redis（控制台联调推荐）

控制台动态下发 per-consumer 配额，要求 **同一个 Redis 既被集群内 quota-server 读、又被控制台写**：
- **集群侧**：QuotaRule CR `redis_info` + `higress-config` 的 `mcpServer.redis` 指向它，改完重启 gateway。
- **控制台侧**：实例 `RedisConfig` 设为它（或留空走 higress-config 解析），`HigressRedisServiceResolver` 自动解析、无需 override。
- **云 Redis（如阿里云 Redis）**：① Redis 白名单放通**集群 NAT 出口公网 IP**（否则 quota-server `i/o timeout`）；② `CONFIG SET notify-keyspace-events KEA`（否则 quota-server LRU 不失效，配额变更 ~10s 内不生效）。
- 本地起控制台联调时，本机 6379 常被控制台自身会话 Redis 占用，**不要用 `quota.dataplane.redis-override=127.0.0.1`**，直接走云 Redis 公网 endpoint。

实测见 [console-driven-token-quota-e2e-20260616.md](./console-driven-token-quota-e2e-20260616.md)。

## 附录 B：自动化方向（待办）

当前搭建仍是手工 kubectl，目标是消除：

1. **Helm chart 化**：把 §7 的 quota-server sidecar、§3/§5 的网关 patch、§2 的 controller env 收敛进 helm 基线 values（`quotaServer.enabled` 开关 + sidecar 模板 + ConfigMap 挂载），新实例部署即带 quota 能力，免去手动 patch 与 warmup。
2. **控制台触发下发**：QuotaRule CR（GLOBAL_DEFAULT 接线）+ ratelimit ConfigMap 由控制台在「启用配额」时按实例下发（复用现有 K8s 下发通道），per-consumer 配额继续走 Redis 动态写。即把 §10 的 CR 接线纳入控制台生命周期，而非人工预置。
3. 过渡期可把第 2–10 节命令脚本化 `setup-quota-rule.sh`，变量化 `$NS`/`$CLUSTER_ID`/`$REDIS_*`/镜像 tag，新 ns 一键拉起。

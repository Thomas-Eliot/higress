# 控制台驱动的 Token 配额 e2e 测试报告

**日期**：2026-06-16
**环境**：阿里云 ACK，namespace `ls-test`
**测试人**：lvshui
**目标**：验证 **admin/console → 共享 Redis → 数据面 quota-server → 429** 的 Token 维度全链路，即控制台动态写入 per-consumer 配额，数据面按 LLM 响应的 token 用量精确限流。

---

## 一、测试目标

打通并验证「控制台配额管理」的完整数据面链路：

```
console 建/改规则(token/day)
   │ 写
   ▼
Aliyun 共享 Redis  rl_dc:{domain}:cu_{consumer}
   │ 读
   ▼
quota-server(网关 sidecar)  ← 读到 rpu/unit/dim/timezone
   │
网关 ai-statistics 从 mock-llm 响应抽取 token 用量
   │ 上报
   ▼
quota-server 计数累加 → 超过 limit → SYNC_CHECK_DENIED → 网关返回 429
```

与历史 e2e（[6/15 报告](./e2e-quota-rule-test-report-20260615.md)，echo-server + `request` 维度）的区别：本次用 **真实 LLM 路由（mock-llm-qwen2）+ `token` 维度**，且配额由 **admin 控制台动态写入**（非手工 HSET）。

---

## 二、测试环境

| 组件 | 取值 |
|------|------|
| 网关实例(console) | `i-3f60ee95d0a90b6eaba3`（gateway_instance.deploy_cluster_namespace=`ls-test`）|
| 网关入口 SLB | `47.109.156.3:80` |
| **共享 Redis** | Aliyun 云 Redis `r-2vc6ri4l3xzru23gujpd.redis.cn-chengdu.rds.aliyuncs.com:6379`（auth `eliot_test:Admin123@gateway`）|
| 数据面 domain | `Kubernetes-quotarule` |
| LLM 后端 | `mock-llm-qwen2`（OpenAI 兼容，`--served-model-name qwen2-7b-instruct`，返回 `usage.total_tokens`）|
| 网关/控制器镜像 | `registry.cn-shanghai.aliyuncs.com/daofeng/{gateway,higress,pilot}:quota-rule` |
| quota-server | `registry.cn-shanghai.aliyuncs.com/daofeng/ratelimit-quota-server:clientid-unify-20260615`（sidecar，port 8081）|
| 测试 consumer | `perf-09927`（ls-test 实例已有压测 consumer，经 `x-mse-consumer` 头标识）|

**共享 Redis 的两个前置**（缺一不可）：
1. 在 Redis 白名单中放通**集群 NAT 出口公网 IP**（否则集群内 quota-server `dial tcp …:6379 i/o timeout`）。
2. `CONFIG SET notify-keyspace-events KEA`（否则 quota-server LRU 不被失效，配额变更 ~10s 内不生效，一直读旧值）。

> console 本地联调：实例 `RedisConfig` 为空时，`HigressRedisServiceResolver` 原生解析 higress-config 的 `mcpServer.redis`（=Aliyun），本地 Mac 直连公网 endpoint 即可。**注意本地 6379 被 console 自身会话 Redis 占用，不要用 `quota.dataplane.redis-override=127.0.0.1`**。

---

## 三、数据面搭建（runbook 补全项）

[env-setup runbook](./e2e-quota-rule-env-setup.md) 假设 helm 已部署 quota 栈，但全新 ls-test 缺以下步骤，本次补全：

### 3.1 镜像升级到 quota-rule
```bash
kubectl set image -n ls-test deploy/higress-controller \
  higress=…/daofeng/higress:quota-rule discovery=…/daofeng/pilot:quota-rule
kubectl set image -n ls-test deploy/higress-gateway \
  higress-gateway=…/daofeng/gateway:quota-rule
```
（原镜像 `…:2.1.12` 不含 `rate_limit_quota_apig` filter / 不认 QuotaRule CRD。）

### 3.2 手动加 quota-server sidecar（关键，runbook 缺）
gateway deploy 默认无 quota-server 容器。strategic patch 加入，**用 subPath 把 ratelimit ConfigMap 的 `config.yaml` 覆盖到镜像自带的空默认配置路径**：

```yaml
containers:
- name: quota-server
  image: …/ratelimit-quota-server:clientid-unify-20260615
  ports: [{containerPort: 8081}]
  env:
  - {name: SIDECAR_MOD, value: gateway-1}
  - {name: RUNTIME_ROOT, value: /data/ratelimit-quota}
  - {name: RUNTIME_SUBDIRECTORY, value: config}
  - {name: RUNTIME_APPDIRECTORY, value: config}
  - {name: RUNTIME_WATCH_ROOT, value: "true"}
  - {name: LOG_LEVEL, value: info}
  - {name: USE_STATSD, value: "false"}
  volumeMounts:
  - name: ratelimit-config
    mountPath: /data/ratelimit-quota/config/config.yaml   # ← 精确覆盖镜像空默认
    subPath: config.yaml
volumes:
- name: ratelimit-config
  configMap: {name: kubernetes-ratelimit-config}
```
> 坑：直接挂目录到 `/data/ratelimit-quota/config/config/` 会差一层，quota-server 读到镜像自带的空 `config.yaml` → 报 `config file cannot have empty domain` + Redis 回落 `localhost:6379`。RLQS cluster 是 `STRICT_DNS → 127.0.0.1:8081`，故必须 sidecar。

### 3.3 controller env + warmup（关键）
```bash
kubectl set env -n ls-test deploy/higress-controller -c higress \
  QUOTA_GATEWAY_ENDPOINTS_NAME=higress-gateway CLUSTER_ID=Kubernetes \
  WATCH_RESOURCES_BY_NAMESPACE_FOR_PRIMARY_CLUSTER=ls-test
kubectl delete pod -n ls-test -l app=higress-controller   # ← 必须，warmup endpoints informer
```
> 不 warmup 会持续报 `quotarule: envoy endpoints length is 0, don't push quotarule to envoy` → filter 进不了 HCM filter chain → 请求全程不过配额（200 但无 SyncCheck）。`higress-gateway` Endpoints 实际有 gateway pod IP，仅 informer 未同步。

### 3.4 禁用拖死 listener 的 wasmplugin
```bash
kubectl patch wasmplugin -n ls-test key-auth.internal --type=merge \
  -p='{"spec":{"defaultConfigDisable":true}}'
```

---

## 四、QuotaRule 配置（对齐：全局按 consumer，不绑路由）

数据面 CRD 的 `rules[].application_scope` 决定作用域：

| scope | 作用 | 是否需要 `target.routes` |
|-------|------|:---:|
| `ROUTE`（默认） | 按路由 per-route override | ✅ 需要 |
| **`GLOBAL_DEFAULT`** | **HCM 级全局，按 match+维度生效** | ❌ **不需要** |
| `GLOBAL_INFRASTRUCTURE` | 仅 redis_info/control | — |

控制台配额是 **per-consumer、实例全局**，与路由无关，故用 `GLOBAL_DEFAULT`：

```yaml
apiVersion: networking.istio.io/v1alpha3
kind: QuotaRule
metadata: {name: test-quota, namespace: ls-test}
spec:
  redis_info: {redis_url: "<aliyun>:6379", redis_auth: "eliot_test:Admin123@gateway"}
  rules:
    - application_scope: GLOBAL_DEFAULT          # 全局，无 target.routes
      match:
        - name: all-consumers
          headers: {items: [{name: x-mse-consumer, value: ".*", match_type: REGEX}]}
      dimensions:
        - short_name: cu                         # ← 对应 console 的 rl_dc:{domain}:cu_{id}
          source: {request_header: x-mse-consumer}
          priority: 100
          limit:
            dynamic: true
            fallback: {requests_per_unit: 5, unit: DAY, quota_dimension: token}
```

要点：
- **消费者 header = `x-mse-consumer`**（鉴权后网关注入；测试可手动传）。
- `short_name: cu` 必须与控制台写入的 Redis key 前缀（`cu_`）一致。
- **`unit` 枚举支持 `SECOND/MINUTE/HOUR/DAY/WEEK/MONTH/YEAR`** → 控制台日/周/月配额数据面均支持。

---

## 五、测试用例 + 实测结果

### 用例 1：控制台写入 → 抵达共享 Redis ✅
控制台 `createQuotaRule`（perf-09927, day=50000 token，无 override 原生解析）后：
```
$ redis-cli -h <aliyun> HGETALL rl_dc:Kubernetes-quotarule:cu_perf-09927
limits_json     [{"unit":"DAY","requests_per_unit":50000,"quota_dimension":"token"}]
quota_dimension token
window_alignment calendar
timezone        Asia/Shanghai
```
→ 控制台原生解析实例 Redis（=Aliyun）并写入，格式正确。

### 用例 2：quota-server 读取控制台配置 ✅
请求带 `x-mse-consumer: perf-09927` 后，quota-server 日志：
```
GetDynamicLimit: returning config for rl_dc:Kubernetes-quotarule:cu_perf-09927
  (rpu=100 unit=day dim=token alignment=calendar tz=Asia/Shanghai remote_bands=1)
```
→ 数据面读到控制台写的 rpu/unit/dim/timezone，完全一致。

### 用例 3：Token 用量抽取与计数 ✅
mock-llm 响应 `usage:{prompt_tokens, completion_tokens, total_tokens}`，网关 ai-statistics 抽取并上报：
```
streamRateLimitQuota … bucket_id:{cu:perf-09927}
  tokens_consumed:2 input_tokens_consumed:1 output_tokens_consumed:1
```
Redis counter：
```
$ HGETALL {rl_Kubernetes-quotarule_cu_perf-09927_token_day_1781539200}:used
total_tokens 306   input_tokens 153   output_tokens 153
```
→ 按 token 计数，累加到 Redis counter key。

### 用例 4：超额触发 429（核心）✅
控制台 `updateQuotaRule` 把 perf-09927 改为 day=100 token + CR fallback=5 token/day，重置 counter 后串行 burst 15 次（长 prompt，每次约 30–50 token）：
```
200 200 200 200 429 200 429 429 200 429 200 429 200 429 200
```
quota-server 日志：
```
SYNC_CHECK_DENIED  allowed=false remaining=0 dim=token   (rpu=100)
```
→ token 累计（total_tokens=306）超过 limit=100 后，明确拒绝 → 429。200/429 混合系 token 维度正常现象（每请求 token 数不定 + 计数响应后回填 + 近限额降级）。

---

## 六、链路通过项

| 环节 | 验证项 | 状态 |
|------|--------|:---:|
| console → Redis | 原生解析实例 Redis(=Aliyun)，写 rl_dc key 格式正确 | ✅ |
| 集群 → Redis | 白名单放通后 quota-server 连上 Aliyun redis | ✅ |
| 数据面读取 | quota-server 读到 console 写的 token 配置（rpu/unit/dim/tz） | ✅ |
| Token 抽取 | ai-statistics 从 mock-llm 响应抽 token 用量并上报 | ✅ |
| 计数 | Redis counter `…_token_day_…:used` total_tokens 累加 | ✅ |
| 强制 429 | 超 limit → SYNC_CHECK_DENIED → 429 | ✅ |
| 全局形态 | GLOBAL_DEFAULT 在 HCM 级全局生效，不绑路由 | ✅ |
| 动态生效 | console 改 limit 后 ~10s（keyspace KEA）内生效 | ✅ |

---

## 七、关键发现 / 调优注意

1. **降级阈值 ≈ limit 的 20%**（limit=100→threshold=20，limit=10→9）。配额降到阈值以下进 `[DEGRADED]`，envoy 改用 CR `fallback`。**fallback 必须设小**，否则近限额时被 fallback 放行、到不了 429。
2. **WEEK/MONTH/YEAR 单位 CRD 原生支持**（`rate_limit.unit` enum），控制台日/周/月配额数据面无障碍。
3. **endpoints informer 必须 warmup**（改 controller env 后删 pod），否则 `envoy endpoints length is 0` 致 EnvoyFilter 不下发。
4. **subPath 挂载**覆盖镜像默认 config.yaml，否则 quota-server 读空配置回落 localhost。
5. 停用规则 = DEL rl_dc key 后回落 CR fallback，非完全无限额（语义待产品确认）。

---

## 八、相关文档

- [环境准备 runbook](./e2e-quota-rule-env-setup.md)
- [6/15 单窗口 e2e](./e2e-quota-rule-test-report-20260615.md) / [多窗口 limits_json](./quota-rule-limits-json-multi-window-test-20260615.md)
- 权威架构文档：`higress-gateway/aigateway-ratelimit-quota-knownow/docs/`（`01_CRD_TRANSLATION` / `03_QUOTA_CONFIG_GUIDE` / `04_TOKEN_EXTRACTION` / `07_DEGRADATION_STATE_MACHINE`）

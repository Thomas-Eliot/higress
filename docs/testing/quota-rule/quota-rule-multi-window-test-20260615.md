# QuotaRule 多窗口（limits_json）端到端测试记录

**日期**: 2026-06-15
**测试环境**: 阿里云 ACK 集群，namespace `ls-test2`
**测试人**: lvshui

---

## 一、测试目标

验证 `limits_json` 在 dynamic 链路下支持多个时间窗口并行限流（例如 MINUTE + DAY），AND 语义（任一窗口耗尽即拒）。

## 二、limits_json 机制（调研结论）

**位置**：Redis HASH `rl_dc:{domain}:{uniqueKey}` 的一个字段，**不是** CRD 字段也不是 ConfigMap 字段。

**Schema**（quota-server 端）：
- 字段名：`limits_json`
- 值：JSON 数组，每个元素是一个时间窗口 band：
  ```json
  [
    {"unit":"MINUTE","requests_per_unit":20,"quota_dimension":"token"},
    {"unit":"DAY","requests_per_unit":50,"quota_dimension":"token"}
  ]
  ```
- 每个 band 字段：`unit` / `requests_per_unit` / `unit_multiplier` / `quota_dimension` / `version` / `timezone`

**解析路径**：`ratelimit-quota-server/src/redis/impl.go`
- `parseDynamicConfigFromHash` (2107)：`HGETALL rl_dc:...` 后读 `limits_json`，`json.Unmarshal` 到 `[]dynamicLimitBand`
- 每个 band 转 `config.TimeQuotaBand`，存入 `RemoteLimits`
- `SortTimeQuotaBands` 按时间粒度排序（second → minute → hour → day → month）
- `MaxBandRPU` 取最大 RPU 用于主窗口
- **AND 语义**：每个 band 一个独立 Redis 计数器 key（含 `WindowKeySlot` 后缀如 `minute-v-...`、`day-v-...`），任一耗尽即拒

## 三、环境处理 / 镜像版本

### 镜像清单（ls-test2）

| 组件 | 镜像 |
|------|------|
| higress-controller | `registry.cn-shanghai.aliyuncs.com/daofeng/higress:quota-rule` |
| pilot (discovery) | `registry.cn-shanghai.aliyuncs.com/daofeng/pilot:quota-rule` |
| higress-gateway | `registry.cn-shanghai.aliyuncs.com/daofeng/gateway:quota-rule` |
| nginx sidecar | `registry.cn-shanghai.aliyuncs.com/daofeng/nginx:alpine` |
| quota-server | `registry.cn-shanghai.aliyuncs.com/daofeng/ratelimit-quota-server:latest` |
| mock-llm (qwen2) | `registry.cn-shanghai.aliyuncs.com/daofeng/mock-llm:v3` (ls-test 命名空间) |

### Redis 选择（重要）

ls-test2 环境的 quota-server 应连 **`redis-builtin.higress-system.svc.cluster.local:6379`**（auth `1905b762fd25c8a5`）；
不是 ls-test2 内的 redis-builtin（没 endpoints），也不是 apigateway-system 的（auth 不同）。

### Controller 必须设置的环境变量

```bash
kubectl set env -n ls-test2 deployment/higress-controller \
  -c higress -c discovery \
  WATCH_RESOURCES_BY_NAMESPACE_FOR_PRIMARY_CLUSTER=ls-test2 \
  CLUSTER_ID=Kubernetes        # 大写！否则 domain 变 istio-quotarule，与历史配置不兼容
```

### quota-server 环境变量

```
RUNTIME_ROOT=/data/ratelimit-quota   RUNTIME_SUBDIRECTORY=config
RUNTIME_APPDIRECTORY=config          RUNTIME_WATCH_ROOT=true
RUNTIME_IGNOREDOTFILES=true          SIDECAR_MOD=gateway-1
ZONEINFO=/usr/share/zoneinfo         LOG_LEVEL=DEBUG (诊断) / WARN (生产)
REDIS_URL=redis-builtin.higress-system.svc.cluster.local:6379
REDIS_AUTH=1905b762fd25c8a5
```

### 跨 ns 引流（mock-llm-qwen2 在 ls-test，gateway 在 ls-test2）

```yaml
# ExternalName service + Ingress
apiVersion: v1
kind: Service
metadata: { name: mock-llm-qwen2, namespace: ls-test2 }
spec:
  type: ExternalName
  externalName: mock-llm-qwen2.ls-test.svc.cluster.local
  ports: [{ port: 8000, protocol: TCP, targetPort: 8000 }]
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata: { name: mock-llm-qwen2, namespace: ls-test2 }
spec:
  ingressClassName: ls-test2
  rules:
    - http:
        paths:
          - { path: /v1, pathType: Prefix, backend: { service: { name: mock-llm-qwen2, port: { number: 8000 } } } }
```

## 四、问题与解决方案清单

### 问题 1：Controller 报 `envoy endpoints length is 0, don't push quotarule to envoy`

| 项 | 内容 |
|----|------|
| 现象 | Controller 不下发 QuotaRule，不生成 ConfigMap / EnvoyFilter |
| 根因 | `WATCH_RESOURCES_BY_NAMESPACE_FOR_PRIMARY_CLUSTER` 未设置，导致 `EndpointClient.Get("envoy-hs", "")` 用空 namespace 查询返回 nil |
| 代码 | `istio/istio/pilot/pkg/config/alikube/quotarule/quotarule.go:1798-1810 GetEnvoyEndpointLen` |
| 解决 | 给 controller 加 env：`WATCH_RESOURCES_BY_NAMESPACE_FOR_PRIMARY_CLUSTER=ls-test2`（两个 container 都要）|
| 验证 | reconcile 后 controller 日志出现 `gatewayEnvoyEndpointCount=1 envoyFilterResources=2 quotarule ConfigMap: successfully synced` |

### 问题 2：EnvoyFilter `rlqs_server` 多了一层 `grpc_service` 包装，envoy 拒绝 listener

| 项 | 内容 |
|----|------|
| 现象 | envoy 启动日志：`gRPC config for Listener rejected: RateLimitQuotaFilterConfigValidationError.RlqsServer: target_specifier is required` |
| 根因 | EnvoyFilter YAML 中实际格式：`rlqs_server.grpc_service.envoy_grpc.cluster_name`；envoy 端 proto 期望：`rlqs_server.envoy_grpc.cluster_name` |
| 影响 | 80 listener 配置被拒，所有走 80 端口的请求返回 000（连接级失败）|
| 临时解决 | 手动 patch EnvoyFilter，扁平化 `rlqs_server`：`{envoy_grpc: {cluster_name: rate_limit_quota_service}, timeout: 2s}` |
| 根本修复 | 待定位 controller `BuildHTTPFilter` 中 protobuf JSON marshal 路径异常（源码上 `RlqsServer *GrpcService` 是直接类型，但 `conversion.MessageToStruct` 输出多了一层；可能是 protobuf JSON marshaling 配置或两边 proto 版本不一致）|

### 问题 3：ConfigMap 名 / domain 随 CLUSTER_ID 变化

| 项 | 内容 |
|----|------|
| 现象 | `CLUSTER_ID=istio` 时，生成 `istio-ratelimit-config` ConfigMap 和 `istio-quotarule` domain；与历史配置 `kubernetes-ratelimit-config` / `Kubernetes-quotarule` 不一致 |
| 影响 | quota-server 挂载 `kubernetes-ratelimit-config`，但 controller 写到 `istio-ratelimit-config`，配置不生效；Redis key `rl_dc:Kubernetes-quotarule:...` 与 controller 生成的 `rl_dc:istio-quotarule:...` 不匹配 |
| **坑点** | `CLUSTER_ID` env 不生效 — controller deployment 的 `higress` container args 硬编码了 `--clusterID=istio`，flag 优先级高于 env |
| 解决 A | 改 deployment args：`--clusterID=Kubernetes`（保持历史一致）|
| 解决 B | 改 quota-server 挂载的 ConfigMap 引用从 `kubernetes-ratelimit-config` → `istio-ratelimit-config`，limits_json 改写到 `rl_dc:istio-quotarule:cu_alice` |
| 历史背景 | `incident-quota-rule-controller-deployment.md` 记录过：曾尝试改 `kubernetes` 小写导致 mTLS 失败 |

### 问题 6：EnvoyFilter `BucketMatchers.MatcherList.Matchers[].Predicate.SinglePredicate.Input.typed_config.name` 字段缺失

| 项 | 内容 |
|----|------|
| 现象 | envoy 拒绝 listener 80：`TypedExtensionConfigValidationError.Name: value length must be at least 1 characters` |
| 根因 | controller 生成 BucketMatchers 时，`Input` 的 typed_config 没填 `name` 字段；envoy 端 proto 要求 name 长度 >= 1 |
| 触发场景 | Bug2 修复后才暴露（之前 listener 因 rlqs_server 错误直接拒，没走到 BucketMatchers 校验）|
| 状态 | 待修复（在 controller 源码中需要为 typed_config 设置 name 字段）|

### 问题 4：LB ExternalIP 切 pod 后 SLB 后端不刷新

| 项 | 内容 |
|----|------|
| 现象 | gateway pod 重启后 LB IP `8.156.95.31` 请求返回 000，pod 端口实际可访问 |
| 根因 | 阿里云 SLB CCM 同步延迟 |
| 解决 | 等待 SLB 后端刷新；或用 `kubectl port-forward` / NodePort 30815 绕过 LB |

### 问题 5：mock-llm-qwen2 模型名不固定

| 项 | 内容 |
|----|------|
| 现象 | `qwen2` / `qwen-turbo` 模型名都返回 `model not exist` |
| 解决 | 真实模型名是 `qwen2-7b-instruct`（从 mock-llm pod startup 参数 `--served-model-name` 获取）|
| token 返回 | 实际依输入字符长度返回 prompt+completion tokens（`hi` → 1+1=2；长 prompt → 18+18=36）|

## 五、测试方案

### 5.1 配置参数

- Consumer：`alice` (`x-consumer: alice`)
- 维度：`token`
- 配额：MINUTE=20 tokens, DAY=50 tokens
- 后端：mock-llm-qwen2（模型 `qwen2-7b-instruct`），`/v1/chat/completions`
- 短 prompt（`"hi"`）：~2 tokens/req → MINUTE 第 10 个请求触发，DAY 第 25 个请求触发

### 5.2 Redis 写入命令

```bash
REDIS_AUTH="1905b762fd25c8a5"
kubectl exec -n higress-system redis-builtin-0 -- redis-cli -a "$REDIS_AUTH" --no-auth-warning HSET \
  "rl_dc:Kubernetes-quotarule:cu_alice" \
  quota_dimension "token" \
  limits_json '[{"unit":"MINUTE","requests_per_unit":20,"quota_dimension":"token"},{"unit":"DAY","requests_per_unit":50,"quota_dimension":"token"}]'
```

### 5.3 验证矩阵

| 场景 | 期望 |
|------|------|
| burst 短请求至 MINUTE 耗尽 | 前 ~10 个 200，之后 429 |
| 等 60s 后再 burst | 第 1-10 仍 200（MINUTE 重置）|
| 累计达 DAY 配额 | 第 26 个起永久 429（直到次日重置）|
| 修改 limits_json 后 ~10s 内 | 新配额生效，无需重启 |

## 六、当前状态（待继续）

- [x] limits_json 调研完成
- [x] mock-llm-qwen2 跨 ns 路由就绪
- [x] Bug1（envoy endpoints length is 0）已修复
- [x] Bug2（rlqs_server 嵌套）手动 patch 验证有效，待源码定位
- [x] Bug6（BucketMatchers Input.name 缺字段）已发现，需源码修复
- [x] limits_json 写入 Redis（已写 `rl_dc:Kubernetes-quotarule:cu_alice`，但 controller 实际生成的 domain 是 `istio-quotarule`，需要重写）
- [ ] **未完成**：修 Bug6 源码 + 重 build pilot 镜像
- [ ] **未完成**：修 Bug2 源码（rlqs_server 嵌套，定位 protobuf JSON marshaling 问题）
- [ ] **未完成**：实际压测验证 AND 语义
- [ ] **未完成**：动态热更新 limits_json 验证

## 八、下次会话续作指引

1. **修 Bug6**：定位 `istio/istio/pilot/pkg/config/alikube/quotarule/quotarule.go` 或 `quotarule_multidim.go` 中构造 `cncfv3.Matcher_MatcherList_FieldMatcher` → `SinglePredicate` → `Input *corev3.TypedExtensionConfig` 的代码，给 `Input.Name` 设置非空值（如 `"x-consumer-input"`）

2. **修 Bug2（可选）**：定位 `BuildHTTPFilter` 中 `conversion.MessageToStruct(httpFilter)` 序列化路径，确认为什么 `RlqsServer *v3.GrpcService` 在 JSON 中多了一层 `grpc_service` 包装

3. **重 build pilot 镜像**：
   ```bash
   cd istio/istio
   # build & push 到 daofeng/pilot:quota-rule-v2（避免覆盖原镜像）
   ```

4. **替换镜像 + 重启 controller**：
   ```bash
   kubectl set image -n ls-test2 deploy/higress-controller discovery=registry.cn-shanghai.aliyuncs.com/daofeng/pilot:quota-rule-v2
   ```

5. **如选解决 A（改 args）**：
   ```bash
   kubectl patch deploy higress-controller -n ls-test2 --type=json \
     -p='[{"op":"replace","path":"/spec/template/spec/containers/0/args/9","value":"--clusterID=Kubernetes"}]'
   ```
   或选解决 B（让 quota-server 挂 `istio-ratelimit-config`），并把 limits_json 写到 `rl_dc:istio-quotarule:cu_alice`

6. **跑测试**：参考第五节"测试方案"，发请求 + 看 quota-server DEBUG 日志确认 limits_json 被解析、AND 语义生效

## 七、教训

1. **Controller env 配置必须三件套**：`WATCH_RESOURCES_BY_NAMESPACE_FOR_PRIMARY_CLUSTER` + `CLUSTER_ID` + `POD_NAMESPACE` — 缺一不可，否则要么不下发，要么生成的资源名/domain 不兼容
2. **protobuf wrapper 类型坑**：controller 与 envoy 之间 proto 版本若不一致，序列化为 JSON 时会出现意外嵌套（如本次 `rlqs_server.grpc_service` 包装）；最好的诊断是直接查 envoy 拒绝原因里的 `field` 字段名
3. **redis 选择**：测试环境多 ns 都有 redis-builtin，看 helm release-namespace 标签确认权威实例（这里是 higress-system，不是 apigateway-system）
4. **跨 ns 引流**：用 ExternalName Service 比 EndpointSlice 更稳定；ingressClassName 必须匹配 gateway 的 ingress class
5. **保留两个核心文档**：
   - `docs/operations/incident-quota-rule-controller-deployment.md`（历史 controller 部署故障）
   - 本文档（多窗口测试 + 全部 bug）

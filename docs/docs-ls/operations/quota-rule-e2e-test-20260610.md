# QuotaRule 端到端测试 — 决策记录 (2026-06-10)

## 目标

验证 QuotaRule 限流全链路：CR → Controller → EnvoyFilter → Envoy → quota-server → 429

## 最终状态：全链路已打通

| 组件 | 镜像 | 状态 |
|------|------|------|
| higress (controller) | daofeng/higress:quota-rule | 正常 |
| pilot (discovery) | daofeng/pilot:quota-rule | 正常 |
| gateway (envoy) | daofeng/gateway:quota-rule | 正常 - 含 apig filter，348 extensions |
| quota-server (sidecar) | daofeng/ratelimit-quota-server:latest | 正常 - Redis 已连接 |

**验证结果**: 并发 200 请求 → 36 通过 + 164 返回 429。限流生效，但当前生效的是 envoy 本地令牌桶（NoAssignmentBehavior fallback），不是 quota-server Redis 计数器。

## 待解决

**quota-server Redis 计数器未生效**：quota-server 日志显示 `SYNC_CHECK_ALLOWED`（本地 sync check），没有走 Redis 全局计数。需排查：
- quota-server 的 SYNC_CHECK 与 Redis 计数的切换逻辑
- 是否需要额外配置触发 Redis 模式
- 串行 120 请求全部通过（令牌桶填充速率 > 请求速率），只有并发场景才触发限流

---

## 解决的问题记录

### 问题 1: ConfigMap 名称不匹配

**现象**: quota-server sidecar 挂载 `ratelimit-quota-config`（手动创建，bucket_action 为空），Controller 自动生成的是 `kubernetes-ratelimit-config`（含实际规则）。

**解决**:
```bash
kubectl patch deploy higress-gateway -n ls-test --type=json \
  -p='[{"op":"replace","path":"/spec/template/spec/volumes/11/configMap/name","value":"kubernetes-ratelimit-config"}]'
```

**根因**: Controller 生成的 ConfigMap 名称遵循 `{CLUSTER_ID}-ratelimit-config` 模式。

---

### 问题 2: EnvoyFilter 中缺少 HTTP_FILTER 补丁

**现象**: Controller 生成的 EnvoyFilter 只有 CLUSTER 和 HTTP_ROUTE 补丁，没有将 `rate_limit_quota_apig` filter 注入 HCM filter chain。

**根因**: 内部版本通过 `QuotaRuleHTTPFilterProvider.GetHTTPFilter()` 在 pilot 的 listener builder 中直接注入。开源版 higress 和 pilot 是独立容器，无法使用该路径。

**解决**: 修改 `getGlobalEnvoyFilter()` 增加 `HTTP_FILTER INSERT_BEFORE envoy.filters.http.router` 补丁。

**代码**: `istio/istio` 子模块 `pilot/pkg/config/alikube/quotarule/quotarule.go`
- 已推送到 csb2 istio-1.19 分支

---

### 问题 3: Pilot 无法反序列化自定义 proto 类型

**现象**: Pilot 崩溃 — `could not resolve Any message type: ...RateLimitQuotaFilterConfig`

**根因**: pilot 二进制没有导入 `rate_limit_quota_apig/v3` 包，protobuf 注册表缺少这些类型。

**解决**: 在 `pkg/config/xds/xds.go` 添加 blank import：
```go
_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/rate_limit_quota_apig/v3"
```

**代码**: `istio/istio` 子模块 `pkg/config/xds/xds.go`
- 已推送到 csb2 istio-1.19 分支

**影响**: pilot 镜像升级为 `daofeng/pilot:quota-rule`

---

### 问题 4: Gateway envoy 未包含 rate_limit_quota_apig filter

**现象**: envoy NACK — `Didn't find a registered implementation for 'envoy.filters.http.rate_limit_quota_apig'`

**根因**: 两个子问题：

**4a**: proxy 仓库的 `bazel/extension_config/extensions_build_config.bzl` 没有注册 apig filter。envoy 源码有 filter 代码，但 proxy 构建用自己的 extensions 列表。

**解决**: 在 `ENVOY_EXTENSIONS` 中添加：
```python
"envoy.filters.http.rate_limit_quota_apig": "//source/extensions/filters/http/rate_limit_quota_apig:config",
```

**代码**: `istio/proxy` 子模块 `bazel/extension_config/extensions_build_config.bzl`
- 已推送到 Thomas-Eliot/proxy istio-1.19 分支

**4b**: apig filter 使用了 `Grpc::GrpcServiceConfigWithHashKey` API，当前 envoy 版本没有这个类型。

**解决**: 在 `envoy/grpc/async_client_manager.h` 添加 `GrpcServiceConfigWithHashKey` 类和 `getOrCreateRawAsyncClientWithHashKey` 方法（default implementation 委托给 `getOrCreateRawAsyncClient`）。

**代码**: `envoy/envoy` 子模块 `envoy/grpc/async_client_manager.h`
- 已推送到 Thomas-Eliot/envoy envoy-1.27 分支

---

### 问题 5: QuotaRule target route 名称不匹配

**现象**: QuotaRule `target.routes: ["test-route"]` 但 envoy 路由名是 `ls-test`。

**解决**: 修改 QuotaRule target 为 `echo-server`（无 auth 的测试路由）。

---

## 代码变更汇总

| 仓库 | 分支 | 远程 | 改动文件 |
|------|------|------|----------|
| istio/istio | istio-1.19 | csb2 (gitlab) | `pilot/pkg/config/alikube/quotarule/quotarule.go`, `pkg/config/xds/xds.go` |
| istio/proxy | istio-1.19 | Thomas-Eliot/proxy (github) | `bazel/extension_config/extensions_build_config.bzl` |
| envoy/envoy | envoy-1.27 | Thomas-Eliot/envoy (github) | `envoy/grpc/async_client_manager.h` |

## 构建脚本

- `build-envoy.sh` — 构建 envoy 二进制（full/test 模式）
- `build-gateway-image.sh` — 打包并推送 gateway 镜像

---

## 2026-06-10 续：Redis 全局计数排查

### 已解决

#### 问题 6: quota-server FileProvider 加载不到 ConfigMap 中的限流配置

**现象**: SyncCheck 到达 quota-server 但所有请求返回 ALLOW（fail-open），Redis 无任何 `rl_*` key。Debug 日志显示 `unknown domain 'Kubernetes-quotarule'`。

**根因**: goruntime `loader.New2()` 在 `runtimeSubdirectory == ""` 时直接返回 nil loader（[loader.go:203](https://github.com/lyft/goruntime/blob/v0.3.0/loader/loader.go#L203)）。部署配置 `RUNTIME_APPDIRECTORY=""` 触发了这个逻辑。

**修复**（两项 env 变量）:
```bash
kubectl set env deploy/higress-gateway -n ls-test -c quota-server \
  RUNTIME_WATCH_ROOT=true \
  RUNTIME_APPDIRECTORY=config
```

- `RUNTIME_WATCH_ROOT=true`: 改用 SymlinkRefresher 代替 DirectoryRefresher，走 `loader.New2(RuntimePath, RuntimeSubdirectory)` 路径，`RuntimeSubdirectory=config` 非空不触发 nil loader
- `RUNTIME_APPDIRECTORY=config`: FileProvider 的 key 过滤 `HasPrefix(key, AppDir+".")` 要求 key 以 `config.` 开头。ConfigMap 文件名 `config.yaml` 匹配 `config.`，通过过滤

**验证**: 修复后日志显示 `loading domain: Kubernetes-quotarule`，配置正确加载。

---

#### 问题 7: SyncCheck panic — `time: missing Location in call to Time.In`

**现象**: 配置加载成功后，SyncCheck 调用 `calendarWindowBounds()` 时 panic，`time.LoadLocation("Asia/Shanghai")` 返回 nil。

**根因**: quota-server 容器镜像（`debian:bookworm-slim`）未安装 `tzdata` 包，Go 二进制又是 `CGO_ENABLED=0` 静态编译，无法使用系统 timezone 数据库。`resolveTimezoneLocation()` 对 `LoadLocation` 失败的返回值没有 nil 检查。

**修复**:
1. Dockerfile 添加 `apt-get install -y tzdata`，重新构建并推送镜像 `registry.cn-shanghai.aliyuncs.com/daofeng/ratelimit-quota-server:latest`
2. 代码层面修复（已改本地但未编译部署）：`resolveTimezoneLocation()` 在 `LoadLocation` 返回 nil 时 fallback 到 `time.UTC`

**代码**: `ratelimit-quota-server/src/utils/window_bounds.go` + `ratelimit-quota-server/Dockerfile`

**验证**: 修复后 SyncCheck 不再 panic，Redis Lua EVAL 成功执行，`latency_ms` 从 0.1ms（假 SyncCheck）升到 ~3.7ms（真实 Redis 往返）。

---

#### 问题 8: SyncCheck client ID 与 AllocQuotas client ID 不匹配（已修复）

**现象**: SyncCheck 返回 `allowed=false remaining=0`，即使 `used=0`，因为 `effective_prealloc` 计算错误。

**根因**: AllocQuotas（异步上报）路径将 client ID 写入 Redis prealloc hash 时使用 **base64 编码**（如 `Z2F0ZXdheS0x` = base64("gateway-1")），但 SyncCheck 路径（`handleSyncCheck` 行 421）在 `SIDECAR_MOD` 非空时直接使用**原始值**（如 `gateway-1`）。Lua 中 `HGET prealloc, "gateway-1"` 找不到 base64 编码的 key，导致 `my_prealloc=0`，`effective_prealloc = total_prealloc - 0 = 100`，`total_committed = used + 100 > max_quota` → DENY。

**修复**: `ratelimit-quota-server/src/service/ratelimit_quota.go` 行 421，`SIDECAR_MOD` 路径也做 base64 编码：
```go
// Before:
clientId = s.GetSidecarMod()
// After:
clientId = base64.StdEncoding.EncodeToString([]byte(s.GetSidecarMod()))
```

**编译环境**: go.mod replace 指向 `csb2/envoy_go-control-plane.git` istio-1.19 分支（本地 clone 到 `../csb2-go-control-plane`）。

**验证**: hey 压测 300 并发请求 → **200 = 100, 429 = 200**，精确匹配 `requests_per_unit: 100`。两轮测试结果完全一致。

---

### 当前验证状态（全链路打通）

| 阶段 | 状态 | 说明 |
|------|------|------|
| CR → Controller → ConfigMap | ✅ | 配置正确生成 |
| Controller → EnvoyFilter | ✅ | HTTP_FILTER + CLUSTER + ROUTE 补丁 |
| Envoy → quota-server gRPC | ✅ | SyncCheck 请求到达 |
| quota-server config 加载 | ✅ | 问题 6 已修复 |
| quota-server → Redis SyncCheck | ✅ | 问题 7 已修复 |
| SyncCheck 精确计数 | ✅ | 问题 8 已修复，300 请求 → 100 通过 + 200 拒绝 |
| Envoy 本地令牌桶限流 | ✅ | NoAssignmentBehavior fallback 生效 |

### 压测结果

```
hey -n 300 -c 50 -H "x-consumer: user1" http://localhost:8888/echo

Run 1: [200] 100 responses  [429] 200 responses  (448 QPS, avg 108ms)
Run 2: [200] 100 responses  [429] 200 responses  (448 QPS, avg 108ms)
```

### 环境变量汇总（当前生效）

```bash
RUNTIME_ROOT=/data/ratelimit-quota
RUNTIME_SUBDIRECTORY=config
RUNTIME_APPDIRECTORY=config
RUNTIME_WATCH_ROOT=true
RUNTIME_IGNOREDOTFILES=true
SIDECAR_MOD=gateway-1
ZONEINFO=/usr/share/zoneinfo
LOG_LEVEL=WARN
```

### 镜像
- `registry.cn-shanghai.aliyuncs.com/daofeng/ratelimit-quota-server:latest` — 含 tzdata + client ID 修复

### 代码变更

| 文件 | 变更 |
|------|------|
| `src/service/ratelimit_quota.go:421` | SyncCheck SIDECAR_MOD 路径 base64 编码 client ID |
| `src/utils/window_bounds.go:160,175` | `resolveTimezoneLocation` nil 检查 fallback UTC |
| `Dockerfile` | 添加 `apt-get install tzdata` |

---

## 2026-06-10 续：动态链路 Consumer 限流验证

### QuotaRule CRD（多维度 + 动态）

```yaml
apiVersion: networking.istio.io/v1alpha3
kind: QuotaRule
metadata:
  name: test-quota
  namespace: ls-test
spec:
  redis_info:
    redis_url: "redis-builtin.ls-test.svc.cluster.local:6379"
    redis_auth: "f5aa5a6298924a63"
  rules:
    - match:
        - name: "consumer-limit"
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
            request_header: x-consumer    # 注意: source.request_header 是字符串，不是对象
          limit:
            dynamic: true
            fallback:
              requests_per_unit: 100
              unit: MINUTE
              quota_dimension: request
      target:
        routes:
          - echo-server
```

### Controller 产物

ConfigMap 生成:
```yaml
bucket_action:
- bucket_id: {cu: '*'}
  limit_source: remote
  num_instances: 1
  rate_limit_strategy: {quota_dimension: request, requests_per_unit: 100, unit: minute}
parallel_dimensions:
- {dimension_key: cu, limit_type: dynamic, priority: 100}
quota_key_include_requests_per_unit: false
```

### Redis 动态配额

```bash
# Key 格式: rl_dc:{domain}:{uniqueKey}
# uniqueKey = GenerateUniqueKey({"cu": "alice"}) = "cu_alice"

HSET "rl_dc:Kubernetes-quotarule:cu_alice" unit MINUTE requests_per_unit 50 quota_dimension request
HSET "rl_dc:Kubernetes-quotarule:cu_bob"   unit MINUTE requests_per_unit 200 quota_dimension request
```

### 压测结果

| 测试 | 请求数 | 200 | 429 | 配额 | 精确匹配 |
|------|--------|-----|-----|------|:---:|
| alice 初始 | 100 | **50** | 50 | 50/min | ✅ |
| bob 初始 | 300 | **200** | 100 | 200/min | ✅ |
| alice 动态改为 20/min（不重启） | 100 | **20** | 80 | 20/min | ✅ |
| bob 改后不变 | 300 | **200** | 100 | 200/min | ✅ |

### 验证结论

- [x] 不同 consumer 独立配额，精确计数
- [x] Redis 动态修改，无需重启，~10s 后生效（LRU 缓存 TTL）
- [x] consumer 间互不影响
- [x] 全链路: CRD → Controller → ConfigMap(limit_source:remote) → EnvoyFilter(BucketIdBuilder) → Envoy → quota-server → Redis rl_dc: → Lua EVAL → 精确限流

## 下一步

1. **双架构镜像** — arm64 + amd64
2. **将修复推送到 csb2 ratelimit-quota-server 分支**

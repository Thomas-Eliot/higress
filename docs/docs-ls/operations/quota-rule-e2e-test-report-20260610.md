# QuotaRule 端到端测试报告

**日期**: 2026-06-10  
**测试环境**: 阿里云 ACK 集群，namespace `ls-test`  
**测试人**: lvshui  

---

## 一、测试概述

验证 QuotaRule 限流全链路：**CRD → Controller → EnvoyFilter + ConfigMap → Envoy → quota-server → Redis → 精确限流**。

覆盖两种场景：
1. **静态限流** — ConfigMap 固定配额，所有 consumer 共享
2. **动态链路 consumer 限流** — Redis `rl_dc:` per-consumer 独立配额，支持热更新

## 二、测试环境

| 组件 | 镜像 | 说明 |
|------|------|------|
| higress (controller) | `daofeng/higress:quota-rule` | CRD → EnvoyFilter + ConfigMap |
| pilot (discovery) | `daofeng/pilot:quota-rule` | xDS 推送，含 apig proto import |
| gateway (envoy) | `daofeng/gateway:quota-rule` | 含 `rate_limit_quota_apig` filter |
| quota-server (sidecar) | `registry.cn-shanghai.aliyuncs.com/daofeng/ratelimit-quota-server:latest` | 含 3 项 bugfix |
| Redis | `redis-builtin` (集群内) | Data Redis + rl_dc 动态配置 |

### quota-server 环境变量

```
RUNTIME_ROOT=/data/ratelimit-quota       RUNTIME_SUBDIRECTORY=config
RUNTIME_APPDIRECTORY=config              RUNTIME_WATCH_ROOT=true
RUNTIME_IGNOREDOTFILES=true              SIDECAR_MOD=gateway-1
ZONEINFO=/usr/share/zoneinfo             LOG_LEVEL=WARN
```

## 三、测试一：静态限流

### 配置

```yaml
# QuotaRule CRD
spec:
  rules:
    - match: [{name: test, headers: {items: [{name: x-consumer, match_type: ANY}]}}]
      rate_limit: {requests_per_unit: 100, unit: MINUTE, quota_dimension: request}
      target: {routes: [echo-server]}
```

### 结果

| 测试轮次 | 总请求 | 并发 | 200 (通过) | 429 (限流) | 精确匹配 |
|----------|--------|------|-----------|-----------|:--------:|
| Run 1 | 300 | 50 | **100** | 200 | ✅ |
| Run 2 | 300 | 50 | **100** | 200 | ✅ |

**结论**: 静态 100/min 限流精确生效，通过 Redis SyncCheck Lua EVAL 实现全局计数。

## 四、测试二：动态链路 Consumer 限流

### 配置

```yaml
# QuotaRule CRD — 多维度 + 动态
spec:
  rules:
    - match: [{name: consumer-limit, headers: {items: [{name: x-consumer, match_type: ANY}]}}]
      rate_limit: {requests_per_unit: 100, unit: MINUTE, quota_dimension: request, dynamic: true}
      dimensions:
        - short_name: cu
          source: {request_header: x-consumer}
          limit: {dynamic: true, fallback: {requests_per_unit: 100, unit: MINUTE, quota_dimension: request}}
      target: {routes: [echo-server]}
```

Controller 产物:
```yaml
# ConfigMap
bucket_action:
- bucket_id: {cu: '*'}
  limit_source: remote          # 从 Redis 动态读取
parallel_dimensions:
- {dimension_key: cu, limit_type: dynamic, priority: 100}
```

### Redis 动态配额

```bash
HSET "rl_dc:Kubernetes-quotarule:cu_alice" unit MINUTE requests_per_unit 50 quota_dimension request
HSET "rl_dc:Kubernetes-quotarule:cu_bob"   unit MINUTE requests_per_unit 200 quota_dimension request
```

### 结果

| 测试 | Consumer | 配额 | 总请求 | 200 | 429 | 精确匹配 |
|------|----------|------|--------|-----|-----|:--------:|
| 初始 | alice | 50/min | 100 | **50** | 50 | ✅ |
| 初始 | bob | 200/min | 300 | **200** | 100 | ✅ |
| 动态修改（不重启） | alice | **20/min** | 100 | **20** | 80 | ✅ |
| 动态修改后 | bob | 200/min | 300 | **200** | 100 | ✅ |

**结论**: 
- 不同 consumer 独立配额，精确计数
- Redis 动态修改后 ~10s 内生效（LRU 缓存 TTL），无需重启任何组件
- Consumer 间完全隔离

## 五、修复的 Bug

### Bug 1: FileProvider 加载不到 ConfigMap 配置

| 项目 | 内容 |
|------|------|
| 现象 | quota-server 收到 SyncCheck 但全部放行（fail-open），Redis 无 key |
| 根因 | goruntime `loader.New2()` 在 `runtimeSubdirectory==""` 时返回 nil loader |
| 修复 | 环境变量 `RUNTIME_WATCH_ROOT=true` + `RUNTIME_APPDIRECTORY=config` |

### Bug 2: SyncCheck panic — timezone

| 项目 | 内容 |
|------|------|
| 现象 | `time: missing Location in call to Time.In` panic |
| 根因 | 容器无 tzdata，`time.LoadLocation("Asia/Shanghai")` 返回 nil |
| 修复 | Dockerfile 加 `tzdata` + `resolveTimezoneLocation()` nil fallback UTC |
| 文件 | `src/utils/window_bounds.go`, `Dockerfile` |

### Bug 3: SyncCheck client ID 不匹配

| 项目 | 内容 |
|------|------|
| 现象 | SyncCheck 永远返回 DENY，即使 used=0 |
| 根因 | AllocQuotas 用 base64(clientId) 存 prealloc，SyncCheck 用原始值查询 |
| 修复 | `handleSyncCheck` 的 SIDECAR_MOD 路径统一 base64 编码 |
| 文件 | `src/service/ratelimit_quota.go:421` |

## 六、代码变更

| 文件 | 变更说明 |
|------|---------|
| `Dockerfile` | 添加 `apt-get install tzdata ca-certificates` |
| `src/utils/window_bounds.go` | `resolveTimezoneLocation` — `LoadLocation` 失败时 fallback `time.UTC` |
| `src/service/ratelimit_quota.go` | `handleSyncCheck` — SIDECAR_MOD 路径 base64 编码 client ID |

## 七、已知限制

1. **单实例测试**: 当前仅测试单 gateway pod 场景，多实例 prealloc 分配未验证
2. **Token 维度未测试**: 仅测试 `request` 维度，`token`/`concurrency` 维度待验证
3. **镜像仅 amd64**: 尚未构建 arm64 镜像
4. **go.mod replace**: 编译依赖 `csb2/envoy_go-control-plane` istio-1.19 分支的本地 clone

## 八、结论

QuotaRule 限流全链路 e2e 测试**通过**。静态限流和动态链路 consumer 限流均精确匹配配额配置，动态热更新无需重启即可生效。

# Issue：配额冷路径 SyncCheck 始终 deny —— 低速流量永远 429

**日期**：2026-06-17
**环境**：阿里云 ACK，ns `ls-test`，实例 `i-3f60ee95d0a90b6eaba3`
**报告人**：lvshui
**严重级**：高 —— 正常低 QPS 的真实用户流量永远 429，配额功能对常规使用不可用。

---

## 一句话

冷路径（低速流量）下，quota-server 判定 `SYNC_CHECK_ALLOWED`（2~5ms），但 envoy filter **立即 reset 流并 deny**（`latency_ms=0`，非真超时）→ 429。只有**高速 burst**把桶推过 hotspot 阈值切到热路径后才返回 200。

## 镜像（先排除"版本回归"误判）

| 组件 | tag | digest |
|------|-----|--------|
| gateway | `2.1.13` **和** `quota-rule` | **同一个** `sha256:e07232fc9e00c928f86c24f92d4d7f8c5ebd96874faae8c14f6af46b572c34f0` |
| quota-server | `clientid-unify-20260615` | `sha256:7301f97eb1be9e7f632a3ba909e7fd0ccdf2d7804572192275c47fb02f478929` |

> ⚠️ `gateway:2.1.13` 与 `gateway:quota-rule` 是**同一 digest**，换 tag 不换二进制。本问题与镜像 tag 无关，是该 gateway build 自身的冷路径行为。

## 现象与证据

envoy（每个冷路径请求）：
```
sync_quota_checker.h:380  Async quota check timed out, resetting stream to prevent response mismatch
filter.cc:1269            Rate limit decision: mode=cold_path_sync_error, fallback=deny, latency_ms=0
```
quota-server（同一请求）：
```
request_type:SYNC_CHECK  bucket_id:{cu:perf-17759}  result:SYNC_CHECK_ALLOWED  remaining_quota:1000  latency_ms:5.4
level=error msg="Error receiving quota request: rpc error: code = Canceled desc = context canceled"
```
即：quota-server 判定放行并准备回包，但 envoy 已 reset 流（`latency_ms=0` 瞬间判定，非等满默认 20ms `cold_sync_timeout`）→ 响应送不回（context canceled）→ envoy fallback=deny。EnvoyFilter 未配 `cold_sync_timeout`/`cold_fallback_allow_on_error`（默认 20ms / **fail-open=true**），但实测是 **deny**，说明走的是 **"response mismatch" 硬重置**路径，覆盖了 fail-open。

## 复现（关键：速率依赖）

冷桶状态（重启网关 deploy 使本地缓存桶清空）+ 已确认 quota-server 能读到正确配额（`rl_dc:i-3f60ee95d0a90b6eaba3:cu_perf-17759` = 1000 token/day，domain 已对齐）：

| 方式 | 结果 |
|------|------|
| 间隔 0.3s × 30 次 | `429 ×30`（全程冷路径，**从不恢复**） |
| 紧凑 burst（无间隔）× 15 次 | `429 ×9` 然后 `200 ×6`（第 ~10 个越过 hotspot 阈值切热路径） |
| 切热后持续紧凑流量 | 稳定 `200`，counter `{rl_..._token_day_...}:used` total_tokens 正确累加，超 1000 才 429（配额在热路径下 enforce 正确） |

热路径出现时 quota-server 会打 `request_type:ASYNC_REPORT result:ALLOWED allocated_quota:1000→…`；冷路径下**只有 SYNC_CHECK + context canceled，无 ASYNC_REPORT**（流被反复 reset，异步上报也一起被带崩 → assignment 永远建不起来 → 永远停冷路径）。

bearer `000712eaf5e6417b7f91b82088d9077f`（key-auth → `x-mse-consumer: perf-17759`），路由 `POST /v1/chat/completions` + `x-higress-llm-model: qwen2` → mock-llm-qwen2。

## 根因假设（数据面）

1. 冷路径 SyncCheck 的**请求/响应关联失败** → envoy `sync_quota_checker.h` 判 "response mismatch" 立即 reset（`latency_ms=0`），而非等响应。第一个 SyncCheck 一旦没被正确匹配，后续每个都立即 reset → 级联。
2. 该 reset 把承载异步上报的同一条 bidi 流也带崩 → 无法建立 assignment → 无法转热路径（除非高速 burst 强行越过 hotspot_threshold，让 filter 走另一条路）。
3. 默认 `cold_fallback_allow_on_error=true`（fail-open）未生效，被 mismatch-reset 的 deny 覆盖。

## 排除项（都不是病因）

- 镜像 tag（2.1.13 / quota-rule 同 digest）。
- 控制台 CR：结构正确（GLOBAL_DEFAULT + x-mse-consumer + dynamic + fallback token），与 06-16 跑通 CR 一致。
- domain：已对齐（CR `key_domain=i-3f60ee95d0a90b6eaba3`，envoy filter / ConfigMap / console 写入三者一致）。
- quota-server：健康（Redis ping 2ms），判定正确（ALLOWED/remaining 都对）。

## 待查源码

- `envoy/filter.cc:1269`（cold_path_sync_error 决策）、`envoy/sync_quota_checker.h:380`（response mismatch reset / 关联逻辑）。
- `server/service/ratelimit_quota.go` `StreamRateLimitQuotas()` / `handleSyncCheck()`（SyncCheck 响应回包、与异步上报共用流的处理）。
- 对照 06-16 console e2e（[console-driven-token-quota-e2e-20260616.md](./console-driven-token-quota-e2e-20260616.md)）当时冷路径首请求即 200，需确认是否环境/首包延迟差异导致现在播种 mismatch。

## 旁注

压测负载下 gateway pod 被 OOMKill 重建一次（`exit 137`），需关注 gateway/quota-server 在压测下的内存。

## 对照：跑通过的参照

- [6/15 e2e](./e2e-quota-rule-test-report-20260615.md)（echo + request 维度，50×200 后 429）
- [6/16 console-driven token e2e](./console-driven-token-quota-e2e-20260616.md)（token 维度，200…后 SYNC_CHECK_DENIED→429）

# QuotaRule limits_json 多窗口 + 动态下发 e2e 测试报告

**日期**：2026-06-15
**环境**：阿里云 ACK，namespace `ls-test2`
**测试人**：lvshui
**镜像**：`ratelimit-quota-server:clientid-unify-20260615` (digest `sha256:7301f97e…`)
**前置**：环境已按 [env-setup runbook](./e2e-quota-rule-env-setup.md) 完成；单窗口 e2e 已通过 ([e2e 报告](./e2e-quota-rule-test-report-20260615.md))

---

## 一、测试目标

在动态 consumer 限流链路（CRD → controller → ConfigMap + EnvoyFilter → envoy filter → quota-server → Redis）上，验证：

1. **多窗口 `limits_json`**：单个 consumer 同时绑定多个时间窗口配额（如 MINUTE + HOUR），quota-server 解析为多 band
2. **AND 语义**：任一 band 触底立即拒绝
3. **主动重置 basetime**：HSET `base_timestamp` 字段切换 Redis counter key 后缀，等价于"清零"一个或两个 band
4. **热更新 `limits_json`**：在线变更配额数值，不重启 gateway 即生效（双向：缩小+扩大）
5. **跨 consumer 隔离**：alice 多 band 行为不影响 bob 单 band 限流

后端用 echo-server + `request` 维度（每请求 1 token），串行请求避开后端并发干扰（背景见 [e2e 报告 §测试方法](./e2e-quota-rule-test-report-20260615.md#二测试方法学)）。

---

## 二、机制确认（源码层面）

### 2.1 `limits_json` 写法

位置：Redis HASH `rl_dc:{domain}:{uniqueKey}` 的 `limits_json` 字段，值是 JSON 数组：

```json
[
  {"unit":"MINUTE","requests_per_unit":10,"quota_dimension":"request"},
  {"unit":"HOUR","requests_per_unit":12,"quota_dimension":"request"}
]
```

每个元素一个 band，字段：`unit` / `requests_per_unit` / `unit_multiplier` / `quota_dimension` / `version` / `timezone`。

解析路径：`ratelimit-quota-server/src/redis/impl.go:2107 parseDynamicConfigFromHash` → 每个 band 转 `config.TimeQuotaBand` → `RemoteLimits` → `SortTimeQuotaBands` 排序 → `MaxBandRPU` 取最大 RPU 作主窗口。

### 2.2 windowStart 与 `base_timestamp` 的关系

代码：`src/utils/window_bounds.go:56 epochWindowBounds`

```
windowStart = base_timestamp + ((now - base_timestamp) / divider) * divider
```

- `window_alignment=calendar`（默认）：忽略 `base_timestamp`，按自然日历边界
- `window_alignment=epoch`：用 `base_timestamp` 锚定窗口
- **windowStart 会拼到 Redis counter key 后缀**：`rl_{domain}_{uniqueKey}_{dimension}_{unit}_{windowStart}`（key 后缀见 `quota_key.go:250` 测试）

所以"重写 `base_timestamp`"等价于切到新的 counter key → 旧 key 自然 TTL 过期，新 key 从 0 开始计 → 实现**主动重置**。

注意：`base_timestamp` 是 HASH 顶层字段（不是 per-band），重置时 **所有 band 共享同一新 basetime**。

### 2.3 LRU 缓存与热更新延迟

`fixedRateLimitCacheImpl.dynamicConfigLru` 缓存解析后的配置，positive TTL=10s（控制 plane Redis 默认）。所以变更 HASH 后**最多 10s** 生效。如启用了 Redis keyspace notification（`CONFIG SET notify-keyspace-events KEA`，启动时 quota-server 主动配置），可即时失效。

实测：写 HASH 后 `sleep 12` 足够看到新配置生效（无需重启）。

---

## 三、测试用例 + 实测结果

### 配置参数

- Consumer：`alice`（多 band）、`bob`（单 band 对照组）
- 维度：`request`
- 后端：`echo-server.ls-test2.svc:80`，路径 `/echo`
- 入口：SLB `8.156.95.31:80`

初始状态（P0 之前）：alice/bob 都是单窗口（alice 50/min、bob 200/min）。

---

### 用例 1 (P0)：写入多窗口 `limits_json` + epoch 对齐

**操作**：

```bash
T0=$(date +%s)   # 1781527597
kubectl exec -n higress-system redis-builtin-0 -- redis-cli ... DEL rl_dc:Kubernetes-quotarule:cu_alice
kubectl exec ... HSET rl_dc:Kubernetes-quotarule:cu_alice \
  quota_dimension request \
  window_alignment epoch \
  base_timestamp $T0 \
  limits_json '[{"unit":"MINUTE","requests_per_unit":10,"quota_dimension":"request"},
                {"unit":"HOUR","requests_per_unit":12,"quota_dimension":"request"}]'
sleep 5
curl -H "x-consumer: alice" http://$SLB/echo   # probe
```

**期望**：quota-server 解析两个 band，第一个请求两 band 同步扣减。

**实测**：✅

```
GetDynamicLimit: returning config for rl_dc:Kubernetes-quotarule:cu_alice
  (rpu=12 unit=minute dim=request alignment=epoch tz= remote_bands=2)

[SYNC_CHECK] Input: maxQuota=10, windowStart=1781527597, expireIn=43s    # MINUTE band
[SYNC_CHECK_STRING] key=rl_Kubernetes-quotarule_cu_alice_request_minute_1781527597 allowed=true remaining=9
[SYNC_CHECK] Input: maxQuota=12, windowStart=1781527597, expireIn=3583s  # HOUR band
[SYNC_CHECK_STRING] key=rl_Kubernetes-quotarule_cu_alice_request_hour_1781527597 allowed=true remaining=11
```

两个 band 都解析了，counter key 后缀含 windowStart=T0。

---

### 用例 2 (P1)：MINUTE band 触底（AND 语义验证 1/2）

**操作**：在 P0 windowStart=T0 的 MINUTE 窗口内 burst 11 个请求（加上 P0 probe 共 12 个）。

```bash
for i in $(seq 1 11); do curl -H "x-consumer: alice" http://$SLB/echo; sleep 0.15; done
```

**期望**：10×200（MINUTE 共 10 配额）+ 2×429（MINUTE 触底）。

**实测**：✅ `200×9 + 429×2`（加上 P0 probe = 10×200 + 2×429）。

quota-server log：
- 第 9 burst（第 10 总数）：`minute remaining=0 allowed=true`（最后一个允许）
- 第 10 burst：`minute remaining=0 allowed=false`（拒）
- 第 11 burst：同上

---

### 用例 3 (P2)：HOUR band 拦截（AND 语义验证 2/2）

**操作**：等 MINUTE 窗口自动滚到新窗口（windowStart=T0+120），再 probe 5 个。

```bash
sleep ~90s   # 让 MINUTE 滚到第 3 个窗口
for i in 1..5; do curl -H "x-consumer: alice" http://$SLB/echo; done
```

**期望**：MINUTE 已重置允许，但 HOUR 仍在原窗口 used=12（剩 0）→ 全部 429。

**实测**：✅ `429 429 429 429 429`

log（典型一次）：

```
[SYNC_CHECK_STRING] key=...minute_1781527717 allowed=true  remaining=8   # MINUTE 新窗口允许
[SYNC_CHECK_STRING] key=...hour_1781527597   allowed=false remaining=0   # HOUR 拦截
[SYNC_CHECK] Result: allowed=false                                       # 最终拒
```

**结论**：HOUR band 在 MINUTE 还有余量时切断 → AND 语义命中 ✓

---

### 用例 4 (P3)：主动重置 basetime（运维场景）

**操作**：在 alice 仍处于 HOUR 触底状态时，HSET 新 `base_timestamp=T1`（T1=now，比 T0 晚 ~211s）。

```bash
T1=$(date +%s)   # 1781527808
kubectl exec ... HSET rl_dc:Kubernetes-quotarule:cu_alice base_timestamp $T1
sleep 12   # LRU 10s TTL
for i in 1..5; do curl -H "x-consumer: alice" http://$SLB/echo; done
```

**期望**：counter key 后缀切到 T1，两 band 全新计数 → 全部 200。

**实测**：✅ `200 200 200 200 200`

log：

```
[SYNC_CHECK] Input: windowStart=1781527808 ...   # 新 windowStart=T1
[SYNC_CHECK_STRING] key=...minute_1781527808 remaining=9→8→7→6→5
[SYNC_CHECK_STRING] key=...hour_1781527808   remaining=11→10→9→8→7
```

旧 key（`...minute_1781527597` / `...hour_1781527597`）保留在 Redis 中按 TTL 过期，新 key 从满额开始。

> ⚠️ **basetime 是 HASH 顶层字段，同时影响所有 band**。如果只想重置某个 band，当前 schema 不支持 per-band basetime。要单独重置某 band 的 counter 需要直接 `DEL` 对应 counter key（运维侧操作）。

---

### 用例 5 (P4)：热更新 `limits_json`（双向）

#### P4a：缩小配额 + 配套 basetime reset

```bash
T2=$(date +%s)   # 1781527869
kubectl exec ... HSET rl_dc:Kubernetes-quotarule:cu_alice \
  base_timestamp $T2 \
  limits_json '[{"unit":"MINUTE","requests_per_unit":5,"quota_dimension":"request"},
                {"unit":"HOUR","requests_per_unit":20,"quota_dimension":"request"}]'
sleep 12
for i in 1..6; do curl -H "x-consumer: alice" http://$SLB/echo; done
```

**期望**：新 MINUTE=5 → 5×200 + 1×429。

**实测**：✅ `200 200 200 200 200 429`

log: `maxQuota=5 windowStart=1781527869`，第 6 个请求被新配额拦截。

#### P4b：扩大配额（不动 basetime）

```bash
kubectl exec ... HSET rl_dc:Kubernetes-quotarule:cu_alice \
  limits_json '[{"unit":"MINUTE","requests_per_unit":15,"quota_dimension":"request"},
                {"unit":"HOUR","requests_per_unit":30,"quota_dimension":"request"}]'
sleep 12
for i in 1..10; do curl -H "x-consumer: alice" http://$SLB/echo; done
```

**期望**：同 windowStart=T2，MINUTE used=5（P4a 用了），扩到 15 → 还剩 10，10 个 burst 全过。

**实测**：✅ `200 200 200 200 200 200 200 200 200 200`

log：`maxQuota=15 windowStart=1781527869`（windowStart 没变），MINUTE remaining 持续递减直到尾部。

**结论**：
- 配额缩小+basetime reset 联合下发 → 立即生效，旧 used 与新 quota 重新对账
- 配额扩大不动 basetime → counter 延续，新 quota 直接 lift 上限（适合临时放量）

---

### 用例 6 (P5)：alice/bob 跨 consumer 隔离

**操作**：在 alice 多 band 状态下交替发 alice + bob 各 8 次。

```bash
for i in 1..8; do
  curl -H "x-consumer: alice" http://$SLB/echo
  curl -H "x-consumer: bob" http://$SLB/echo
done
```

bob 配置（保持不变）：

```
unit=MINUTE  requests_per_unit=200  quota_dimension=request   # 单 band（无 limits_json）
```

**期望**：bob 8/8 全 200（远未触达 200/min）；alice 行为不受 bob 影响。

**实测**：✅

```
alice: 429 429 429 429 200 200 200 200    # MINUTE 窗口中途 roll 到新窗口，开始放行
bob:   200 200 200 200 200 200 200 200
```

bob counter key: `{rl_..._cu_bob_request_MINUTE_1781527920}:used = 8 tokens`
alice counter key: `{rl_..._cu_alice_request_minute_1781527929}:used = 4 tokens`（新窗口）

两个 consumer Redis key 完全独立。

---

## 四、最终 Redis counter 全景

测试结束时 alice / bob 在 control-plane Redis 上的状态：

| Key | total_tokens | TTL | 说明 |
|---|---|---|---|
| `{rl_..._cu_alice_request_hour_1781527597}:used` | 12 | 3234s | P0-P2，basetime=T0 时段的 HOUR 累计 |
| `{rl_..._cu_alice_request_hour_1781527808}:used` | 5 | 3449s | P3，basetime=T1 时段的 HOUR 累计 |
| `{rl_..._cu_alice_request_hour_1781527869}:used` | 24 | 3512s | P4-P5，basetime=T2 时段的 HOUR 累计 |
| `{rl_..._cu_alice_request_minute_1781527929}:used` | 4 | 28s | P5 末尾 MINUTE 新窗口 |
| `{rl_..._cu_bob_request_MINUTE_1781527920}:used` | 8 | 15s | bob 单窗口 |

**观察点**：
- 历史 basetime 的 HOUR counter key 同时存在，等 TTL（约 1 小时）自然过期
- bob 的 key 是 `MINUTE`（大写），alice 是 `minute`（小写）— 单 band 路径直接传 `unit` 字段（大写），limits_json 路径走 `trimUnit` 归一化为小写。功能等价，不影响限流，但建议后续统一

---

## 五、链路通过项

| 测试维度 | 验证项 | 状态 |
|---|---|---|
| limits_json 解析 | quota-server 把 JSON 数组拆成 N 个 band，`remote_bands=N` | ✅ |
| 多 band Redis key 隔离 | 每 band 一个独立 counter key（unit 后缀 minute/hour） | ✅ |
| AND 语义 | 任一 band 触底立即拒，最终 `allowed=false` | ✅ |
| basetime 重置 | HSET 新 basetime → counter key 后缀切换 → 计数从 0 开始 | ✅ |
| 热更新缩小 | 缩小+reset basetime 联合下发，新配额立即生效 | ✅ |
| 热更新扩大 | 不动 basetime 同 counter key 直接抬高 maxQuota | ✅ |
| 跨 consumer 隔离 | alice/bob counter key 独立递减，互不干扰 | ✅ |

---

## 六、发现 / 待跟踪问题

### 6.1 拒绝的请求仍消耗其它 band 计数

P1 中第 11/12 个请求被 MINUTE band 拒，但 HOUR band 的 counter 同步递减。最终 HOUR `total_tokens=12`，等于"提交请求总数"而非"允许请求数"。

源码位置：`src/redis/sync_check.go`（多 band 检查路径）

潜在影响：
- 客户在被 MINUTE 限流的同时，HOUR 余额也快速耗尽
- 用户重试在 MINUTE 重置后可能 HOUR 已先耗尽，体验差

**待定**：是否要改成"按最终决定回滚"语义？需要业务侧 RFC（影响 SLA 解释）。当前实测没看到 quota-server log 出现回滚分支。

### 6.2 P3 之后第一个 MINUTE 新窗口起步 remaining=8 而非 9

P2 等 MINUTE 自动滚后，新 windowStart 的首个请求 SYNC_CHECK 输出 `remaining=8`（期望 9）。1-token 偏差，疑似 envoy CachedBucket / `no_assignment_behavior.fallback_rate_limit.token_bucket`（100/60s）在本地预扣。串行 / 单请求测试不影响正确性，但并发场景需要量化下漏算 / 重算的边界。

### 6.3 unit 大小写不一致

bob（单 band 路径）counter key 是 `_MINUTE_`，alice（limits_json 路径）是 `_minute_`。背后是不同的 unit 归一化路径：`limitsFromHashFields` 走 `parseLimitsFromHashRow` 转小写，单 band 路径走 `parseDynamicConfigFromHash` 直接取 `fields["unit"]` 保留大小写。建议在 `quota_key.go:GenerateQuotaKey` 入口统一 `strings.ToLower`，避免理论上的大小写双 key 漏算。

---

## 七、操作 cheatsheet（运维向）

写 / 改多窗口配额：

```bash
REDIS_AUTH="1905b762fd25c8a5"
DOMAIN="Kubernetes-quotarule"
KEY="rl_dc:$DOMAIN:cu_<consumer>"

kubectl exec -n higress-system redis-builtin-0 -- redis-cli -a "$REDIS_AUTH" --no-auth-warning HSET "$KEY" \
  quota_dimension request \
  window_alignment epoch \
  base_timestamp $(date +%s) \
  limits_json '[{"unit":"MINUTE","requests_per_unit":N1,"quota_dimension":"request"},
                {"unit":"HOUR","requests_per_unit":N2,"quota_dimension":"request"}]'
# ~10s 内生效（LRU TTL）
```

主动重置一个 consumer 的所有 band：

```bash
kubectl exec ... HSET "$KEY" base_timestamp $(date +%s)
# 10s 内下个请求开新 counter key，旧 key 按 TTL 自然过期
```

只清某个 band（绕过 basetime）：

```bash
kubectl exec ... DEL "{rl_${DOMAIN}_cu_<consumer>_request_<unit>_<windowStart>}:used"
kubectl exec ... DEL "{...}:client_usage"
kubectl exec ... DEL "{...}:synccheck"
```

---

## 八、相关文档

- [环境准备 runbook](./e2e-quota-rule-env-setup.md) — 集群部署前置
- [单窗口 e2e 报告](./e2e-quota-rule-test-report-20260615.md) — alice/bob 基础限流通过
- [多窗口测试调研笔记](./quota-rule-multi-window-test-20260615.md) — limits_json 调研 + 历史 bug 清单（部分已推翻）
- [6/10 决策记录](./quota-rule-e2e-test-20260610.md) — 全链路首次打通

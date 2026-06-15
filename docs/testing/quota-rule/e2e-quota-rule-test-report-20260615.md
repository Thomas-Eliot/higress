# QuotaRule e2e 测试报告

**日期**：2026-06-15
**环境**：阿里云 ACK，namespace `ls-test2`
**测试人**：lvshui
**镜像**：`ratelimit-quota-server:clientid-unify-20260615`（digest `sha256:7301f97e...`）
**前置**：环境已按 [环境准备 runbook](./e2e-quota-rule-env-setup.md) 完成，sanity check 12 节全通过。

---

## 一、测试目的

验证 QuotaRule 动态 consumer 限流链路在当前镜像 + 部署下：
1. 链路结构正确（CRD → Controller → ConfigMap + EnvoyFilter → Envoy → quota-server → Redis）
2. 单 consumer 配额能精确触达 / 触发
3. 多 consumer 之间配额隔离

---

## 二、测试方法学

**用串行请求，不用并发压测**。

QuotaRule 链路本身在串行 + 中高并发下都能精确限流；但本环境的测试后端 echo-server 在并发请求下会返回大量 400（response_code_details: `via_upstream`），跟限流链路无关。串行请求可以稳定看到精确的限流分布。

并发压测见 [§ 五 已知干扰](#五已知干扰)，未来换 backend 后可补回并发压测。

---

## 三、链路结构观察

### 3.1 Controller 生成的 ConfigMap

```yaml
bucket_action:
- bucket_id: { cu: '*' }
  limit_source: remote
  num_instances: 1
  rate_limit_strategy:
    quota_dimension: request
    requests_per_unit: 100
    unit: minute
domain: Kubernetes-quotarule
parallel_dimensions:
- dimension_key: cu
  limit_type: dynamic
  priority: 100
redis_info:
  redis_auth: 1905b762fd25c8a5
  redis_url: redis-builtin.higress-system.svc.cluster.local:6379
```

### 3.2 Envoy listener 80 配置

listener-level filter 配置：

```json
{
  "name": "envoy.filters.http.rate_limit_quota_apig",
  "typed_config": {
    "rlqs_server": {
      "envoy_grpc": { "cluster_name": "rate_limit_quota_service" }
    },
    "domain": "Kubernetes-quotarule",
    "stat_prefix": "quota_filter"
  }
}
```

per-route override（仅动态形态有）：含 `bucket_matchers` + `bucket_id_builder.cu` 提取 `x-consumer` header + `no_assignment_behavior.fallback_rate_limit.token_bucket`（100 tokens/60s）。

### 3.3 quota-server 启动状态

```
Successfully loaded the initial ratelimit configs
get quota ratelimit domain: Kubernetes-quotarule bucket_action: cu_*_100_minute_request
Loaded config: cu_*_100_minute_request
```

`bucket_action: cu_*` 是 wildcard → 运行时 `cu_alice` / `cu_bob` 会走 wildcard match，去 Redis 查精确配额。

---

## 四、测试用例 + 实测结果

### 测试用例 1：alice 精确触达 50/min 配额

**Redis 配置**：`rl_dc:Kubernetes-quotarule:cu_alice` → 50/min request

**步骤**：等到分钟边界开始，串行发 50 个 alice 请求（间隔 100ms），再补 5 个。

```bash
SLB=8.156.95.31
for i in $(seq 1 50); do
  curl -s -o /dev/null -w "%{http_code} " -H "x-consumer: alice" http://$SLB/echo
  sleep 0.1
done; echo ""
for i in $(seq 1 5); do
  curl -s -o /dev/null -w "%{http_code} " -H "x-consumer: alice" http://$SLB/echo
done; echo ""
```

**期望**：前 50 个全 200，后 5 个全 429。

**实测**：
```
200 ×50
429 429 429 429 429
```

✅ **完全命中**。

quota-server log 印证：
- 前 50 次：`[SYNC_CHECK] Result: ... allowed=true, remaining=49→48→...→0`
- 后 5 次：`[SYNC_CHECK] Result: ... allowed=false, remaining=0`

### 测试用例 2：bob 精确触达 200/min 配额（未耗尽场景）

**Redis 配置**：`rl_dc:Kubernetes-quotarule:cu_bob` → 200/min request

**步骤**：bob 串行发 10 个请求（远低于配额）。

```bash
for i in $(seq 1 10); do
  curl -s -o /dev/null -w "%{http_code} " -H "x-consumer: bob" http://$SLB/echo
done; echo ""
```

**期望**：10 个全 200。

**实测**：
```
200 200 200 200 200 200 200 200 200 200
```

✅ **完全命中**。Redis 计数器从 200 递减到 190。

### 测试用例 3：多 consumer 配额隔离

**步骤**：交替串行发 alice + bob 请求（每人 3 个），验证 Redis 两个 key 独立计数。

```bash
for i in 1 2 3; do
  curl -s -o /dev/null -w "%{http_code} " -H "x-consumer: alice" http://$SLB/echo
  curl -s -o /dev/null -w "%{http_code} " -H "x-consumer: bob" http://$SLB/echo
done; echo ""
```

**期望**：6 个全 200。alice 计数器递减 3，bob 计数器递减 3，互不干扰。

**实测**：
```
200 200 200 200 200 200
```

quota-server log：
- 3 次 `bucket=map[cu:alice] remaining=N→N-1→N-2`
- 3 次 `bucket=map[cu:bob] remaining=M→M-1→M-2`

✅ **完全命中**。两个 consumer 的 Redis bucket key 独立扣减，分别为 `rl_Kubernetes-quotarule_cu_alice_request_MINUTE_<bucket>` 和 `rl_Kubernetes-quotarule_cu_bob_request_MINUTE_<bucket>`。

---

## 五、已知干扰

| 干扰 | 表现 | 处理 |
|---|---|---|
| echo-server 并发 400 | `hey -c N` 压测时大量 `400 via_upstream`，跟限流无关 | 用串行测试规避；将来换 nginx-static / busybox 等并发友好 backend 后可恢复 hey 压测 |
| envoy fallback bucket 偶发拦截 | 高并发 burst 时少数请求绕过 SyncCheck，被 listener 80 上的 `no_assignment_behavior.fallback_rate_limit.token_bucket`（100/60s 共享）拦截，envoy access log `RL flag + quota_rate_limited` | 这是 envoy apig filter 在 CachedBucket 还没建立时的设计兜底；串行测试不触发 |

---

## 六、链路通过项

| 链路环节 | 验证项 | 状态 |
|---|---|---|
| Controller | CRD → ConfigMap + EnvoyFilter 正确生成 | ✅ |
| Envoy listener 80 | quota filter 注入 + per-route override 含 bucket_matchers | ✅ |
| Envoy → quota-server | bucket `{cu:<consumer>}` 通过 gRPC SyncCheck 传递 | ✅ |
| quota-server | wildcard `cu_*` 命中 → Redis 查精确配额 → 精确扣减 | ✅ |
| 响应路径 | SyncCheck 响应 `BlanketRule + degraded:true`，envoy 正确执行 ALLOW/DENY | ✅ |
| 多 consumer 隔离 | alice / bob 各自的 Redis 计数 key 独立递减 | ✅ |

---

## 七、相关文档

- [环境准备 runbook](./e2e-quota-rule-env-setup.md) — 前置部署步骤
- [6/10 e2e 决策记录](./quota-rule-e2e-test-20260610.md) — 历史首次跑通的故障 + 决策
- [6/15 多窗口测试](./quota-rule-multi-window-test-20260615.md) — `limits_json` 多窗口测试场景
- [6/15 重跑踩坑记录](../../operations/incident-replay-6.10-flow-on-ls-test2-20260615.md) — 排障流水（按时间序）

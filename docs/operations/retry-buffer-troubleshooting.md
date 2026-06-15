本文面向开发和运维同学，说明「重试已配置但偶发 503 仍未触发重试」这一类问题的排查方法、根因和修复方案。配套 [retry-demo-test.md](retry-demo-test.md) 使用。

## 现象

典型症状：

```plain
1. 控制台已配置重试策略（proxy-next-upstream / proxy-next-upstream-tries）
2. Ingress annotation 也已正确写入
3. config_dump 反查 retry_policy，num_retries / retry_on / retriable_status_codes 全部正确
4. 但生产 access log 仍然偶发 503，且 response_flags 只有 UC，看不到 URX
5. 重新部署、重启 gateway 都无效
6. 单次失败率本就不高，按统计正常重试若生效，连续多次失败的概率应当趋近于 0
```

如果你的现场命中以上 5 条以上，大概率是 listener 层 buffer 不足导致 router 重试 replay buffer overflow，本文给出的就是这一类问题的排查与修复路径。

## 关键日志字段

排查入口是 Envoy access log 的三个字段：

| 字段                    | 命令操作符                | 含义                                 |
| ----------------------- | ------------------------- | ------------------------------------ |
| `response_code`         | `%RESPONSE_CODE%`         | 最终返回给客户端的状态码             |
| `response_flags`        | `%RESPONSE_FLAGS%`        | Envoy 层失败标记                     |
| `response_code_details` | `%RESPONSE_CODE_DETAILS%` | 状态码生成的具体原因                 |
| `bytes_received`        | `%BYTES_RECEIVED%`        | 客户端 → 网关方向的请求 body 字节数 |

`response_flags` 上常见的与本类问题相关的标志：

```plain
UC      上游在响应头之前关闭/重置连接（connection_termination）
URX     重试达到上限仍然失败（retry exhausted）
UC,URX  发生过重试且都失败（重试生效但都没救活）
```

判定规则：

```plain
response_flags = "UC"          → 重试没触发，回到本文 → 检查 buffer
response_flags = "UC,URX"      → 重试发生且耗尽，是真业务问题（上游持续不可达）
response_flags = "URX"         → 同上
```

## 根因：listener per_connection_buffer_limit_bytes

Envoy router filter 在 decode 阶段把请求 body 副本累积在内部 buffer 中，准备在 reset 时 replay 给上游做重试。这个 buffer 的上限受**所在 listener 的 `per_connection_buffer_limit_bytes`** 约束。

```plain
请求 body 累积量 ≤ buffer 上限   → router 保留副本，可以重试
请求 body 累积量 > buffer 上限   → 高水位触发，stream 被标记为不可 replay
                                    后续任何 reset / 5xx 都会静默放弃重试
                                    response_flags 也不会留下 URX
```

Higress 默认值：

```plain
listener per_connection_buffer_limit_bytes = 32768  (32KB)
```

LLM 调用场景下请求 body 普遍超过 32KB（例如 chat completion + RAG context 经常 60KB ~ 200KB），所以这一类业务一旦命中上游异常，配的重试相当于没配。

## Higress 配置项

控制 listener buffer 上限的字段，在 `higress-config` configmap 中：

```yaml
# kubectl get cm higress-config -n higress-system -o yaml
data:
  higress: |
    downstream:
      connectionBufferLimits: 32768       # listener per_connection_buffer_limit_bytes
      ...
    upstream:
      connectionBufferLimits: 10485760    # cluster per_connection_buffer_limit_bytes（与本问题无关）
      ...
```

字段映射：

| Higress 字段                          | Envoy 字段                                      | 默认值   |
| ------------------------------------- | ----------------------------------------------- | -------- |
| `downstream.connectionBufferLimits`   | listener `per_connection_buffer_limit_bytes`    | 32768    |
| `upstream.connectionBufferLimits`     | cluster `per_connection_buffer_limit_bytes`     | 10485760 |

注意：与本问题相关的是 **downstream**（listener 入向）那一项；upstream 是上游连接 buffer，跟 router 重试 replay 无关，不需要改。

## 阈值二分定位

如果想在自己环境复现这个问题、确认阈值出处，可按下述步骤：

### 准备 retry-demo

参考 [retry-demo-test.md](retry-demo-test.md) 部署 retry-demo。Ingress 注解推荐：

```yaml
higress.io/enable-proxy-next-upstream: "true"
higress.io/proxy-next-upstream: error,timeout,non_idempotent,http_502,http_503,http_504
higress.io/proxy-next-upstream-tries: "1"
higress.io/proxy-next-upstream-timeout: "0"
```

### 测试脚本

每次换 key、不同 body size 跑 POST + status-503 + fail=1。pod_attempt 为 2 表示重试生效，为 1 表示重试未触发。

```bash
GW_NS=<gateway-namespace>          # higress-gateway 所在命名空间
DEMO_NS=<retry-demo-namespace>     # retry-demo 所在命名空间

run_one() {
  local size="$1"
  local key="t${size}-$(date +%s%N | tail -c 6)"
  local body=$(python3 -c "print('{\"d\":\"' + 'x'*$size + '\"}')")
  local code=$(kubectl exec -n "$GW_NS" deploy/higress-gateway -c higress-gateway -- \
    curl -sS -o /dev/null -w "%{http_code}" -X POST \
    -H "Host: retry-demo.local" -H "Content-Type: application/json" \
    --data-binary "$body" \
    "http://127.0.0.1/retry-demo/status-503?key=${key}&fail=1")
  sleep 1
  local cnt=$(kubectl exec -n "$DEMO_NS" deploy/retry-demo -- \
    sh -c "cat /tmp/retry-demo-*${key}* 2>/dev/null" || echo 0)
  printf "body=%-6s http=%s pod_attempt=%s\n" "$size" "$code" "$cnt"
}

for SIZE in 20000 28000 32000 36000 48000 65000; do run_one $SIZE; done
```

### 期望输出（默认 32KB buffer）

```plain
body=20000  http=200  pod_attempt=2
body=28000  http=200  pod_attempt=2
body=32000  http=200  pod_attempt=2
body=36000  http=503  pod_attempt=1   ← 阈值之上立即断崖
body=48000  http=503  pod_attempt=1
body=65000  http=503  pod_attempt=1
```

阈值精确等于 listener 的 `per_connection_buffer_limit_bytes`（默认 32768，含部分 header 开销，所以实际 cutoff 略小于 32768）。

## 修复方案

调大 `higress-config` 中的 `downstream.connectionBufferLimits`：

```bash
kubectl edit cm higress-config -n higress-system
```

把：

```yaml
downstream:
  connectionBufferLimits: 32768
```

改成：

```yaml
downstream:
  connectionBufferLimits: 1048576    # 1MB，覆盖绝大部分 LLM/AI 业务
```

LLM 业务经验值参考：

| 取值      | 适用场景                                       |
| --------- | ---------------------------------------------- |
| 1048576   | 普通 chat completion，含中等长度 RAG context   |
| 4194304   | 大型 RAG / 长文档输入 / 多轮对话历史拼接       |
| 10485760  | 极端大 prompt 场景，等同 upstream 上限         |

不建议无限调大；这是上限不是分配，但单条连接异常累积时确实会吃掉这么多内存。

## 修复后验证

### 1. 配置已下发

```bash
kubectl get cm higress-config -n higress-system -o jsonpath='{.data.higress}' \
  | grep -A 1 "downstream:"
```

期望：

```plain
downstream:
  connectionBufferLimits: 1048576
```

### 2. Envoy 已收到推送

xDS 热推送，**不需要重启 gateway pod**。10-20 秒内可收到新配置：

```bash
kubectl exec -n <gateway-ns> deploy/higress-gateway -c higress-gateway -- \
  curl -s 'http://127.0.0.1:15000/config_dump' \
  | grep "per_connection_buffer_limit_bytes" | sort | uniq -c
```

期望（数字按修复值匹配）：

```plain
1 "per_connection_buffer_limit_bytes": 1048576,   ← listener
4 "per_connection_buffer_limit_bytes": 10485760,  ← clusters
```

### 3. 重试已恢复

用前述 retry-demo 二分脚本再跑一次，所有 body size 全部应该 `http=200 pod_attempt=2`。

## 注意事项

### 1. 千万别用 sed 全字符串替换

`10485760` 包含 `1048576` 子串，使用以下命令会把 upstream 的 10MB 误改成 320KB：

```bash
# 错误示例，会破坏 upstream.connectionBufferLimits
sed 's/connectionBufferLimits: 1048576/connectionBufferLimits: 32768/' file.yaml
```

正确做法：

- 用 `kubectl edit` 手工修改
- 或用 `kubectl replace` 整份 cm 替换
- 或用精确锚定的 sed（带前后字段）

### 2. 修复影响面是全局

`higress-config` 是全局 configmap，修改后所有 listener 的 buffer 上限都会涨。如果要按路由控制，使用 EnvoyFilter 给单条路由加 `per_request_buffer_limit_bytes` 是更精细的方法（但需要额外维护一个 CR）。

### 3. POST 重试还有其他前置条件

`per_connection_buffer_limit_bytes` 只是 POST 重试的必要条件之一，下面这些条件同样必须满足：

```plain
1. retry_on 包含 non_idempotent           （否则 POST 不重试）
2. retry_on 包含 5xx 或 retriable-status-codes
3. proxy-next-upstream-tries ≥ 1
4. 上游在 response 头之前 reset           （response 已开始就不能重试）
```

修 buffer 之前先用 retry-demo 的 GET + reset-before-headers 路径确认前述条件都已就绪。

### 4. URX 标志只在重试发生且失败时出现

排查时不要看到 `UC` 单独出现就以为「重试根本没下发」。`UC` 单独出现可能是：

```plain
1. retry_on 不含 error              → 重试没触发
2. POST 但 retry_on 不含 non_idempotent → 重试没触发
3. body > listener buffer 上限      → 重试静默放弃 ← 本文场景
```

只有 `UC,URX` 或 `URX` 才能确认「重试已发生且耗尽」。

## 排查 checklist

按顺序对照即可，命中其一就停下来修复对应项。

```plain
□ 1. config_dump 中目标 route 的 retry_policy 字段是否存在
□ 2. retry_on 是否包含：5xx / retriable-status-codes / non_idempotent（POST 必需）
□ 3. num_retries 是否 ≥ 1
□ 4. retriable_status_codes 是否覆盖了实际错误码（502/503/504）
□ 5. 失败请求的 access log 是 UC 单独出现（怀疑本文场景），还是 UC,URX（真业务问题）
□ 6. 失败请求的 bytes_received 是否 > listener per_connection_buffer_limit_bytes
□ 7. higress-config.downstream.connectionBufferLimits 当前值
□ 8. retry-demo 在客户环境同样 annotation 下，POST + 65KB body 是否能复现 pod_attempt=1
```

满足条件 1-4 但 5 命中 UC、6 超过当前 buffer 值，本文方案直接适用。

## 排查命令汇总

```bash
# 看当前 listener buffer 上限
kubectl exec -n <gateway-ns> deploy/higress-gateway -c higress-gateway -- \
  curl -s 'http://127.0.0.1:15000/config_dump' \
  | grep "per_connection_buffer_limit_bytes" | sort | uniq -c

# 看目标路由的 retry_policy
kubectl exec -n <gateway-ns> deploy/higress-gateway -c higress-gateway -- \
  curl -s 'http://127.0.0.1:15000/config_dump' \
  | grep -A 30 '"name": "<route-name>"'

# 看重试相关 stats（集群维度）
kubectl exec -n <gateway-ns> deploy/higress-gateway -c higress-gateway -- \
  curl -s 'http://127.0.0.1:15000/stats' \
  | grep -E "<cluster>.*(rq_retry|rq_retry_success|rq_retry_limit_exceeded|retry_or_shadow_abandoned)"

# 看 higress-config 当前值
kubectl get cm higress-config -n higress-system -o jsonpath='{.data.higress}' \
  | grep -E "connectionBufferLimits"

# 修复（手工编辑）
kubectl edit cm higress-config -n higress-system
```

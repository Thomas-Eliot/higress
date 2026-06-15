本文面向开发和测试同学，说明网关重试配置的验收范围、Retry Demo 复现方式、测试用例和预期结果。

## 提测范围

本次重点验证网关路由重试配置是否正确下发并生效：

```plain
proxy-next-upstream: error, timeout, invalid_header, non_idempotent, http_502, http_503, http_504
proxy-next-upstream-tries
proxy-next-upstream-timeout
```

需要同时确认两件事：

```plain
1. Ingress annotation 已按控制台配置写入
2. 请求经过网关后的重试行为符合预期
```

说明：

```plain
Envoy route.retry_policy 只作为排查和辅助参考，不作为测试同学必须关注的验收项。
常规验收以控制台配置、Ingress annotation、请求响应和 demo attempt 为准。
```

## 控制台入口

本次重试策略在控制台中有两个入口：

```plain
1. Model API 策略配置
2. 路由策略配置
```

两边最终都应写入同类 Higress 重试配置，建议做等价性测试：

```plain
相同重试条件、重试次数、重试超时时间下：
Model API 策略配置生成的 Ingress annotation 应与路由策略配置保持一致
经过网关后的重试行为也应一致
```

本文的 Retry Demo 更适合通过“路由策略配置”来验证，因为 Demo 本质是一个普通 HTTP 上游服务，便于直接配置 `/retry-demo` 前缀路由并观察 attempt。

## Retry Demo

复现清单：

```plain
kubectl -n <test-namespace> apply -f - <<'EOF'
# 粘贴本文末尾“附录：Retry Demo YAML”中的完整 YAML
EOF
kubectl -n <test-namespace> rollout status deploy/retry-demo --timeout=120s
```

资源信息：

| **项目**          | **值**                                                   |
| ----------------- | -------------------------------------------------------- |
| Deployment        | `retry-demo`                                             |
| Service           | `retry-demo`                                             |
| 默认 Service 类型 | `ClusterIP`                                              |
| 服务端口          | `80`                                                     |
| 通用路径前缀      | `/retry-demo`                                            |
| 镜像              | `registry.cn-shanghai.aliyuncs.com/daofeng/nginx:alpine` |
| 实现方式          | BusyBox `nc` + shell handler                             |

测试变量：

```plain
GW_HOST=<gateway-host>
DEMO_HOST=<demo-service-host>
KEY="$(date +%s)"
```

参数说明：

| **参数** | **默认值** | **说明**                       |
| -------- | ---------- | ------------------------------ |
| `key`    | `default`  | 计数 key。每轮测试必须换新 key |
| `fail`   | `1`        | 前多少次模拟失败，之后恢复 200 |
| `delay`  | `3`        | 仅 `/slow-before-headers` 使用 |

计数维度是：

method + normalizedPath + key

## Demo 场景映射

使用说明：

```plain
Retry Demo 是为了验证重试行为刻意设计的“可恢复故障”服务。
在相同 method + path + key 下，Demo 会让前 fail 次请求按指定方式失败，之后恢复为 HTTP 200。

例如 fail=1 时：
直连 Demo：第 1 次请求失败，第 2 次请求成功。
经过网关且重试生效：客户端只发起 1 次请求，但网关内部会请求上游 2 次，最终客户端收到第 2 次上游请求的成功响应。

因此测试时必须为每轮测试使用新的 key，避免历史计数影响结果。
```

| **接口**                           | **模拟真实场景**          | **主要验证点**                             |
| ---------------------------------- | ------------------------- | ------------------------------------------ |
| `/retry-demo/status-503`           | 上游应用正常返回 HTTP 503 | `http_503` / `retriable-status-codes`      |
| `/retry-demo/reset-before-headers` | 上游响应头前断开连接      | `error` 类重试、网关侧 503 / UC            |
| `/retry-demo/close-before-headers` | 同上                      | 同上                                       |
| `/retry-demo/invalid-header`       | 上游返回非法响应头        | `invalid_header` 转换和重试效果            |
| `/retry-demo/slow-before-headers`  | 上游迟迟不返回响应头      | `timeout` 与 `proxy-next-upstream-timeout` |
| `/retry-demo/close-mid-body`       | 上游返回部分响应体后断开  | 响应已开始后的失败表现，通常不应自动重试   |

## 配置验收

Ingress 侧应能看到类似配置：

```plain
higress.io/enable-proxy-next-upstream: "true"
higress.io/proxy-next-upstream: error,timeout,non_idempotent,invalid_header,http_502,http_503,http_504
higress.io/proxy-next-upstream-timeout: "<seconds>"
higress.io/proxy-next-upstream-tries: "<retries>"
```

控制台两处入口的等价性可重点对比：

| **配置项**   | **期望**                                                     |
| ------------ | ------------------------------------------------------------ |
| 重试开关     | 两边均能正确启用/关闭                                        |
| 重试条件     | `error`、`timeout`、`invalid_header`、`non_idempotent`、HTTP 状态码保持一致 |
| 重试次数     | 两边写入的 `proxy-next-upstream-tries` 一致                  |
| 重试超时时间 | 两边写入的 `proxy-next-upstream-timeout` 一致                |

行为验证时，优先使用“路由策略配置”入口将 `/retry-demo` 路由到 Retry Demo 服务。

Envoy 侧检查：

```plain
kubectl -n <gateway-namespace> exec deploy/higress-gateway -c higress-gateway -- \
  curl -s http://127.0.0.1:15000/config_dump | grep -n "retry-demo"
```

Envoy 配置说明：

```plain
这一部分仅供开发排查使用。
测试同学如果已经能从 Ingress annotation 和请求结果确认配置生效，可以不关注 Envoy config_dump。
```

当前 Higress 转换规则：

| **Ingress 条件**             | **Envoy 表现**                                         |
| ---------------------------- | ------------------------------------------------------ |
| `error`                      | 转换为 `retry_on: 5xx`                                 |
| `timeout`                    | 转换为 `retry_on: 5xx`，但必须配置实际超时时间才会触发 |
| `invalid_header`             | 转换为 `retry_on: 5xx`                                 |
| `non_idempotent`             | 保留为 `non_idempotent`                                |
| `http_502/http_503/http_504` | 转换为 `retriable-status-codes` + 对应状态码           |

注意：

```plain
error、timeout、invalid_header 不会在 Envoy 中保留为三个独立 token。
三者任意一个存在，Higress 都会生成 Envoy retry_on=5xx。
如果配置里已经有 error 或 timeout，再新增 invalid_header，Envoy retry_on 字符串通常不会变化。
```

示例 Envoy 结果：

```plain
retry_policy:
  retry_on: 5xx,non_idempotent,retriable-status-codes
  num_retries: 1
  per_try_timeout: 0s
  retriable_status_codes: [502, 503, 504]
```

`num_retries=1` 表示：

1 次原始请求 + 最多 1 次重试 = 最多 2 次上游请求

## 测试用例

### RT-01 上游 HTTP 503，GET 重试

请求：

```plain
KEY="rt01-$(date +%s)"
curl -i "http://${GW_HOST}/retry-demo/status-503?key=${KEY}&fail=1"
```

预期：

```plain
本次请求：HTTP 200
响应体：attempt=2, code=200
后端实际收到 2 次请求
```

原因说明：

```plain
Demo 在相同 method + path + key 下，第 1 次上游请求返回 503，第 2 次返回 200。
网关配置了 http_503，遇到第 1 次上游 503 后会重试。
因此客户端最终看到的是第 2 次上游请求的 200 响应，响应体中 attempt=2。
```

### RT-02 上游 HTTP 503，POST 重试

请求：

```plain
KEY="rt02-$(date +%s)"
curl -i -X POST "http://${GW_HOST}/retry-demo/status-503?key=${KEY}&fail=1" \
  -H "Content-Type: application/json" \
  -d '{"hello":"world"}'
```

预期：

```plain
已配置 non_idempotent：
本次请求：HTTP 200
响应体：method=POST, attempt=2, code=200

未配置 non_idempotent：
本次请求：HTTP 503
响应体：method=POST, attempt=1, code=503
```

原因说明：

```plain
POST 默认属于非幂等请求，网关通常不会自动重试，避免重复写入或重复提交。
配置 non_idempotent 后，表示允许非幂等方法也参与重试。
因此 POST 第 1 次上游返回 503 后，网关会再发起第 2 次上游请求并拿到 200。
```

### RT-03 上游响应头前断开连接

请求：

```plain
KEY="rt03-$(date +%s)"
curl -i "http://${GW_HOST}/retry-demo/reset-before-headers?key=${KEY}&fail=1"
```

预期：

```plain
已配置 error 类重试：
本次请求：HTTP 200
响应体：attempt=2, code=200

未配置对应重试：
本次请求：HTTP 503
网关日志：response_flags=UC
```

原因说明：

```plain
Demo 在第 1 次上游请求时会在响应头前关闭连接，网关拿不到完整 HTTP 响应。
未配置重试时，网关会把该上游异常转换成 503，并在日志中记录 UC。
配置 error 类重试后，网关会重新请求上游；Demo 第 2 次恢复 200，所以客户端最终收到 200，attempt=2。
```

### RT-04 上游非法响应头

请求：

```plain
KEY="rt04-$(date +%s)"
curl -i "http://${GW_HOST}/retry-demo/invalid-header?key=${KEY}&fail=1"
```

预期：

```plain
第 1 次上游请求返回非法响应头
网关内部重试 1 次
本次请求：HTTP 200
响应体：attempt=2, code=200
```

原因说明：

```plain
Demo 第 1 次返回格式不合法的响应头，第 2 次返回正常 200。
Higress 会把 invalid_header 转换为 Envoy 的 5xx 类 retry 条件。
因此 Envoy 解析第 1 次上游响应失败后会重试，客户端最终看到第 2 次上游请求的 200。
```

说明：

```plain
直连 demo 时，不同客户端对非法响应头的容忍度不同，可能不会报错。
判断是否重试以经过网关后的 attempt=2 和后端计数为准。
```

### RT-05 慢响应与 timeout

无实际超时时间时：

```plain
KEY="rt05-no-timeout-$(date +%s)"
curl -i "http://${GW_HOST}/retry-demo/slow-before-headers?key=${KEY}&fail=1&delay=2"
```

预期：

```plain
如果 proxy-next-upstream-timeout=0：
本次请求：HTTP 200
响应体：attempt=1
请求耗时约 2 秒
不会触发 timeout 重试
```

原因说明：

```plain
timeout 条件只表示“超时时可以重试”，但必须同时存在实际超时时间。
当 proxy-next-upstream-timeout=0 时，Envoy 下发 per_try_timeout=0s，表示不设置单次重试超时。
所以上游慢 2 秒并不会触发 timeout，网关会等待上游返回，响应体仍是 attempt=1。
```

配置实际超时时间后：

```plain
# 前提：proxy-next-upstream-timeout 小于 delay，例如 1 秒
KEY="rt05-timeout-$(date +%s)"
curl -i "http://${GW_HOST}/retry-demo/slow-before-headers?key=${KEY}&fail=1&delay=2"
```

预期：

```plain
第 1 次上游请求超过 per_try_timeout
网关内部重试 1 次
本次请求：HTTP 200
响应体：attempt=2
```

原因说明：

```plain
当 proxy-next-upstream-timeout 小于 delay 时，第 1 次上游请求会先达到单次重试超时。
网关命中 timeout 重试条件后发起第 2 次上游请求。
Demo 第 2 次不再 sleep，直接返回 200，所以客户端最终看到 attempt=2。
```

### RT-06 重试次数

请求：

```plain
KEY="rt06-$(date +%s)"
curl -i "http://${GW_HOST}/retry-demo/status-503?key=${KEY}&fail=2"
```

预期：

```plain
如果 num_retries=1：
本次请求：HTTP 503
响应体：attempt=2, code=503
网关日志：可能出现 response_flags=URX
```

原因说明：

```plain
fail=2 表示 Demo 的第 1 次和第 2 次上游请求都会返回 503，第 3 次才会恢复 200。
如果网关只允许重试 1 次，则最多只有 2 次上游请求。
两次上游请求都失败后，网关把最后一次 503 返回给客户端；Envoy 可能记录 URX 表示重试耗尽。
```

### RT-07 响应体中途断开

请求：

```plain
KEY="rt07-$(date +%s)"
curl -v "http://${GW_HOST}/retry-demo/close-mid-body?key=${KEY}&fail=1"
```

预期：

```plain
客户端可能已收到 200 响应头和部分 body，随后连接异常结束。
该场景响应已经开始发送给客户端，通常不应作为安全自动重试场景。
```

原因说明：

```plain
一旦响应头或部分响应体已经发给客户端，网关再自动重试可能导致客户端看到混合响应或重复副作用。
因此这类场景主要用于观察失败表现和日志，不建议作为常规自动重试成功用例。
```

## 判定方式

优先看响应体中的 `attempt`：

```plain
attempt=1：没有发生网关内部重试
attempt=2：发生了 1 次网关内部重试
attempt=3：发生了 2 次网关内部重试
```

辅助看网关日志：

kubectl -n <gateway-namespace> logs deploy/higress-gateway -c higress-gateway --since=5m | grep "<test-key>"

常见字段：

| **字段**                | **说明**                 |
| ----------------------- | ------------------------ |
| `response_code`         | 最终返回给客户端的状态码 |
| `response_flags=UC`     | 上游响应前断连           |
| `response_flags=URX`    | 重试耗尽                 |
| `response_code_details` | Envoy 生成状态码的原因   |
| `upstream_cluster`      | 目标上游                 |
| `upstream_host`         | 实际上游地址             |

注意：网关 access log 通常只记录最终结果，失败的前置尝试不一定单独出现。因此 `attempt` 是本 demo 中最直接的判定信号。

## 排查命令

```plain
kubectl -n <test-namespace> get deploy,svc,pod -l app=retry-demo -o wide
kubectl -n <test-namespace> logs deploy/retry-demo --tail=100
kubectl -n <test-namespace> exec deploy/retry-demo -- sh -c 'ls /tmp/retry-demo-* | tail'
```

## 附录：Retry Demo YAML

```plain
apiVersion: v1
kind: ConfigMap
metadata:
  name: retry-demo-script
  labels:
    app: retry-demo
data:
  handler.sh: |
    #!/bin/sh

    PREFIX="/retry-demo"

    log() {
      echo "$*" >/proc/1/fd/2
    }

    reason_for() {
      case "$1" in
        200) echo "OK" ;;
        404) echo "Not Found" ;;
        503) echo "Service Unavailable" ;;
        *) echo "Status" ;;
      esac
    }

    send_json() {
      code="$1"
      body="$2"
      reason="$(reason_for "$code")"
      len=${#body}
      printf 'HTTP/1.1 %s %s\r\nContent-Type: application/json\r\nContent-Length: %s\r\nConnection: close\r\n\r\n' "$code" "$reason" "$len"
      if [ "$method" != "HEAD" ]; then
        printf '%s' "$body"
      fi
    }

    param() {
      name="$1"
      echo "&$query" | sed -n "s/.*[&]$name=\([^&]*\).*/\1/p" | head -n 1
    }

    content_length=0
    read -r request_line || exit 0
    while read -r header_line; do
      clean_header="$(printf '%s' "$header_line" | tr -d '\r')"
      [ -z "$clean_header" ] && break
      header_name="$(printf '%s' "$clean_header" | awk -F: '{print tolower($1)}')"
      if [ "$header_name" = "content-length" ]; then
        content_length="$(printf '%s' "$clean_header" | sed 's/^[^:]*:[[:space:]]*//')"
      fi
    done

    case "$content_length" in
      ''|*[!0-9]*) content_length=0 ;;
    esac
    if [ "$content_length" -gt 0 ]; then
      dd bs=1 count="$content_length" of=/dev/null 2>/dev/null
    fi

    method="$(echo "$request_line" | awk '{print $1}')"
    uri="$(echo "$request_line" | awk '{print $2}')"
    raw_path="${uri%%\?*}"
    path="$raw_path"
    query=""
    if [ "$uri" != "$raw_path" ]; then
      query="${uri#*\?}"
    fi

    case "$path" in
      "$PREFIX"/*) path="${path#$PREFIX}" ;;
      "$PREFIX") path="/" ;;
    esac

    if [ "$path" = "/health" ]; then
      send_json 200 "{\"status\":\"ok\",\"prefix\":\"$PREFIX\",\"method\":\"$method\",\"contentLength\":$content_length}"
      exit 0
    fi

    key="$(param key)"
    fail="$(param fail)"
    delay="$(param delay)"
    [ -z "$key" ] && key="default"
    case "$fail" in
      ''|*[!0-9]*) fail=1 ;;
    esac
    case "$delay" in
      ''|*[!0-9]*) delay=3 ;;
    esac

    safe_method="$(echo "$method" | tr -c 'A-Za-z0-9_.-' '_')"
    safe_path="$(echo "$path" | tr -c 'A-Za-z0-9_.-' '_')"
    safe_key="$(echo "$key" | tr -c 'A-Za-z0-9_.-' '_')"
    count_file="/tmp/retry-demo-${safe_method}-${safe_path}-${safe_key}.count"
    if [ -f "$count_file" ]; then
      attempt="$(cat "$count_file" 2>/dev/null)"
    else
      attempt=0
    fi
    case "$attempt" in
      ''|*[!0-9]*) attempt=0 ;;
    esac
    attempt=$((attempt + 1))
    echo "$attempt" >"$count_file"

    base_fields="\"method\":\"$method\",\"path\":\"$raw_path\",\"normalizedPath\":\"$path\",\"prefix\":\"$PREFIX\",\"key\":\"$key\",\"attempt\":$attempt,\"fail\":$fail,\"contentLength\":$content_length"

    if [ "$path" = "/status-503" ]; then
      if [ "$attempt" -le "$fail" ]; then
        code=503
      else
        code=200
      fi
      body="{$base_fields,\"code\":$code,\"mode\":\"normal-http-503\"}"
      send_json "$code" "$body"
      exit 0
    fi

    if [ "$path" = "/invalid-header" ]; then
      if [ "$attempt" -le "$fail" ]; then
        log "$method $raw_path key=$key attempt=$attempt fail=$fail send invalid response header"
        printf 'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nInvalid Header Without Colon\r\nContent-Length: 48\r\nConnection: close\r\n\r\n'
        if [ "$method" != "HEAD" ]; then
          printf '{"mode":"invalid-header","attempt":%s}' "$attempt"
        fi
        exit 0
      fi
      body="{$base_fields,\"code\":200,\"mode\":\"recovered-after-invalid-header\"}"
      send_json 200 "$body"
      exit 0
    fi

    if [ "$path" = "/slow-before-headers" ]; then
      if [ "$attempt" -le "$fail" ]; then
        log "$method $raw_path key=$key attempt=$attempt fail=$fail sleep $delay seconds before headers"
        sleep "$delay"
      fi
      body="{$base_fields,\"code\":200,\"mode\":\"slow-before-headers\",\"delay\":$delay}"
      send_json 200 "$body"
      exit 0
    fi

    if [ "$path" = "/reset-before-headers" ] || [ "$path" = "/close-before-headers" ]; then
      if [ "$attempt" -le "$fail" ]; then
        log "$method $raw_path key=$key attempt=$attempt fail=$fail close connection before headers"
        exit 0
      fi
      body="{$base_fields,\"code\":200,\"mode\":\"recovered-after-upstream-close-before-headers\"}"
      send_json 200 "$body"
      exit 0
    fi

    if [ "$path" = "/close-mid-body" ]; then
      if [ "$attempt" -le "$fail" ]; then
        log "$method $raw_path key=$key attempt=$attempt fail=$fail close connection mid body"
        printf 'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 1048576\r\nConnection: close\r\n\r\n'
        if [ "$method" != "HEAD" ]; then
          printf '{\"method\":\"%s\",\"path\":\"%s\",\"normalizedPath\":\"/close-mid-body\",\"partial\":true' "$method" "$raw_path"
        fi
        exit 0
      fi
      body="{$base_fields,\"code\":200,\"mode\":\"recovered-after-upstream-close-mid-body\"}"
      send_json 200 "$body"
      exit 0
    fi

    send_json 404 "{\"error\":\"not found\",\"method\":\"$method\",\"path\":\"$raw_path\",\"normalizedPath\":\"$path\",\"prefix\":\"$PREFIX\",\"contentLength\":$content_length}"
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: retry-demo
  labels:
    app: retry-demo
spec:
  replicas: 1
  selector:
    matchLabels:
      app: retry-demo
  template:
    metadata:
      labels:
        app: retry-demo
    spec:
      containers:
        - name: retry-demo
          image: registry.cn-shanghai.aliyuncs.com/daofeng/nginx:alpine
          imagePullPolicy: IfNotPresent
          command:
            - sh
            - -c
            - exec nc -lk -p 8080 -e /app/handler.sh
          ports:
            - name: http
              containerPort: 8080
          readinessProbe:
            httpGet:
              path: /retry-demo/health
              port: http
            initialDelaySeconds: 2
            periodSeconds: 3
          livenessProbe:
            httpGet:
              path: /retry-demo/health
              port: http
            initialDelaySeconds: 10
            periodSeconds: 10
          resources:
            requests:
              cpu: 20m
              memory: 32Mi
            limits:
              cpu: 200m
              memory: 128Mi
          volumeMounts:
            - name: script
              mountPath: /app
      volumes:
        - name: script
          configMap:
            name: retry-demo-script
            defaultMode: 0755
---
apiVersion: v1
kind: Service
metadata:
  name: retry-demo
  labels:
    app: retry-demo
spec:
  type: ClusterIP
  selector:
    app: retry-demo
  ports:
    - name: http
      port: 80
      targetPort: http
```
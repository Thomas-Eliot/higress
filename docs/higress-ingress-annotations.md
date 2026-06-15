# Higress Ingress Annotations 参考手册

Higress 支持两种注解前缀：

- `nginx.ingress.kubernetes.io/` — 兼容 NGINX Ingress Controller
- `higress.io/` — Higress 专有扩展

---

## 1. CORS 跨域

| 注解 | 作用 | 默认值 |
|------|------|--------|
| `nginx.ingress.kubernetes.io/enable-cors` | 开启 CORS | - |
| `nginx.ingress.kubernetes.io/cors-allow-origin` | 允许的来源 | `*` |
| `nginx.ingress.kubernetes.io/cors-allow-methods` | 允许的 HTTP 方法 | `GET, PUT, POST, DELETE, PATCH, OPTIONS` |
| `nginx.ingress.kubernetes.io/cors-allow-headers` | 允许的请求头 | `DNT,X-CustomHeader,Keep-Alive,User-Agent,...` |
| `nginx.ingress.kubernetes.io/cors-expose-headers` | 暴露给浏览器的响应头 | - |
| `nginx.ingress.kubernetes.io/cors-allow-credentials` | 是否允许携带凭证 | - |
| `nginx.ingress.kubernetes.io/cors-max-age` | 预检请求缓存时间 | - |

## 2. 路径重写

| 注解 | 作用 | 默认值 |
|------|------|--------|
| `nginx.ingress.kubernetes.io/rewrite-target` | 重写目标路径（支持正则捕获组 `$1` 等） | - |
| `nginx.ingress.kubernetes.io/use-regex` | 启用前缀正则匹配 | `false` |
| `nginx.ingress.kubernetes.io/upstream-vhost` | 覆盖转发到上游的 Host 头 | - |
| `higress.io/rewrite-path` | 直接重写路径 | - |
| `higress.io/full-path-regex` | 全路径正则匹配模式 | `false` |

## 3. 重定向

| 注解 | 作用 | 默认值 |
|------|------|--------|
| `nginx.ingress.kubernetes.io/app-root` | 访问 `/` 时重定向到指定路径 | - |
| `nginx.ingress.kubernetes.io/temporal-redirect` | 临时重定向目标 URL | - |
| `nginx.ingress.kubernetes.io/permanent-redirect` | 永久重定向目标 URL | - |
| `nginx.ingress.kubernetes.io/permanent-redirect-code` | 永久重定向状态码 | `301` |
| `nginx.ingress.kubernetes.io/ssl-redirect` | 强制 HTTPS 重定向 | - |
| `nginx.ingress.kubernetes.io/force-ssl-redirect` | 强制 SSL 重定向 | - |

## 4. 上游 TLS（Backend）

| 注解 | 作用 | 默认值 |
|------|------|--------|
| `nginx.ingress.kubernetes.io/backend-protocol` | 后端协议：`HTTP`/`HTTPS`/`GRPC`/`GRPCS` | `HTTP` |
| `nginx.ingress.kubernetes.io/proxy-ssl-secret` | 上游 mTLS 客户端证书 Secret | - |
| `nginx.ingress.kubernetes.io/proxy-ssl-verify` | 是否验证上游服务端证书 | - |
| `nginx.ingress.kubernetes.io/proxy-ssl-name` | 上游 TLS SNI 名称 | - |
| `nginx.ingress.kubernetes.io/proxy-ssl-server-name` | 是否向上游发送 SNI | - |

## 5. 下游 TLS（Client）

| 注解 | 作用 | 默认值 |
|------|------|--------|
| `nginx.ingress.kubernetes.io/auth-tls-secret` | 客户端 CA 证书 Secret（用于 mTLS） | - |
| `nginx.ingress.kubernetes.io/ssl-cipher` | SSL 加密套件列表 | - |
| `nginx.ingress.kubernetes.io/tls-min-protocol-version` | TLS 最低协议版本 | - |
| `nginx.ingress.kubernetes.io/tls-max-protocol-version` | TLS 最高协议版本 | - |

## 6. 灰度发布（Canary）

| 注解 | 作用 | 默认值 |
|------|------|--------|
| `nginx.ingress.kubernetes.io/canary` | 启用灰度发布 | `false` |
| `nginx.ingress.kubernetes.io/canary-by-header` | 基于请求头名称进行灰度 | - |
| `nginx.ingress.kubernetes.io/canary-by-header-value` | 匹配的请求头精确值 | - |
| `nginx.ingress.kubernetes.io/canary-by-header-pattern` | 匹配的请求头正则表达式 | - |
| `nginx.ingress.kubernetes.io/canary-by-cookie` | 基于 Cookie 名称进行灰度 | - |
| `nginx.ingress.kubernetes.io/canary-weight` | 灰度流量权重 | - |
| `nginx.ingress.kubernetes.io/canary-weight-total` | 权重总数 | `100` |

## 7. 超时

| 注解 | 作用 | 默认值 |
|------|------|--------|
| `higress.io/timeout` | 路由超时时间（单位：秒） | - |

## 8. 重试

| 注解 | 作用 | 默认值 |
|------|------|--------|
| `nginx.ingress.kubernetes.io/proxy-next-upstream-tries` | 最大重试次数 | `3` |
| `nginx.ingress.kubernetes.io/proxy-next-upstream-timeout` | 单次重试超时时间 | - |
| `nginx.ingress.kubernetes.io/proxy-next-upstream` | 触发重试的条件 | `5xx` |
| `nginx.ingress.kubernetes.io/retriable-status-codes` | 可重试的 HTTP 状态码列表 | - |

## 9. 负载均衡 & 会话保持

| 注解 | 作用 | 默认值 |
|------|------|--------|
| `nginx.ingress.kubernetes.io/load-balance` | 负载均衡算法 | - |
| `nginx.ingress.kubernetes.io/upstream-hash-by` | 一致性哈希 key（支持 `$http_`、`$arg_` 变量） | - |
| `nginx.ingress.kubernetes.io/affinity` | 会话亲和性类型（cookie） | - |
| `nginx.ingress.kubernetes.io/affinity-mode` | 亲和模式（balanced） | - |
| `nginx.ingress.kubernetes.io/affinity-canary-behavior` | 灰度场景下的亲和行为（legacy） | - |
| `nginx.ingress.kubernetes.io/session-cookie-name` | 会话 Cookie 名称 | `INGRESSCOOKIE` |
| `nginx.ingress.kubernetes.io/session-cookie-path` | 会话 Cookie 路径 | `/` |
| `nginx.ingress.kubernetes.io/session-cookie-max-age` | 会话 Cookie 最大存活时间 | - |
| `nginx.ingress.kubernetes.io/session-cookie-expires` | 会话 Cookie 过期时间 | - |
| `higress.io/mcp-sse-stateful-param-name` | MCP SSE 有状态会话参数名 | `sessionId` |

## 10. 本地限流

| 注解 | 作用 | 默认值 |
|------|------|--------|
| `higress.io/route-limit-rpm` | 每分钟请求数限制 | - |
| `higress.io/route-limit-rps` | 每秒请求数限制 | - |
| `higress.io/route-limit-burst-multiplier` | 突发流量倍数（令牌桶 maxTokens = limit × multiplier） | `5` |

> 注：`route-limit-rpm` 和 `route-limit-rps` 二选一，优先使用 `rpm`。

## 11. IP 访问控制

| 注解 | 作用 | 默认值 |
|------|------|--------|
| `nginx.ingress.kubernetes.io/whitelist-source-range` | IP 白名单（逗号分隔的 CIDR 列表） | - |

## 12. 流量镜像

| 注解 | 作用 | 默认值 |
|------|------|--------|
| `nginx.ingress.kubernetes.io/mirror-target-service` | 镜像目标服务名 | - |
| `nginx.ingress.kubernetes.io/mirror-percentage` | 镜像流量百分比 | - |
| `nginx.ingress.kubernetes.io/mirror-target-fqdn` | 镜像目标 FQDN 地址 | - |
| `nginx.ingress.kubernetes.io/mirror-target-fqdn-port` | 镜像目标端口 | - |

## 13. 高级路由匹配

| 注解 | 作用 | 默认值 |
|------|------|--------|
| `higress.io/match-method` | 匹配 HTTP 方法（如 `GET POST`） | - |
| `higress.io/match-query-[exact\|regex\|prefix]-<name>` | 匹配 URL 查询参数 | - |
| `higress.io/match-header-[exact\|regex\|prefix]-<name>` | 匹配请求头 | - |
| `higress.io/match-pseudo-header-[exact\|regex\|prefix]-<name>` | 匹配伪头（如 `:authority`、`:method`） | - |

> 匹配模式支持三种：`exact`（精确）、`regex`（正则）、`prefix`（前缀）。

## 14. 请求/响应头控制

| 注解 | 作用 | 默认值 |
|------|------|--------|
| `higress.io/request-header-control-add` | 添加请求头（不覆盖已有值） | - |
| `higress.io/request-header-control-update` | 更新请求头（覆盖已有值） | - |
| `higress.io/request-header-control-remove` | 删除指定请求头 | - |
| `higress.io/response-header-control-add` | 添加响应头（不覆盖已有值） | - |
| `higress.io/response-header-control-update` | 更新响应头（覆盖已有值） | - |
| `higress.io/response-header-control-remove` | 删除指定响应头 | - |

## 15. 路径大小写

| 注解 | 作用 | 默认值 |
|------|------|--------|
| `nginx.ingress.kubernetes.io/ignore-path-case` | 路径匹配时忽略大小写 | `false` |

## 16. 默认后端 & 自定义错误页

| 注解 | 作用 | 默认值 |
|------|------|--------|
| `nginx.ingress.kubernetes.io/default-backend` | 默认后端服务（无匹配路由时使用） | - |
| `nginx.ingress.kubernetes.io/custom-http-errors` | 自定义错误码列表（触发 fallback 到默认后端） | - |

## 17. 自定义目标路由（Destination）

| 注解 | 作用 | 默认值 |
|------|------|--------|
| `higress.io/destination` | 自定义路由目标，支持权重、端口、subset | - |

格式：每行一个目标，`[weight%] <host>[:port] [subset]`

示例：
```
70% my-svc.DEFAULT-GROUP.xxxx.nacos:8080 v1
30% my-svc.DEFAULT-GROUP.xxxx.nacos:8080 v2
```

## 18. HTTP 转 RPC

| 注解 | 作用 | 默认值 |
|------|------|--------|
| `higress.io/rpc-destination-name` | HTTP 转 RPC 的目标服务名 | - |

## 19. MCP Server

| 注解 | 作用 | 默认值 |
|------|------|--------|
| `nginx.ingress.kubernetes.io/mcp-server` | 启用 MCP Server 功能 | - |
| `nginx.ingress.kubernetes.io/mcp-server-match-rule-domains` | MCP 匹配规则域名 | - |
| `nginx.ingress.kubernetes.io/mcp-server-match-rule-type` | MCP 匹配规则类型 | - |
| `nginx.ingress.kubernetes.io/mcp-server-match-rule-value` | MCP 匹配规则值 | - |
| `nginx.ingress.kubernetes.io/mcp-server-upstream-type` | MCP 上游服务类型 | - |
| `nginx.ingress.kubernetes.io/mcp-server-enable-path-rewrite` | MCP 是否启用路径重写 | - |
| `nginx.ingress.kubernetes.io/mcp-server-path-rewrite-prefix` | MCP 路径重写前缀 | - |

## 20. 认证（⚠️ 已废弃，v2.0.0 后不推荐使用）

| 注解 | 作用 | 默认值 |
|------|------|--------|
| `nginx.ingress.kubernetes.io/auth-type` | 认证类型 | `basic` |
| `nginx.ingress.kubernetes.io/auth-realm` | 认证 Realm | - |
| `nginx.ingress.kubernetes.io/auth-secret` | 认证凭证 Secret 名称 | - |
| `nginx.ingress.kubernetes.io/auth-secret-type` | Secret 类型（`auth-file`） | `auth-file` |

---

## 使用示例

### 灰度发布 + 权重

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: my-canary
  annotations:
    nginx.ingress.kubernetes.io/canary: "true"
    nginx.ingress.kubernetes.io/canary-weight: "20"
spec:
  rules:
    - host: example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: my-svc-canary
                port:
                  number: 80
```

### 限流 + 超时 + 重写

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: my-route
  annotations:
    higress.io/timeout: "30"
    higress.io/route-limit-rps: "100"
    higress.io/route-limit-burst-multiplier: "3"
    nginx.ingress.kubernetes.io/rewrite-target: /$1
    nginx.ingress.kubernetes.io/use-regex: "true"
spec:
  rules:
    - host: example.com
      http:
        paths:
          - path: /api/(.*)
            pathType: ImplementationSpecific
            backend:
              service:
                name: my-backend
                port:
                  number: 8080
```

### Header 控制

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: my-route
  annotations:
    higress.io/request-header-control-add: |
      X-Request-Id 12345
    higress.io/response-header-control-update: |
      Cache-Control no-cache
    higress.io/response-header-control-remove: "X-Powered-By"
```

---

> 本文档基于源码 `pkg/ingress/kube/annotations/` 目录自动整理，共 20 个功能类别，约 70+ 个注解。

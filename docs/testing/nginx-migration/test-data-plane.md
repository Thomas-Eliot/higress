# 数据面测试用例 — 迁移后功能一致性验证

## 测试范围

验证迁移后的 Ingress 通过 Higress 网关转发流量时，各注解对应的功能是否正常生效。需要实际发送 HTTP 请求，对比 Nginx 和 Higress 的行为差异。

## 测试前提

- 控制面测试（test-control-plane.md）已通过
- 迁移后的 Ingress 已在 Higress 控制台路由列表中可见
- 后端服务可正常访问
- DNS 或 /etc/hosts 已配置指向 Higress 网关 SLB

## 验证方法

通过 curl 分别请求 Nginx SLB 和 Higress SLB，对比响应行为。

```bash
# Nginx 侧
curl -H "Host: <domain>" http://<nginx-slb>/<path>

# Higress 侧
curl -H "Host: <domain>" http://<higress-slb>/<path>
```

---

## 完全兼容注解 — 数据面验证

这些注解在 Higress 中应与 Nginx 行为一致，是数据面验证的重点。

### TC-D1: rewrite-target 路径重写

**Ingress 配置**：
```yaml
nginx.ingress.kubernetes.io/rewrite-target: /$2
nginx.ingress.kubernetes.io/use-regex: "true"
# path: /api(/|$)(.*)
```

**验证**：
```bash
curl -H "Host: test.com" http://<higress-slb>/api/users
# 预期：请求被重写为 /users 转发到后端
# 对比 Nginx 侧相同请求的响应
```

---

### TC-D2: ssl-redirect HTTPS 重定向

**Ingress 配置**：
```yaml
nginx.ingress.kubernetes.io/ssl-redirect: "true"
```

**验证**：
```bash
curl -v -H "Host: test.com" http://<higress-slb>/path
# 预期：返回 308 重定向到 https://test.com/path
```

---

### TC-D3: CORS 跨域

**Ingress 配置**：
```yaml
nginx.ingress.kubernetes.io/enable-cors: "true"
nginx.ingress.kubernetes.io/cors-allow-origin: "https://frontend.com"
nginx.ingress.kubernetes.io/cors-allow-methods: "GET,POST"
```

**验证**：
```bash
curl -v -H "Host: test.com" -H "Origin: https://frontend.com" -X OPTIONS http://<higress-slb>/api
# 预期：
#   Access-Control-Allow-Origin: https://frontend.com
#   Access-Control-Allow-Methods: GET,POST
```

---

### TC-D4: canary 灰度发布（按权重）

**Ingress 配置**：主 Ingress + canary Ingress（canary-weight: 20）

**验证**：
```bash
# 发送 100 次请求，统计路由到 canary 后端的比例
for i in $(seq 1 100); do
  curl -s -H "Host: test.com" http://<higress-slb>/path | grep -c "canary-backend"
done
# 预期：约 20% 请求路由到 canary 后端
```

---

### TC-D5: canary 灰度发布（按 Header）

**Ingress 配置**：
```yaml
nginx.ingress.kubernetes.io/canary: "true"
nginx.ingress.kubernetes.io/canary-by-header: "X-Canary"
nginx.ingress.kubernetes.io/canary-by-header-value: "always"
```

**验证**：
```bash
# 带 header 请求
curl -H "Host: test.com" -H "X-Canary: always" http://<higress-slb>/path
# 预期：路由到 canary 后端

# 不带 header 请求
curl -H "Host: test.com" http://<higress-slb>/path
# 预期：路由到主后端
```

---

### TC-D6: whitelist-source-range IP 白名单

**Ingress 配置**：
```yaml
nginx.ingress.kubernetes.io/whitelist-source-range: "10.0.0.0/8"
```

**验证**：
```bash
# 从白名单外 IP 请求
curl -H "Host: test.com" http://<higress-slb>/path
# 预期：返回 403

# 从白名单内 IP 请求
# 预期：正常返回 200
```

---

### TC-D7: proxy-next-upstream 重试

**Ingress 配置**：
```yaml
nginx.ingress.kubernetes.io/proxy-next-upstream: "error timeout"
nginx.ingress.kubernetes.io/proxy-next-upstream-tries: "3"
```

**验证**：后端服务模拟间歇性 502，观察 Higress 是否自动重试到健康实例。

---

### TC-D8: session affinity 会话保持

**Ingress 配置**：
```yaml
nginx.ingress.kubernetes.io/affinity: "cookie"
nginx.ingress.kubernetes.io/session-cookie-name: "SERVERID"
```

**验证**：
```bash
# 首次请求
curl -v -H "Host: test.com" http://<higress-slb>/path
# 预期：响应头包含 Set-Cookie: SERVERID=xxx

# 携带 cookie 再次请求
curl -H "Host: test.com" -b "SERVERID=xxx" http://<higress-slb>/path
# 预期：路由到同一后端实例
```

---

## 部分兼容注解 — 数据面验证

这些注解在 Higress 中部分功能可用，需验证支持的部分是否正常。

### TC-D9: backend-protocol 后端协议

**支持的协议**：HTTP, HTTP2, HTTPS, GRPC, GRPCS

```yaml
nginx.ingress.kubernetes.io/backend-protocol: "GRPC"
```

**验证**：
```bash
grpcurl -plaintext -H "Host: grpc.test.com" <higress-slb>:80 grpc.health.v1.Health/Check
# 预期：gRPC 请求正常转发
```

**不支持**：AJP, FCGI — 如果原 Ingress 使用这两种协议，迁移后无法工作。

---

### TC-D10: load-balance 负载均衡算法

**支持**：round_robin, least_conn (least_request), random, 一致性哈希
**不支持**：ewma

```yaml
nginx.ingress.kubernetes.io/load-balance: "round_robin"
```

**验证**：多次请求观察后端实例分布是否符合 round_robin 策略。

---

### TC-D11: upstream-hash-by 一致性哈希

**支持**：单变量（`$request_uri`, `$host`, `$remote_addr`, `$http_*`, `$arg_*`）
**不支持**：多变量组合

```yaml
nginx.ingress.kubernetes.io/upstream-hash-by: "$request_uri"
```

**验证**：相同 URI 的请求应始终路由到同一后端。

---

## 可等价替换注解 — 数据面验证

这些注解迁移时保留了原值，但在 Higress 中不一定直接生效，需要额外配置插件或 EnvoyFilter。

### TC-D12: auth-url 外部认证（需配置 ext-auth 插件）

**Ingress 配置**：
```yaml
nginx.ingress.kubernetes.io/auth-url: "https://auth.example.com/verify"
```

**注意**：此注解在 Higress 中不会自动生效。需要额外部署 ext-auth WASM 插件并配置 WasmPlugin CRD。

**验证（配置插件后）**：
```bash
# 未认证请求
curl -v -H "Host: test.com" http://<higress-slb>/protected
# 预期：返回 401 或 403

# 已认证请求
curl -H "Host: test.com" -H "Authorization: Bearer <token>" http://<higress-slb>/protected
# 预期：返回 200
```

---

### TC-D13: limit-rps 限流（需配置限流插件）

**Ingress 配置**：
```yaml
nginx.ingress.kubernetes.io/limit-rps: "10"
```

**注意**：需要部署 key-rate-limit 插件。

**验证（配置插件后）**：快速发送超过 10 rps 的请求，预期超限请求返回 429。

---

### TC-D14: enable-modsecurity WAF（需配置 WAF 插件）

**Ingress 配置**：
```yaml
nginx.ingress.kubernetes.io/enable-modsecurity: "true"
nginx.ingress.kubernetes.io/enable-owasp-core-rules: "true"
```

**注意**：需要部署 Higress waf WASM 插件。

**验证（配置插件后）**：
```bash
curl -H "Host: test.com" "http://<higress-slb>/path?id=1%20OR%201=1"
# 预期：SQL 注入请求被 WAF 拦截，返回 403
```

---

### TC-D15: proxy-read-timeout 超时（需配置 EnvoyFilter）

**Ingress 配置**：
```yaml
nginx.ingress.kubernetes.io/proxy-read-timeout: "120"
```

**注意**：路由级超时需通过 EnvoyFilter 配置，全局超时通过 higress-config 配置。

**验证（配置后）**：后端延迟 60s 响应，预期 Higress 不超时（120s > 60s）。

---

### TC-D16: mirror-target 流量镜像（需使用 Higress 注解）

**Nginx 注解**：
```yaml
nginx.ingress.kubernetes.io/mirror-target: "https://mirror.example.com"
```

**Higress 等价配置**：需改用 `higress.io/mirror-target-service` 或 `higress.io/mirror-target-fqdn`。

**验证**：请求主路由后，检查镜像服务是否收到相同请求。

---

## 路由优先级差异验证

### TC-D17: regex vs prefix 路由优先级

**背景**：NGINX 中 regex > prefix，Higress 中 prefix > regex。

**Ingress 配置**：同一 host 下存在：
- Ingress A: path `/api/v1/users` (prefix)
- Ingress B: path `/api/v1/.*` (regex, use-regex: true)

**验证**：
```bash
curl -H "Host: test.com" http://<higress-slb>/api/v1/users
# NGINX 预期：匹配 regex Ingress B
# Higress 预期：匹配 prefix Ingress A（优先级更高）
```

**这是已知的行为差异**，兼容性评估报告中会标记为路由优先级冲突。

---

## 测试结果记录模板

| 用例 | Nginx 行为 | Higress 行为 | 是否一致 | 备注 |
|------|-----------|-------------|---------|------|
| TC-D1 rewrite-target | | | | |
| TC-D2 ssl-redirect | | | | |
| TC-D3 CORS | | | | |
| TC-D4 canary 权重 | | | | |
| TC-D5 canary Header | | | | |
| TC-D6 IP 白名单 | | | | |
| TC-D7 重试 | | | | |
| TC-D8 会话保持 | | | | |
| TC-D9 backend-protocol | | | | |
| TC-D10 负载均衡 | | | | |
| TC-D11 一致性哈希 | | | | |
| TC-D12 外部认证 | | | | 需 ext-auth 插件 |
| TC-D13 限流 | | | | 需限流插件 |
| TC-D14 WAF | | | | 需 WAF 插件 |
| TC-D15 超时 | | | | 需 EnvoyFilter |
| TC-D16 流量镜像 | | | | 需 Higress 注解 |
| TC-D17 路由优先级 | | | 已知差异 | |

# 控制面测试用例 — Annotation 迁移正确性验证

## 自动化执行

```bash
# 迁移完成后执行
python3 test_control_plane.py -n <namespace> [--ingress-class <target-class>]

# 示例
python3 test_control_plane.py -n ls-test --ingress-class ls-test
```

脚本会自动检查每个 `-higress` Ingress 的 annotation 保留/移除、label、ingressClassName 是否正确。

## 测试范围

验证迁移执行器在复制 Ingress 时，annotation 的保留/移除逻辑是否正确。只关注 K8s 资源层面的正确性，不涉及流量转发行为。

## 迁移规则速览

| 兼容性分类 | 迁移行为 | 数量 |
|-----------|---------|------|
| ✅ 完全兼容 | 保留 | 39 |
| 🔵 可等价替换 | 保留 | 37 |
| ⚠️ 部分兼容 | 保留 | 7 |
| ❌ 不兼容 | 移除 | 35 |
| 🔴 无需迁移 | 移除 | 12 |
| ❓ 未知注解（非 nginx 前缀） | 保留 | N/A |
| `kubernetes.io/ingress.class` | 移除 | 特殊 |
| `kubectl.kubernetes.io/last-applied-configuration` | 移除 | 特殊 |

## 验证方法

所有用例统一通过 `kubectl get ingress <name>-higress -n <ns> -o yaml` 验证 annotation 是否存在及值是否正确。

---

## 测试用例

### TC-C1: 完全兼容注解保留

**输入 Ingress annotations**：
```yaml
nginx.ingress.kubernetes.io/rewrite-target: /$1
nginx.ingress.kubernetes.io/use-regex: "true"
nginx.ingress.kubernetes.io/ssl-redirect: "false"
nginx.ingress.kubernetes.io/enable-cors: "true"
nginx.ingress.kubernetes.io/cors-allow-origin: "*"
nginx.ingress.kubernetes.io/canary: "true"
nginx.ingress.kubernetes.io/canary-weight: "20"
nginx.ingress.kubernetes.io/whitelist-source-range: "10.0.0.0/8"
nginx.ingress.kubernetes.io/proxy-next-upstream-tries: "3"
```

**预期**：全部保留，值不变。

---

### TC-C2: 不兼容注解移除

**输入 Ingress annotations**：
```yaml
nginx.ingress.kubernetes.io/configuration-snippet: |
  more_set_headers "X-Custom: value";
nginx.ingress.kubernetes.io/server-snippet: |
  location /health { return 200; }
nginx.ingress.kubernetes.io/auth-signin: "https://login.example.com"
nginx.ingress.kubernetes.io/ssl-passthrough: "true"
nginx.ingress.kubernetes.io/session-cookie-samesite: "Strict"
nginx.ingress.kubernetes.io/enable-opentelemetry: "true"
```

**预期**：全部不存在于迁移后的 Ingress 中。

---

### TC-C3: 无需迁移注解移除

**输入 Ingress annotations**：
```yaml
nginx.ingress.kubernetes.io/proxy-body-size: "100m"
nginx.ingress.kubernetes.io/proxy-buffering: "off"
nginx.ingress.kubernetes.io/proxy-buffer-size: "8k"
nginx.ingress.kubernetes.io/proxy-request-buffering: "off"
nginx.ingress.kubernetes.io/service-upstream: "true"
nginx.ingress.kubernetes.io/mirror-request-body: "on"
```

**预期**：全部不存在于迁移后的 Ingress 中。

---

### TC-C4: 可等价替换注解保留

**输入 Ingress annotations**：
```yaml
nginx.ingress.kubernetes.io/auth-url: "https://auth.example.com/verify"
nginx.ingress.kubernetes.io/limit-rps: "100"
nginx.ingress.kubernetes.io/proxy-read-timeout: "60"
nginx.ingress.kubernetes.io/ssl-ciphers: "ECDHE-RSA-AES128-GCM-SHA256"
nginx.ingress.kubernetes.io/enable-modsecurity: "true"
nginx.ingress.kubernetes.io/proxy-set-headers: "my-headers-configmap"
```

**预期**：全部保留，值不变。

---

### TC-C5: 部分兼容注解保留

**输入 Ingress annotations**：
```yaml
nginx.ingress.kubernetes.io/backend-protocol: "HTTPS"
nginx.ingress.kubernetes.io/load-balance: "round_robin"
nginx.ingress.kubernetes.io/upstream-hash-by: "$request_uri"
nginx.ingress.kubernetes.io/affinity-mode: "balanced"
nginx.ingress.kubernetes.io/server-alias: "*.example.com"
nginx.ingress.kubernetes.io/auth-tls-secret: "default/my-ca-secret"
```

**预期**：全部保留，值不变。

---

### TC-C6: 非 nginx 前缀注解保留

**输入 Ingress annotations**：
```yaml
my-company.io/team: "platform"
app.kubernetes.io/managed-by: "helm"
cert-manager.io/cluster-issuer: "letsencrypt"
```

**预期**：全部保留，值不变。

---

### TC-C7: 特殊注解移除

**输入 Ingress annotations**：
```yaml
kubernetes.io/ingress.class: "nginx"
kubectl.kubernetes.io/last-applied-configuration: "{...}"
```

**预期**：两个注解均不存在于迁移后的 Ingress 中。

---

### TC-C8: 混合注解综合验证

**输入 Ingress annotations**：
```yaml
kubernetes.io/ingress.class: "nginx"
nginx.ingress.kubernetes.io/rewrite-target: /$1
nginx.ingress.kubernetes.io/configuration-snippet: |
  more_set_headers "X-Test: 1";
nginx.ingress.kubernetes.io/proxy-body-size: "50m"
nginx.ingress.kubernetes.io/auth-url: "https://auth.ex"
nginx.ingress.kubernetes.io/backend-protocol: "GRPC"
my-company.io/version: "v2"
```

**预期**：

| 注解 | 结果 |
|------|------|
| `kubernetes.io/ingress.class` | 移除 |
| `rewrite-target` | 保留 /$1 |
| `configuration-snippet` | 移除 |
| `proxy-body-size` | 移除 |
| `auth-url` | 保留 |
| `backend-protocol` | 保留 GRPC |
| `my-company.io/version` | 保留 v2 |

---

### TC-C9: Higress 资源标识验证

**预期**：迁移后的 Ingress 满足以下条件：
1. label `higress.io/resource-definer` = `higress`
2. `spec.ingressClassName` = 目标 Higress IngressClass
3. 在 Higress 控制台路由列表中可见

```bash
kubectl get ingress <name>-higress -o jsonpath='{.metadata.labels.higress\.io/resource-definer}'
# 预期: higress
```

---

### TC-C10: 原始 Ingress 不被修改

**操作**：迁移前记录原始 Ingress YAML，迁移后再次获取。

**预期**：原始 Nginx Ingress 的 annotations、spec、labels 与迁移前完全一致。

---

## 附录：完整注解分类速查

### ✅ 完全兼容（39 个）— 保留

| 分类 | 注解（省略 `nginx.ingress.kubernetes.io/` 前缀） |
|------|------|
| 路由与重写 | `rewrite-target`, `use-regex`, `upstream-vhost`, `app-root` |
| 重定向 | `ssl-redirect`, `force-ssl-redirect`, `permanent-redirect`, `permanent-redirect-code`, `temporal-redirect` |
| CORS | `enable-cors`, `cors-allow-origin`, `cors-allow-methods`, `cors-allow-headers`, `cors-allow-credentials`, `cors-expose-headers`, `cors-max-age` |
| 灰度发布 | `canary`, `canary-weight`, `canary-by-header`, `canary-by-header-value`, `canary-by-header-pattern`, `canary-by-cookie`, `canary-weight-total`, `affinity-canary-behavior` |
| 负载均衡 | `affinity`, `session-cookie-name`, `session-cookie-path`, `session-cookie-max-age`, `session-cookie-expires` |
| 访问控制 | `whitelist-source-range` |
| SSL/TLS | `proxy-ssl-secret`, `proxy-ssl-name`, `proxy-ssl-server-name`, `proxy-ssl-verify` |
| 后端服务 | `proxy-next-upstream`, `proxy-next-upstream-timeout`, `proxy-next-upstream-tries` |
| 错误处理 | `custom-http-errors`, `default-backend` |

### ❌ 不兼容（35 个）— 移除

| 分类 | 注解 |
|------|------|
| Snippet | `configuration-snippet`, `server-snippet`, `stream-snippet` |
| 认证 | `auth-signin`, `auth-snippet`, `auth-signin-redirect-param`, `auth-request-redirect`, `auth-always-set-cookie`, `auth-cache-duration`, `auth-cache-key`, `auth-keepalive`, `auth-keepalive-requests`, `auth-keepalive-share-vars`, `auth-keepalive-timeout`, `auth-tls-error-page`, `satisfy` |
| SSL/TLS | `ssl-passthrough` |
| 负载均衡 | `session-cookie-domain`, `session-cookie-samesite`, `session-cookie-secure`, `session-cookie-conditional-samesite-none`, `upstream-hash-by-subset`, `upstream-hash-by-subset-size` |
| 后端服务 | `client-body-buffer-size`, `proxy-buffers-number` |
| 安全防护 | `modsecurity-snippet`, `modsecurity-transaction-id` |
| 可观测性 | `enable-opentelemetry`, `opentelemetry-trust-incoming-span`, `enable-rewrite-log` |
| 重定向 | `temporal-redirect-code` |
| 流量镜像 | `mirror-host` |
| 限流 | `limit-burst-multiplier`, `limit-rate-after`, `limit-rate` |

### 🔴 无需迁移（12 个）— 移除

`proxy-body-size`, `http2-push-preload`, `connection-proxy-header`, `ssl-prefer-server-ciphers`, `proxy-buffering`, `proxy-buffer-size`, `proxy-busy-buffers-size`, `proxy-max-temp-file-size`, `proxy-request-buffering`, `service-upstream`, `session-cookie-change-on-failure`, `mirror-request-body`

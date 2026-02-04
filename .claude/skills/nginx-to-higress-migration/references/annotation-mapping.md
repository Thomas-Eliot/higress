# Nginx to Higress Annotation Compatibility

## ⚠️ Important: Do NOT Modify Your Ingress Resources!

**Higress natively supports `nginx.ingress.kubernetes.io/*` annotations** - no conversion or modification needed!

The Higress controller uses `ParseStringASAP()` which first tries `nginx.ingress.kubernetes.io/*` prefix, then falls back to `higress.io/*`. Your existing Ingress resources work as-is with Higress.

## Fully Compatible Annotations (Work As-Is)

These nginx annotations work directly with Higress without any changes:

| nginx annotation (keep as-is) | Higress also accepts | Notes |
|-------------------------------|---------------------|-------|
| `nginx.ingress.kubernetes.io/rewrite-target` | `higress.io/rewrite-target` | Supports capture groups |
| `nginx.ingress.kubernetes.io/use-regex` | `higress.io/use-regex` | Enable regex path matching |
| `nginx.ingress.kubernetes.io/ssl-redirect` | `higress.io/ssl-redirect` | Force HTTPS |
| `nginx.ingress.kubernetes.io/force-ssl-redirect` | `higress.io/force-ssl-redirect` | Same behavior |
| `nginx.ingress.kubernetes.io/backend-protocol` | `higress.io/backend-protocol` | HTTP/HTTPS/GRPC |
| `nginx.ingress.kubernetes.io/proxy-body-size` | `higress.io/proxy-body-size` | Max body size |

### CORS

| nginx annotation | Higress annotation |
|------------------|-------------------|
| `nginx.ingress.kubernetes.io/enable-cors` | `higress.io/enable-cors` |
| `nginx.ingress.kubernetes.io/cors-allow-origin` | `higress.io/cors-allow-origin` |
| `nginx.ingress.kubernetes.io/cors-allow-methods` | `higress.io/cors-allow-methods` |
| `nginx.ingress.kubernetes.io/cors-allow-headers` | `higress.io/cors-allow-headers` |
| `nginx.ingress.kubernetes.io/cors-expose-headers` | `higress.io/cors-expose-headers` |
| `nginx.ingress.kubernetes.io/cors-allow-credentials` | `higress.io/cors-allow-credentials` |
| `nginx.ingress.kubernetes.io/cors-max-age` | `higress.io/cors-max-age` |

### Timeout & Retry

| nginx annotation | Higress annotation |
|------------------|-------------------|
| `nginx.ingress.kubernetes.io/proxy-connect-timeout` | `higress.io/proxy-connect-timeout` |
| `nginx.ingress.kubernetes.io/proxy-send-timeout` | `higress.io/proxy-send-timeout` |
| `nginx.ingress.kubernetes.io/proxy-read-timeout` | `higress.io/proxy-read-timeout` |
| `nginx.ingress.kubernetes.io/proxy-next-upstream-tries` | `higress.io/proxy-next-upstream-tries` |

### Canary (Grayscale)

| nginx annotation | Higress annotation |
|------------------|-------------------|
| `nginx.ingress.kubernetes.io/canary` | `higress.io/canary` |
| `nginx.ingress.kubernetes.io/canary-weight` | `higress.io/canary-weight` |
| `nginx.ingress.kubernetes.io/canary-header` | `higress.io/canary-header` |
| `nginx.ingress.kubernetes.io/canary-header-value` | `higress.io/canary-header-value` |
| `nginx.ingress.kubernetes.io/canary-header-pattern` | `higress.io/canary-header-pattern` |
| `nginx.ingress.kubernetes.io/canary-by-cookie` | `higress.io/canary-by-cookie` |

### Authentication

| nginx annotation | Higress annotation |
|------------------|-------------------|
| `nginx.ingress.kubernetes.io/auth-type` | `higress.io/auth-type` |
| `nginx.ingress.kubernetes.io/auth-secret` | `higress.io/auth-secret` |
| `nginx.ingress.kubernetes.io/auth-realm` | `higress.io/auth-realm` |

### Load Balancing

| nginx annotation | Higress annotation |
|------------------|-------------------|
| `nginx.ingress.kubernetes.io/load-balance` | `higress.io/load-balance` |
| `nginx.ingress.kubernetes.io/upstream-hash-by` | `higress.io/upstream-hash-by` |

### IP Access Control

| nginx annotation | Higress annotation |
|------------------|-------------------|
| `nginx.ingress.kubernetes.io/whitelist-source-range` | `higress.io/whitelist-source-range` |
| `nginx.ingress.kubernetes.io/denylist-source-range` | `higress.io/denylist-source-range` |

### Redirect

| nginx annotation | Higress annotation |
|------------------|-------------------|
| `nginx.ingress.kubernetes.io/permanent-redirect` | `higress.io/permanent-redirect` |
| `nginx.ingress.kubernetes.io/temporal-redirect` | `higress.io/temporal-redirect` |
| `nginx.ingress.kubernetes.io/permanent-redirect-code` | `higress.io/permanent-redirect-code` |

### Header Control

| nginx annotation | Higress annotation |
|------------------|-------------------|
| `nginx.ingress.kubernetes.io/proxy-set-headers` | `higress.io/proxy-set-headers` |
| `nginx.ingress.kubernetes.io/proxy-hide-headers` | `higress.io/proxy-hide-headers` |
| `nginx.ingress.kubernetes.io/proxy-pass-headers` | `higress.io/proxy-pass-headers` |

### Upstream TLS

| nginx annotation | Higress annotation |
|------------------|-------------------|
| `nginx.ingress.kubernetes.io/proxy-ssl-secret` | `higress.io/proxy-ssl-secret` |
| `nginx.ingress.kubernetes.io/proxy-ssl-verify` | `higress.io/proxy-ssl-verify` |

### TLS Protocol & Cipher Control

Higress provides fine-grained TLS control via dedicated annotations:

| nginx annotation | Higress annotation | Notes |
|------------------|-------------------|-------|
| `nginx.ingress.kubernetes.io/ssl-protocols` | (see below) | Use Higress-specific annotations |

**Higress TLS annotations (no nginx equivalent - use these directly):**

| Higress annotation | Description | Example value |
|-------------------|-------------|---------------|
| `higress.io/tls-min-protocol-version` | Minimum TLS version | `TLSv1.2` |
| `higress.io/tls-max-protocol-version` | Maximum TLS version | `TLSv1.3` |
| `higress.io/ssl-cipher` | Allowed cipher suites | `ECDHE-RSA-AES128-GCM-SHA256` |

**Example: Restrict to TLS 1.2+**
```yaml
# nginx (using ssl-protocols)
annotations:
  nginx.ingress.kubernetes.io/ssl-protocols: "TLSv1.2 TLSv1.3"

# Higress (use dedicated annotations)
annotations:
  higress.io/tls-min-protocol-version: "TLSv1.2"
  higress.io/tls-max-protocol-version: "TLSv1.3"
```

**Example: Custom cipher suites**
```yaml
annotations:
  higress.io/ssl-cipher: "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384"
```

## Unsupported Annotations (Require WASM Plugin)

These annotations have no direct Higress equivalent and require custom WASM plugins:

### Configuration Snippets
```yaml
# NOT supported - requires WASM plugin
nginx.ingress.kubernetes.io/server-snippet: |
  location /custom { ... }
nginx.ingress.kubernetes.io/configuration-snippet: |
  more_set_headers "X-Custom: value";
nginx.ingress.kubernetes.io/stream-snippet: |
  # TCP/UDP snippets
```

### Lua Scripting
```yaml
# NOT supported - convert to WASM plugin
nginx.ingress.kubernetes.io/lua-resty-waf: "active"
nginx.ingress.kubernetes.io/lua-resty-waf-score-threshold: "10"
```

### ModSecurity
```yaml
# NOT supported - use Higress WAF plugin or custom WASM
nginx.ingress.kubernetes.io/enable-modsecurity: "true"
nginx.ingress.kubernetes.io/modsecurity-snippet: |
  SecRule ...
```

### Rate Limiting (Complex)
```yaml
# Basic rate limiting supported via plugin
# Complex Lua-based rate limiting requires WASM
nginx.ingress.kubernetes.io/limit-rps: "10"
ginx.ingress.kubernetes.io/limit-connections: "5"
```

### Other Unsupported
```yaml
# NOT directly supported
nginx.ingress.kubernetes.io/client-body-buffer-size
ginx.ingress.kubernetes.io/proxy-buffering
ginx.ingress.kubernetes.io/proxy-buffers-number
ginx.ingress.kubernetes.io/proxy-buffer-size
ginx.ingress.kubernetes.io/mirror-uri
ginx.ingress.kubernetes.io/mirror-request-body
ginx.ingress.kubernetes.io/grpc-backend
ginx.ingress.kubernetes.io/custom-http-errors
ginx.ingress.kubernetes.io/default-backend
```

## Additional nginx.ingress.kubernetes.io annotations considered (ADDED)

Below are additional annotations commonly used with ingress-nginx that were not listed in the original mapping. For each I add a short note about whether Higress supports it directly, maps to an existing higress.io annotation, or typically requires a plugin/WASM/alternative configuration.

### External Authentication (external auth)
- `nginx.ingress.kubernetes.io/auth-url` — external auth request URL (commonly used with oauth2-proxy).
  - Note: Often requires Higress auth plugin or a WASM extension; map to higress auth plugin if available, otherwise implement external auth as a plugin.
- `nginx.ingress.kubernetes.io/auth-signin`
- `nginx.ingress.kubernetes.io/auth-response-headers`
- `nginx.ingress.kubernetes.io/auth-cache-duration`
- `nginx.ingress.kubernetes.io/auth-cache-key`
- `nginx.ingress.kubernetes.io/auth-tls-secret`
- `nginx.ingress.kubernetes.io/auth-tls-verify-client`
- `nginx.ingress.kubernetes.io/auth-tls-verify-depth`
- `nginx.ingress.kubernetes.io/auth-tls-pass-certificate-to-upstream`

Recommendation: Mark as "requires plugin" unless Higress offers a first-class external-auth mapping. Consider documenting a pattern using Higress auth filter or Envoy external authorization via wasm/plugin.

### Session Affinity / Sticky
- `nginx.ingress.kubernetes.io/affinity` (e.g., cookie)
- `nginx.ingress.kubernetes.io/session-cookie-name`
- `nginx.ingress.kubernetes.io/session-cookie-hash`
- `nginx.ingress.kubernetes.io/session-cookie-path`
- `nginx.ingress.kubernetes.io/session-cookie-expires`
- `nginx.ingress.kubernetes.io/session-cookie-max-age`

Note: Load-balancing / session-affinity features may map to higress.io/load-balance annotations or require service / upstream configuration. Recommend mapping these to Higress LB annotations or documenting implementation steps.

### Proxy / Upstream Behavior
- `nginx.ingress.kubernetes.io/proxy-next-upstream` (and `proxy-next-upstream-timeout`)
- `nginx.ingress.kubernetes.io/upstream-vhost`
- `nginx.ingress.kubernetes.io/proxy-protocol`
- `nginx.ingress.kubernetes.io/proxy-redirect-from`
- `nginx.ingress.kubernetes.io/proxy-redirect-to`

Note: `proxy-next-upstream` is related to retry/failover behavior. Some keys already exist in mapping (tries); add these for completeness.

### TLS / SSL related
- `nginx.ingress.kubernetes.io/ssl-passthrough` — TLS passthrough to upstream
  - Note: May require Higress to be configured in passthrough mode or use Service-type passthrough; document whether supported.
- `nginx.ingress.kubernetes.io/hsts`
- `nginx.ingress.kubernetes.io/hsts-max-age`
- `nginx.ingress.kubernetes.io/hsts-include-subdomains`
- `nginx.ingress.kubernetes.io/hsts-preload`
- `nginx.ingress.kubernetes.io/ssl-dh-param`

Recommendation: HSTS can be implemented via header annotations or via plugin. Document mapping (e.g., set headers or higress.io header controls) or mark as requires header-set plugin.

### Proxy Cache
- `nginx.ingress.kubernetes.io/proxy-cache`
- `nginx.ingress.kubernetes.io/proxy-cache-key`
- `nginx.ingress.kubernetes.io/proxy-cache-valid`
- `nginx.ingress.kubernetes.io/proxy-cache-bypass`
- `nginx.ingress.kubernetes.io/proxy-cache-use-stale`

Note: If users rely on ingress-nginx proxy-cache, clarify whether Higress supports upstream caching or requires an external cache or plugin.

### Real IP / Forwarded headers
- `nginx.ingress.kubernetes.io/real-ip-header`
- `nginx.ingress.kubernetes.io/set-real-ip-from`

Note: Important for client IP detection and logging; verify Higress behavior for X-Forwarded-For and PROXY protocol.

### Observability / Tracing / Logs
- `nginx.ingress.kubernetes.io/enable-opentracing`
- `nginx.ingress.kubernetes.io/opentracing-tracer`
- `nginx.ingress.kubernetes.io/enable-access-log`

Note: Map to Higress tracing and logging configuration or mark as plugin-needed.

### Security / Server tokens
- `nginx.ingress.kubernetes.io/server-tokens`

Note: Often controlled via global config; mark in docs how to handle via Higress global config or snippets (snippets are unsupported; recommend plugin).

### Other commonly used annotations
- `nginx.ingress.kubernetes.io/upstream-vhost` (upstream Host header)
- `nginx.ingress.kubernetes.io/grpc-backend` (listed as unsupported — note grpc pass-through may be supported via backend-protocol: "GRPC")
- `nginx.ingress.kubernetes.io/custom-http-errors` (map to Higress error handling if available)
- `nginx.ingress.kubernetes.io/default-backend` (document behavior)
- Rate-limit variants: `nginx.ingress.kubernetes.io/limit-rps`, `nginx.ingress.kubernetes.io/limit-rpm`

## Guidance & Next Steps
- I recommend we add an explicit "Additional annotations considered" section (as above) to the mapping document and mark each entry as one of: "works as-is", "maps to higress.io/*", "requires plugin/WASM", or "needs investigation". The text added in this update follows that approach.

- If you want a fully exhaustive comparison against the official ingress-nginx annotations page, I can fetch the upstream annotations list and produce a table marking each annotation's status. This will produce a larger PR but gives full confidence for migration.

## Migration Script

Use this script to analyze Ingress annotations:

```bash
# scripts/analyze-ingress.sh in this skill
./scripts/analyze-ingress.sh <namespace>
```
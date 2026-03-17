# NGINX Ingress 迁移至 Higress 指南

> 本文档基于 [注解兼容性分析](./annotation-compatibility.md) 的结论，按风险等级划分迁移优先级，并提供迁移建议与配置示例。

---

## 关键兼容性分析

### ✅ 完全兼容的核心功能（43 个）

Higress 原生支持以下核心功能，可直接使用 NGINX Ingress 注解或对应的 `higress.io/*` 前缀注解：

#### 1. 路由控制
- 路径重写（rewrite-target、use-regex）
- 虚拟主机（upstream-vhost、app-root）

#### 2. CORS 完整支持
- 所有 CORS 相关注解全部兼容（7 个）

#### 3. 灰度发布完整支持
- 所有金丝雀发布注解全部兼容（8 个）
- 支持基于权重、Header、Cookie 的流量分配

#### 4. 认证基础能力
- 外部认证（auth-url、auth-signin、auth-response-headers）

#### 5. 负载均衡与会话保持
- 基本的会话保持能力（cookie-based affinity）
- 会话 Cookie 配置（name、path、max-age、expires）

#### 6. SSL/TLS 基础配置
- 后端 TLS 配置（proxy-ssl-secret、proxy-ssl-name、proxy-ssl-server-name）

#### 7. 重定向
- 核心重定向注解兼容（ssl-redirect、force-ssl-redirect、permanent-redirect、permanent-redirect-code、temporal-redirect）

#### 8. 访问控制
- IP 白名单（whitelist-source-range）

#### 9. 重试机制
- 完整的重试配置（proxy-next-upstream、proxy-next-upstream-timeout、proxy-next-upstream-tries）

---

### 🔵 可等价替换的功能（38 个）

以下功能虽然不是直接注解兼容，但可通过 Higress 的其他机制实现相同效果：

| 功能类别     | NGINX 注解                                                            | Higress 替代方案                                                     |
| ------------ | --------------------------------------------------------------------- | -------------------------------------------------------------------- |
| **超时配置** | proxy-connect-timeout、proxy-read-timeout、proxy-send-timeout         | 连接超时→EnvoyFilter cluster `connect_timeout`；读写超时→`higress-config` `upstream.idleTimeout`（全局）或 EnvoyFilter route `idle_timeout`（路由级）；请求总超时→`higress.io/timeout` |
| **头部控制** | custom-headers、auth-proxy-set-headers、x-forwarded-prefix            | `higress.io/request-header-control-*` 或 `response-header-control-*` |
| **限流限速** | limit-rps、limit-rpm                                                  | `key-rate-limit` 插件                                                |
| **限流白名单** | limit-whitelist                                                     | `cluster-key-rate-limit` 插件 `limit_by_per_ip`（白名单 CIDR 设极大阈值） |
| **连接数限制** | limit-connections                                                   | EnvoyFilter `connection_limit`（推荐）或 DestinationRule `maxConnections` |
| **安全防护** | enable-modsecurity、enable-owasp-core-rules                           | `waf` 插件                                                           |
| **Basic Auth** | auth-type、auth-secret                                              | `basic-auth` WASM 插件（Higress v2.0.0+ 推荐）                      |
| **TLS 配置** | ssl-ciphers、proxy-ssl-ciphers、proxy-ssl-protocols、proxy-ssl-verify | `higress.io/ssl-*` 或 `proxy-ssl-*` 系列注解                         |
| **可观测性** | enable-opentelemetry、opentelemetry-trust-incoming-span               | higress-config 全局配置 tracing                                      |
| **访问日志控制** | enable-access-log                                                 | 设为 `false` 时需通过 EnvoyFilter `metadata_filter` 按路由禁用日志；设为 `true` 或不设时无需处理（Envoy 默认即全局记录） |
| **流量镜像** | mirror-target                                                         | `higress.io/mirror-target-service` 或 `mirror-target-fqdn`          |
| **mTLS 高级** | auth-tls-match-cn、auth-tls-pass-certificate-to-upstream、auth-tls-verify-depth | EnvoyFilter 配置 CertificateValidationContext / XFCC        |
| **后端 TLS** | proxy-ssl-verify-depth                                                | EnvoyFilter 配置 UpstreamTlsContext                                  |
| **重定向**   | from-to-www-redirect                                                  | `higress.io/permanent-redirect` 配合多 Ingress 规则                  |
| **Cookie 改写** | proxy-cookie-domain、proxy-cookie-path                             | WasmPlugin（transformer 插件）或 EnvoyFilter                        |
| **IP 黑名单** | denylist-source-range                                               | `ip-restriction` 插件（deny 模式）或 Higress 1.2.31+ 原生支持       |
| **请求缓冲** | proxy-request-buffering                                               | 若原值为 `off`（streaming）直接删除（Envoy 默认即流式）；若为 `on`（缓冲完整请求体）通过 EnvoyFilter 插入 `envoy.filters.http.buffer` filter |

---

### ❌ 不兼容的功能（33 个）

以下功能由于 Envoy 与 NGINX 的架构差异，存在功能缺失，需评估替代方案：

#### 1. Snippet 类注解（4 个）
- **不兼容原因**：安全考虑，Higress 不允许注入任意配置代码
- **影响注解**：
  - configuration-snippet（重要且常用，迁移工作量最大）
  - server-snippet（重要但不常用）
  - stream-snippet（不重要且不常用）
  - auth-snippet（不重要且不常用）
- **替代方案**：开发 WASM 插件实现自定义逻辑，或使用 Higress 内置插件组合替代

#### 2. 缓冲配置（2 个）
- **不兼容原因**：Envoy 缓冲模型与 NGINX 不同，仅有连接级全局配置，无法按 Ingress 粒度设置
- **影响注解**：
  - client-body-buffer-size（请求体缓冲区，Envoy 仅有连接级全局配置，语义不对等）
  - proxy-buffers-number（响应缓冲区数量，Envoy 仅有连接级总大小配置）
- **说明**：必要时可通过 EnvoyFilter 调整 `per_connection_buffer_limit_bytes`. 需要人工参与评估，大多数情况下，连接级别的全局配置已经可以满足情况。

#### 3. 请求体大小限制（1 个）
- **不兼容原因**：Higress 官方注解文档未列出 `proxy-body-size`,源码 `pkg/ingress/kube/annotations/` 中无对应 annotation parser 实现。Envoy 没有按 Ingress 粒度的请求体大小限制机制
- **影响注解**：
  - proxy-body-size（限制请求体大小,NGINX 中对应 `client_max_body_size`,Higress/Envoy 无按路由粒度的等价实现）
- **说明**：如需全局限制,可通过 `higress-config` 的 `downstream.connectionBufferLimits` 配置,但语义不对等（连接级缓冲 vs 请求体大小）。APIG 官方文档也未提及此注解

#### 4. 外部认证相关（10 个）
- **不兼容原因**：Higress ext-auth WASM 插件功能覆盖有限,不支持认证缓存、keepalive 连接池配置及部分高级配置项
- **影响注解**：
  - auth-cache-duration（认证结果缓存时长,ext-auth 插件不支持缓存功能）
  - auth-cache-key（认证缓存 key 计算方式,ext-auth 插件不支持缓存功能）
  - auth-keepalive（与认证服务的 keepalive 连接数,ext-auth 插件未暴露连接池配置）
  - auth-keepalive-requests（keepalive 连接最大请求数,ext-auth 插件未暴露连接池配置）
  - auth-keepalive-share-vars（keepalive 连接共享变量,NGINX Lua 子请求特有机制,Envoy 无对应概念）
  - auth-keepalive-timeout（keepalive 超时时间,ext-auth 插件未暴露连接池超时配置）
  - auth-method（自定义认证请求 HTTP 方法,v0.24.0+ 引入,ext-auth 插件未暴露此配置项）
  - auth-signin-redirect-param（自定义重定向参数名,v1.0.0+ 引入,ext-auth 插件不支持）
  - auth-request-redirect（设置 X-Auth-Request-Redirect 头,v0.9.0+ 引入,ext-auth 插件不支持）
  - auth-always-set-cookie（始终设置认证 Cookie,v1.1.0+ 引入,ext-auth 插件不支持）

#### 5. 安全防护（2 个）
- **不兼容原因**：Higress 未内嵌 ModSecurity 引擎，WAF 通过基于 Coraza 的 WASM 插件实现，无 ModSecurity 事务模型
- **影响注解**：
  - modsecurity-snippet（自定义 ModSecurity 规则代码片段）
  - modsecurity-transaction-id（ModSecurity 事务 ID）
- **替代方案**：使用 Higress `waf` WASM 插件，`useCRS: true` 启用 OWASP 规则集，`secRules` 传入自定义 SecRule 规则

#### 6. 可观测性（1 个）
- **不兼容原因**：Envoy 没有独立的 rewrite 调试日志机制
- **影响注解**：
  - enable-rewrite-log（Envoy 无法按 Ingress 粒度输出 rewrite 匹配过程日志）

#### 7. Session Cookie 高级属性（5 个）
- **不兼容原因**：Higress 基于 Istio API v1.27,其 `ConsistentHashLB_HTTPCookie` 仅有 Name/Path/Ttl 三个字段,不支持 Domain/SameSite/Secure 等 cookie 属性。Istio 1.28 已新增 SameSite/Secure/HttpOnly 支持,待 Higress 升级后部分可解决
- **影响注解**：
  - session-cookie-domain（Cookie Domain 属性,Istio API 不支持）
  - session-cookie-samesite（Cookie SameSite 属性,Istio 1.28 已支持,待升级）
  - session-cookie-secure（Cookie Secure 属性,Istio 1.28 已支持,待升级）
  - session-cookie-change-on-failure（后端失败时更换 cookie,Envoy 一致性哈希无此概念）
  - session-cookie-conditional-samesite-none（条件性 SameSite=None,需 User-Agent 判断逻辑）

#### 8. 流量镜像 Host 控制（1 个）
- **不兼容原因**：Envoy 的 route mirror 配置没有独立设置镜像请求 Host 的字段
- **影响注解**：
  - mirror-host（镜像请求的 Host 头覆盖）

#### 9. 多认证组合（1 个）
- **不兼容原因**：Envoy 各认证过滤器独立执行且均为"必须通过"语义,没有"any"模式
- **影响注解**：
  - satisfy（多认证方式的 all/any 组合逻辑）

#### 10. mTLS 错误页面（1 个）
- **不兼容原因**：Envoy 在 TLS 握手层面验证失败时直接返回 TLS 错误,无法进行 HTTP 层面的重定向
- **影响注解**：
  - auth-tls-error-page（mTLS 认证失败时的自定义错误页面）

#### 11. 临时重定向状态码（1 个）
- **不兼容原因**：redirect.go 中 temporal-redirect 硬编码为 302,未实现 temporal-redirect-code 注解的解析
- **影响注解**：
  - temporal-redirect-code（自定义临时重定向状态码,如 307）

#### 12. 一致性哈希 Subset 模式（2 个，新增）
- **不兼容原因**：Envoy 的一致性哈希实现没有 subset 模式概念
- **影响注解**：
  - upstream-hash-by-subset（启用 subset 哈希模式,v0.24.0+ 引入）
  - upstream-hash-by-subset-size（subset 大小配置,v0.24.0+ 引入）

#### 13. 响应速率限制（2 个，新增）
- **不兼容原因**：Envoy 流式传输架构没有按连接的响应速率限制机制
- **影响注解**：
  - limit-rate-after（速率限制起始字节数,v0.24.0+ 引入,需启用 proxy-buffering）
  - limit-rate（响应传输速率限制 KB/s,v0.24.0+ 引入,需启用 proxy-buffering）

---

### 🔴 无需迁移的注解（9 个）

以下注解迁移时可直接删除，不会产生功能缺失：

| 注解                    | 原因                                                                                           |
| ----------------------- | ---------------------------------------------------------------------------------------------- |
| http2-push-preload      | HTTP/2 Server Push 已被主流浏览器废弃（Chrome 106+ 移除）                                       |
| connection-proxy-header | Envoy 按 RFC 7230 自动处理 hop-by-hop 头（包括 Connection），且连接池默认 keep-alive，无需手动配置 |
| proxy-buffering         | Envoy 天然流式处理，SSE/长轮询场景自动就是流式的                                                 |
| proxy-buffer-size       | Envoy 响应头处理机制不同，默认配置已够用                                                         |
| proxy-busy-buffers-size | Envoy 流式架构天然不需要繁忙缓冲区概念                                                           |
| proxy-max-temp-file-size| Envoy 不使用磁盘缓冲，不存在临时文件问题                                                         |
| service-upstream        | Higress 默认通过 EDS 路由到 Endpoints（Pod IP），跳过 kube-proxy 性能更优。若原配置用于零停机滚动更新场景，建议确认 Envoy outlier detection 配置 |
| mirror-request-body     | Envoy 流量镜像天然包含完整请求（含请求体），默认行为与 NGINX 一致，无需此注解                      |
| limit-burst-multiplier  | 【v0.24.0+ 引入】Higress 限流插件有自己的突发控制机制，此 NGINX 概念无直接对应                    |

---

### ⚠️ 部分兼容的注解（8 个）

以下注解语义不完全一致，部分值/场景可用但有缺口：

| 注解                    | 问题描述                                                                                                   | 影响                                                       |
| ----------------------- | ---------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------- |
| proxy-http-version      | Envoy 向后端只支持 HTTP/1.1 和 HTTP/2，不支持 HTTP/1.0                                                     | 配置 `"1.0"` 无法实现，但实际需要 HTTP/1.0 的后端极为罕见  |
| load-balance            | Higress 不支持 NGINX 的 `ewma` 算法，Envoy/Istio 无对应实现                                                | 使用 ewma 的场景需改用 ROUND_ROBIN 或 LEAST_REQUEST        |
| upstream-hash-by        | 仅支持单个变量（`$http_*`、`$arg_*`、`$request_uri`、`$host`、`$remote_addr`），不支持多变量组合            | 使用 `$request_uri$host` 等组合 hash key 的场景无法实现    |
| affinity-mode           | 仅支持 "balanced" 模式（默认行为），"persistent" 模式不支持                                                 | 需要强粘性会话的场景受影响                                 |
| backend-protocol        | 支持 HTTP/HTTP2/HTTPS/GRPC/GRPCS，不支持 AJP 和 FCGI                                                       | Tomcat AJP 和 PHP-FPM FastCGI 场景无法使用                 |
| auth-tls-secret         | CA Secret 名称必须与 TLS 证书 Secret 同名（或加 `-cacert` 后缀）且在同一 namespace                         | Secret 命名格式比 NGINX Ingress 更严格                     |
| ssl-passthrough         | 源码中未实现 Ingress 注解层面的解析，需通过 Gateway API TLSRoute + Passthrough 模式实现                     | 无法通过 NGINX Ingress 注解直接使用                        |
| server-alias            | 【新增】Higress 1.2.30+ 支持精确域名和泛域名别名，不支持正则表达式域名别名                                  | 正则域名别名不可用，精确和泛域名可用                       |

---

## 迁移建议

### 迁移优先级

#### P0（必须处理）- 阻塞性问题
1. **Snippet 替换**：所有使用 `*-snippet` 的场景必须重构
   - 评估具体逻辑
   - 开发对应的 WASM 插件
   - 或使用 Higress 内置插件组合实现

2. **Basic Auth 迁移**：`auth-type`/`auth-secret` 推荐迁移到 `basic-auth` WASM 插件（Higress v2.0.0+ 推荐方式），插件支持多用户凭证管理、APR1 加密等，功能更完整。用户凭证需从 K8s Secret 迁移到插件配置。如需 Digest 认证需开发自定义 WASM 插件

3. **超时配置调整**：NGINX 的三个超时注解在 Envoy 中对应不同层级的配置，需分别处理：
   - **proxy-connect-timeout**（TCP 连接建立超时）→ Envoy cluster 级别 `connect_timeout`（默认 5s）。通过 EnvoyFilter 配置 cluster 的 `connect_timeout` 字段，或通过 DestinationRule 的 `trafficPolicy.connectionPool.tcp.connectTimeout` 实现
   - **proxy-read-timeout / proxy-send-timeout**（两次数据传输间的 idle 超时）→ Envoy `stream_idle_timeout`。全局配置：`higress-config` ConfigMap 中 `upstream.idleTimeout`（单位：秒，默认 10 秒）；路由粒度：通过 EnvoyFilter 设置 route 的 `idle_timeout` 按路由覆盖全局值
   - **请求总超时** → `higress.io/timeout` 注解（对应 Envoy route 级别 `timeout`，默认 15s），这是端到端总超时，语义不同于 NGINX 的 idle 超时
   - **注意**：NGINX 区分读/写方向的 idle 超时，Envoy 合并为一个 `stream_idle_timeout`，若原 read/send timeout 值不同，只能取较大值

#### P1（建议处理）- 功能优化
1. **限流限速**：`limit-rps`/`limit-rpm` 迁移到 `key-rate-limit` 插件；`limit-whitelist` 通过 `cluster-key-rate-limit` 插件的 `limit_by_per_ip` 实现（白名单 CIDR 设极大阈值）；`limit-connections` 推荐通过 EnvoyFilter `connection_limit` 实现（与 NGINX 语义一致）
2. **安全防护**：配置 `waf` 插件替代 ModSecurity，`useCRS: true` 启用 OWASP 规则集，`secRules` 追加自定义 SecRule 规则（插件基于 Coraza 引擎，无需外部依赖）
3. **头部控制**：统一使用 `request-header-control-*` / `response-header-control-*`
4. **TLS 配置**：使用 `higress.io/ssl-*` 系列注解
5. **流量镜像**：将 `mirror-target` 迁移到 `higress.io/mirror-target-service` 或 `mirror-target-fqdn`
6. **mTLS 高级特性**：通过 EnvoyFilter 配置 `auth-tls-match-cn`、`auth-tls-pass-certificate-to-upstream`、`auth-tls-verify-depth`
7. **部分兼容注解适配**：评估 `load-balance`(ewma)、`upstream-hash-by`(多变量组合)、`backend-protocol`(AJP/FCGI)、`ssl-passthrough`(改用 Gateway API)等部分兼容注解的实际使用情况,按需调整
8. **IP 黑名单**：`denylist-source-range` 迁移到 `ip-restriction` 插件的 deny 模式

#### P2（可选处理）- 增强功能
1. **Session Cookie 安全属性**：关注 Higress 升级 Istio API 至 1.28+ 后,session-cookie-samesite 和 session-cookie-secure 可原生支持
2. 配置可观测性（tracing、logging），其中 `enable-access-log: "false"` 需通过 EnvoyFilter `metadata_filter` 按路由禁用日志（详见配置示例 3.3）；设为 `"true"` 或不设时无需处理
3. 优化性能相关配置

---

### 迁移步骤

#### 第一阶段：评估与准备（1-2 周）

1. **资源盘点**
   ```bash
   # 导出所有 Ingress 资源
   kubectl get ingress --all-namespaces -o yaml > ingress-backup.yaml
   
   # 统计注解使用情况
   grep "nginx.ingress.kubernetes.io/" ingress-backup.yaml | sort | uniq -c
   ```

2. **风险评估**
   - 标记所有使用 snippet 的 Ingress
   - 标记所有使用 auth-type/auth-secret 的 Ingress
   - 标记所有使用不兼容注解的 Ingress

3. **开发准备**
   - 开发必要的 WASM 插件
   - 准备 higress-config ConfigMap
   - 准备必要的 EnvoyFilter

#### 第二阶段：迁移执行（2-4 周）

1. **完全兼容注解（低风险）**
   - 直接保留或替换为 `higress.io/*` 前缀
   - 验证功能正常

2. **可等价替换注解（中风险）**
   - 按功能模块逐步替换
   - 每个模块替换后进行功能测试

3. **不兼容注解（高风险）**
   - 部署开发的 WASM 插件
   - 小范围灰度验证
   - 逐步扩大范围

#### 第三阶段：验证与优化（1-2 周）

1. **功能验证**
   - 路由功能测试
   - 认证授权测试
   - 灰度发布测试
   - 负载均衡测试

2. **性能测试**
   - 压力测试
   - 延迟测试
   - 稳定性测试

3. **监控告警**
   - 配置 metrics 采集
   - 配置日志采集
   - 配置告警规则

---

## 配置示例

### 1. Higress 全局配置

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: higress-config
  namespace: higress-system
data:
  higress: |
    # Upstream 连接配置
    upstream:
      idleTimeout: 10  # 单位:秒，默认 10 秒。对应 Envoy HCM stream_idle_timeout，替代 NGINX proxy-read-timeout/proxy-send-timeout（idle 语义）
      connectionBufferLimits: 1048576  # 1MB
    
    # Downstream 连接配置
    downstream:
      idleTimeout: 180  # 单位:秒
      maxRequestHeadersKb: 60
      connectionBufferLimits: 32768
      http2:
        maxConcurrentStreams: 100
        initialStreamWindowSize: 65535
        initialConnectionWindowSize: 1048576
    
    # Tracing 配置
    tracing:
      enable: true
      sampling: 100
      timeout: 500
      opentelemetry:
        service: otel-collector.observability.svc.cluster.local
        port: 4317
    
    # Gzip 压缩
    gzip:
      enable: false
      minContentLength: 1024
      contentType:
        - text/html
        - application/json
```

### 2. EnvoyFilter：XFF 可信 CIDR

```yaml
apiVersion: networking.istio.io/v1alpha3
kind: EnvoyFilter
metadata:
  name: xff-trusted-cidrs
  namespace: higress-system
spec:
  workloadSelector:
    labels:
      app: higress-gateway
  configPatches:
  - applyTo: HTTP_FILTER
    match:
      context: GATEWAY
      listener:
        filterChain:
          filter:
            name: "envoy.filters.network.http_connection_manager"
    patch:
      operation: MERGE
      value:
        typed_config:
          "@type": "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager"
          use_remote_address: true
          xff_num_trusted_hops: 1
          original_ip_detection_extensions:
          - name: envoy.http.original_ip_detection.xff
            typed_config:
              "@type": "type.googleapis.com/envoy.extensions.http.original_ip_detection.xff.v3.XffConfig"
              xff_trusted_cidrs:
                cidrs:
                - address_prefix: "10.0.0.0"
                  prefix_len: 8
                - address_prefix: "172.16.0.0"
                  prefix_len: 12
                - address_prefix: "192.168.0.0"
                  prefix_len: 16
```

### 3. EnvoyFilter：连接缓冲区限制

```yaml
apiVersion: networking.istio.io/v1alpha3
kind: EnvoyFilter
metadata:
  name: connection-buffer-limit
  namespace: higress-system
spec:
  workloadSelector:
    labels:
      app: higress-gateway
  configPatches:
  - applyTo: NETWORK_FILTER
    match:
      context: GATEWAY
      listener:
        filterChain:
          filter:
            name: "envoy.filters.network.http_connection_manager"
    patch:
      operation: MERGE
      value:
        typed_config:
          "@type": "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager"
          per_connection_buffer_limit_bytes: 1048576  # 1MB
```

### 3.1 EnvoyFilter：路由级 idle_timeout（替代 proxy-read-timeout / proxy-send-timeout）

> NGINX 的 `proxy_read_timeout` 和 `proxy_send_timeout` 都是 idle 语义（两次数据传输间的最大间隔）。
> 在 Envoy 中，两者合并映射到 `stream_idle_timeout`（HCM 全局级别）和 route `idle_timeout`（路由级别）。
>
> 全局配置使用 `higress-config` 的 `upstream.idleTimeout`；如需按路由覆盖，使用以下 EnvoyFilter。

```yaml
apiVersion: networking.istio.io/v1alpha3
kind: EnvoyFilter
metadata:
  name: route-idle-timeout
  namespace: higress-system
spec:
  workloadSelector:
    labels:
      app: higress-gateway
  configPatches:
  - applyTo: ROUTE_CONFIGURATION
    match:
      context: GATEWAY
    patch:
      operation: MERGE
      value:
        virtual_hosts:
        - name: "api.example.com:80"    # 匹配目标 virtual host
          routes:
          - match:
              prefix: "/slow-api"       # 匹配目标路由
            route:
              idle_timeout: 300s        # 5 分钟，覆盖全局 stream_idle_timeout
```

> **说明**：route `idle_timeout` 会覆盖 HCM 级别的 `stream_idle_timeout`，语义相同——
> 流上两次数据传输之间的最大间隔。适用于后端处理耗时请求（AI 推理、报表生成）的场景。

### 3.2 EnvoyFilter：cluster connect_timeout（替代 proxy-connect-timeout）

> NGINX 的 `proxy_connect_timeout` 仅控制 TCP 连接建立超时。在 Envoy 中对应 cluster 级别的 `connect_timeout`（默认 5s）。

**方式一：EnvoyFilter 修改 cluster connect_timeout**

```yaml
apiVersion: networking.istio.io/v1alpha3
kind: EnvoyFilter
metadata:
  name: cluster-connect-timeout
  namespace: higress-system
spec:
  workloadSelector:
    labels:
      app: higress-gateway
  configPatches:
  - applyTo: CLUSTER
    match:
      context: GATEWAY
      cluster:
        service: "my-service.default.svc.cluster.local"
    patch:
      operation: MERGE
      value:
        connect_timeout: 10s          # TCP 连接建立超时 10 秒
```

**方式二：DestinationRule connectTimeout**

```yaml
apiVersion: networking.istio.io/v1beta1
kind: DestinationRule
metadata:
  name: my-service-timeout
  namespace: default
spec:
  host: my-service.default.svc.cluster.local
  trafficPolicy:
    connectionPool:
      tcp:
        connectTimeout: 10s           # TCP 连接建立超时 10 秒
```

> **NGINX → Envoy 超时映射总结**：
> | NGINX 注解 | Envoy 配置 | 层级 | 默认值 |
> |---|---|---|---|
> | proxy-connect-timeout | cluster `connect_timeout` | cluster 级别 | 5s |
> | proxy-read-timeout | `stream_idle_timeout` / route `idle_timeout` | HCM 全局 / route 级别 | 5min |
> | proxy-send-timeout | 同上（Envoy 不区分读/写） | 同上 | 5min |
> | — | route `timeout` (`higress.io/timeout`) | route 级别 | 15s |

### 3.3 EnvoyFilter：按路由禁用访问日志（替代 enable-access-log）

> NGINX Ingress 全局默认开启 access log，`enable-access-log: "false"` 的作用是在特定 Ingress 的 location 块中插入 `access_log off;`，
> 从而关闭该路由的访问日志输出（常见场景：健康检查路由关闭日志以减少噪音）。设为 `"true"` 或不设时沿用全局配置，不产生额外行为。
>
> Higress 源码中无对应 annotation parser 实现，`higress-config` 也无访问日志相关配置字段。
> Envoy 的 access log 配置在 HCM（HttpConnectionManager）级别，没有原生的按路由开关机制。
> 要实现等价的"按路由禁用日志"，必须通过 EnvoyFilter 在路由上打元数据标记，并在 HCM access_log 中配置 `metadata_filter` 过滤。

**步骤一：在需要关闭日志的路由上设置元数据标记**

```yaml
apiVersion: networking.istio.io/v1alpha3
kind: EnvoyFilter
metadata:
  name: route-disable-accesslog-metadata
  namespace: higress-system
spec:
  workloadSelector:
    labels:
      app: higress-gateway
  configPatches:
  - applyTo: ROUTE_CONFIGURATION
    match:
      context: GATEWAY
    patch:
      operation: MERGE
      value:
        virtual_hosts:
        - name: "api.example.com:80"        # 匹配目标 virtual host
          routes:
          - match:
              prefix: "/healthz"             # 需要关闭日志的路由（如健康检查）
            metadata:
              filter_metadata:
                envoy.access_loggers:
                  disable_access_log: true   # 标记此路由禁用访问日志
            route:
              cluster: health-check-service
```

**步骤二：在 HCM access_log 中添加 metadata_filter，排除已标记的路由**

```yaml
apiVersion: networking.istio.io/v1alpha3
kind: EnvoyFilter
metadata:
  name: accesslog-route-filter
  namespace: higress-system
spec:
  workloadSelector:
    labels:
      app: higress-gateway
  configPatches:
  - applyTo: NETWORK_FILTER
    match:
      context: GATEWAY
      listener:
        filterChain:
          filter:
            name: "envoy.filters.network.http_connection_manager"
    patch:
      operation: MERGE
      value:
        typed_config:
          "@type": "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager"
          access_log:
          - name: envoy.access_loggers.file
            filter:
              # 排除标记了 disable_access_log=true 的路由
              metadata_filter:
                matcher:
                  filter: envoy.access_loggers
                  path:
                  - key: disable_access_log
                  value:
                    bool_match: false        # 仅当 disable_access_log=false 时记录
                match_if_key_not_found: true  # 未打标记的路由默认记录日志（等价于 enable-access-log 默认 true）
            typed_config:
              "@type": "type.googleapis.com/envoy.extensions.access_loggers.file.v3.FileAccessLog"
              path: /dev/stdout
```

> **语义对照**：
> | NGINX Ingress | Envoy/Higress |
> |---|---|
> | `enable-access-log` 不设或 `"true"` | 路由无元数据标记，`match_if_key_not_found: true` 命中，正常记录日志 |
> | `enable-access-log: "false"` | 路由设置 `disable_access_log: true`，`bool_match: false` 不匹配，日志被过滤 |
>
> **注意**：
> - 此方案需要两个 EnvoyFilter 配合：一个在路由上打标记，一个在 access_log 中按标记过滤
> - 配置复杂度显著高于 NGINX 的单注解方式，建议仅在确实需要按路由关闭日志时使用
> - 如果只是想减少健康检查日志噪音，也可直接使用 Envoy 内置的 `not_health_check_filter`（但仅对 Envoy 健康检查请求生效，不适用于自定义健康检查路径）

### 4. WasmPlugin：限流

```yaml
apiVersion: extensions.higress.io/v1alpha1
kind: WasmPlugin
metadata:
  name: rate-limit
  namespace: higress-system
spec:
  defaultConfig:
    limit_by_per_ip: 100          # 每 IP 每秒 100 请求
    limit_by_per_header: ""
    rejected_code: 429
    rejected_msg: "Too Many Requests"
    redis:
      enable: true
      service: "redis.default.svc.cluster.local"
      port: 6379
  matchRules:
  - ingress:
    - "default/my-ingress"
    config:
      limit_by_per_ip: 1000       # 特定 Ingress 提高限额
  url: oci://higress-registry.cn-hangzhou.cr.aliyuncs.com/plugins/key-rate-limit:1.0.0
```

### 4.1 限流白名单（替代 limit-whitelist）

> NGINX `limit-whitelist` 指定不受限流约束的客户端 IP CIDR 列表。Higress 通过 `cluster-key-rate-limit` 插件的
> `limit_by_per_ip` 实现等价功能：为白名单 CIDR 配置极大阈值，兜底 `0.0.0.0/0` 配置正常阈值。
>
> **注意**：C++ 版 `key-rate-limit` 仅支持 `limit_by_header`/`limit_by_param`，不支持按 IP/CIDR 限流，
> 需使用 Go 版 `cluster-key-rate-limit` 插件（依赖 Redis）。

```yaml
apiVersion: extensions.higress.io/v1alpha1
kind: WasmPlugin
metadata:
  name: rate-limit-with-whitelist
  namespace: higress-system
spec:
  defaultConfig:
    rule_name: my-rate-limit
    rule_items:
      - limit_by_per_ip: from-header-x-forwarded-for  # 或 from-remote-addr
        limit_keys:
          # 白名单 CIDR — 设极大阈值，等价于不限流
          - key: 10.0.0.0/8
            query_per_second: 1000000
          - key: 192.168.1.0/24
            query_per_second: 1000000
          # 其他 IP 的正常限流（兜底规则）
          - key: 0.0.0.0/0
            query_per_second: 100
    rejected_code: 429
    rejected_msg: "Too Many Requests"
    show_limit_quota_header: true
    redis:
      service_name: redis.default.svc.cluster.local
      service_port: 6379
  url: oci://higress-registry.cn-hangzhou.cr.aliyuncs.com/plugins/cluster-key-rate-limit:1.0.0
```

> **原理说明**：`limit_keys` 按顺序匹配，白名单 CIDR 放前面，命中后拿到极高阈值（实际永远不会触发限流），
> 未命中白名单的 IP 落入兜底规则 `0.0.0.0/0`，按正常阈值限流。

### 4.2 连接数限制（替代 limit-connections）

> NGINX `limit-connections` 限制的是每个 IP 的并发连接数。Higress 限流插件仅支持请求速率限制，
> 不支持并发连接数限制。需通过以下方式替代：

**方式一（推荐）：EnvoyFilter — 限制下游入站并发连接数（与 NGINX 语义一致）**

```yaml
apiVersion: networking.istio.io/v1alpha3
kind: EnvoyFilter
metadata:
  name: connection-limit
  namespace: higress-system
spec:
  configPatches:
  - applyTo: NETWORK_FILTER
    match:
      listener:
        filterChain:
          filter:
            name: envoy.filters.network.http_connection_manager
    patch:
      operation: INSERT_BEFORE
      value:
        name: envoy.filters.network.connection_limit
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.connection_limit.v3.ConnectionLimit
          stat_prefix: connection_limit
          max_connections: 100     # 最大并发连接数
          delay: 0s
```

**方式二：DestinationRule — 限制到上游的最大连接数**

```yaml
apiVersion: networking.istio.io/v1beta1
kind: DestinationRule
metadata:
  name: my-service-connection-limit
  namespace: default
spec:
  host: my-service.default.svc.cluster.local
  trafficPolicy:
    connectionPool:
      tcp:
        maxConnections: 100       # 最大并发 TCP 连接数
        connectTimeout: 30s
```

> **区别说明**：EnvoyFilter `connection_limit` 限制的是 client → gateway 方向的连接数，与 NGINX `limit-connections` 语义一致，推荐优先使用；
> DestinationRule `maxConnections` 限制的是 gateway → upstream 方向的连接数，适用于保护上游服务的场景。

### 5. WasmPlugin：WAF

> Higress `waf` 插件基于 [Coraza](https://github.com/corazawaf/coraza) 引擎（纯 Go 实现的 ModSecurity 兼容 WAF），
> 编译为 WASM 运行在 Envoy 内部，无需外部服务依赖。内置 SQL 注入（SQLi）、XSS、正则匹配（RX）、短语匹配（PM）检测能力。
>
> 插件配置项：
> - `useCRS`（boolean）：是否启用内嵌的 OWASP CRS（Core Rule Set）规则集，包含 SQL 注入、XSS、RCE 等常见攻击防护规则
> - `secRules`（string[]）：自定义 SecRule 规则列表，语法兼容 ModSecurity SecRule 指令

**示例 5.1：启用 OWASP CRS 规则集（替代 enable-modsecurity + enable-owasp-core-rules）**

```yaml
apiVersion: extensions.higress.io/v1alpha1
kind: WasmPlugin
metadata:
  name: waf
  namespace: higress-system
spec:
  defaultConfig:
    useCRS: true                    # 启用内嵌 OWASP CRS 规则集，覆盖 SQL 注入、XSS、RCE 等常见攻击
  matchRules:
  - ingress:
    - "prod/*"                      # 仅对生产环境 Ingress 启用 WAF
  url: oci://higress-registry.cn-hangzhou.cr.aliyuncs.com/plugins/waf:1.0.0
```

> **迁移映射**：
> - `enable-modsecurity: "true"` + `enable-owasp-core-rules: "true"` → `useCRS: true`
> - 启用后，插件自动加载 `@owasp_crs/*.conf` 规则集并开启 `SecRuleEngine On`

**示例 5.2：自定义 SecRule 规则（替代 modsecurity-snippet）**

```yaml
apiVersion: extensions.higress.io/v1alpha1
kind: WasmPlugin
metadata:
  name: waf-custom
  namespace: higress-system
spec:
  defaultConfig:
    useCRS: true                    # 同时启用 OWASP CRS 基础防护
    secRules:                       # 追加自定义 SecRule 规则
    - "SecRule ARGS \"@rx (?i:union.*select|insert.*into)\" \"id:1001,phase:2,deny,status:403,msg:'SQL Injection Detected'\""
    - "SecRule REQUEST_HEADERS:User-Agent \"@pm nikto sqlmap\" \"id:1002,phase:1,deny,status:403,msg:'Malicious Scanner Blocked'\""
    - "SecRule REQUEST_URI \"@rx /\\.\\./\" \"id:1003,phase:1,deny,status:403,msg:'Path Traversal Blocked'\""
  matchRules:
  - ingress:
    - "default/secure-app"
  url: oci://higress-registry.cn-hangzhou.cr.aliyuncs.com/plugins/waf:1.0.0
```

> **说明**：
> - `secRules` 中每条规则为完整的 SecRule 指令字符串，语法与 ModSecurity 一致
> - 可与 `useCRS: true` 同时使用，自定义规则会追加在 CRS 规则之后
> - 仅使用 `secRules`（不启用 `useCRS`）时，只有自定义规则生效，适合需要精细控制规则集的场景

**示例 5.3：仅自定义规则（不启用 CRS）**

```yaml
apiVersion: extensions.higress.io/v1alpha1
kind: WasmPlugin
metadata:
  name: waf-minimal
  namespace: higress-system
spec:
  defaultConfig:
    secRules:
    - "SecRuleEngine On"            # 需手动开启规则引擎（useCRS 会自动开启）
    - "SecRule ARGS \"@rx (?i:select.*from|drop\\s+table)\" \"id:2001,phase:2,deny,status:403\""
  url: oci://higress-registry.cn-hangzhou.cr.aliyuncs.com/plugins/waf:1.0.0
```

> **NGINX → Higress WAF 迁移对照**：
> | NGINX Ingress 注解 | Higress WAF 插件配置 | 说明 |
> |---|---|---|
> | `enable-modsecurity: "true"` | `useCRS: true` | 启用 WAF 引擎 + OWASP 规则集 |
> | `enable-owasp-core-rules: "true"` | `useCRS: true` | 同上，两个注解合并为一个配置项 |
> | `modsecurity-snippet` | `secRules: [...]` | 自定义规则，语法兼容 SecRule 指令 |
> | `modsecurity-transaction-id` | 无对应 | Coraza 无 ModSecurity 事务模型，如需请求追踪可结合 OpenTelemetry |

### 6. WasmPlugin：Basic Auth

```yaml
apiVersion: extensions.higress.io/v1alpha1
kind: WasmPlugin
metadata:
  name: basic-auth
  namespace: higress-system
spec:
  matchRules:
  - ingress:
    - "default/admin-ingress"     # 仅对 admin Ingress 启用认证
    config:
      consumers:
      - name: "admin"
        credential: "admin:$apr1$1234abcd$..."  # APR1 加密密码
      - name: "operator"
        credential: "operator:$apr1$5678efgh$..."
      realm: "Admin Area"
  url: oci://higress-registry.cn-hangzhou.cr.aliyuncs.com/plugins/basic-auth:1.0.0
```

### 6.1 头部控制迁移（替代 custom-headers / auth-proxy-set-headers / x-forwarded-prefix）

> NGINX Ingress 的 `custom-headers` 注解引用一个 ConfigMap（格式：`namespace/configmap-name`），ConfigMap 中的 key-value 会作为请求头添加到所有代理请求中。
> Higress 不支持 ConfigMap 引用模式，改为在 Ingress 注解中直接内联声明头部操作，粒度更细（支持 add/update/remove 三种操作）。

**迁移前：NGINX Ingress（ConfigMap 引用模式）**

```yaml
# 1. 创建 ConfigMap 存放自定义头部
apiVersion: v1
kind: ConfigMap
metadata:
  name: custom-headers
  namespace: default
data:
  X-Request-ID: "$req_id"
  X-Forwarded-Prefix: "/api"
  X-Custom-Trace: "my-trace-id"
---
# 2. Ingress 通过注解引用 ConfigMap
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: my-ingress
  namespace: default
  annotations:
    nginx.ingress.kubernetes.io/custom-headers: "default/custom-headers"
spec:
  # ...
```

**迁移后：Higress（内联注解模式）**

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: my-ingress
  namespace: default
  annotations:
    # 添加请求头（对应 custom-headers 的核心功能）
    # 格式：每行一个 "header-name header-value"，多个头部用换行分隔
    higress.io/request-header-control-add: |
      X-Request-ID $req_id
      X-Forwarded-Prefix /api
      X-Custom-Trace my-trace-id
    # 覆盖已有请求头（如需修改而非追加）
    higress.io/request-header-control-update: |
      Host backend.internal.com
    # 删除请求头（逗号分隔）
    higress.io/request-header-control-remove: "X-Powered-By,Server"
    # 响应头同理
    higress.io/response-header-control-add: |
      X-Content-Type-Options nosniff
      Strict-Transport-Security "max-age=31536000; includeSubDomains"
    higress.io/response-header-control-remove: "X-Powered-By,Server"
spec:
  # ...
```

> **迁移要点**：
> - NGINX `custom-headers` 引用 ConfigMap → Higress 直接在注解中内联声明，迁移时需将 ConfigMap 的 key-value 逐行写入 `request-header-control-add`
> - NGINX `auth-proxy-set-headers` 同理，迁移到 `request-header-control-add` 或 `request-header-control-update`
> - NGINX `x-forwarded-prefix` 迁移到 `request-header-control-add: X-Forwarded-Prefix /your-prefix`
> - `add` 是追加（同名头部可存在多个值），`update` 是覆盖（同名头部只保留新值），按实际需求选择
> - 值中包含分号或空格时需用引号包裹，如 `"max-age=31536000; includeSubDomains"`

### 7. Ingress 示例：完整配置

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: example-ingress
  namespace: default
  annotations:
    # 路由配置
    higress.io/rewrite-target: /api/$2
    higress.io/use-regex: "true"
    
    # CORS 配置
    higress.io/enable-cors: "true"
    higress.io/cors-allow-origin: "https://example.com"
    higress.io/cors-allow-methods: "GET, POST, PUT, DELETE"
    higress.io/cors-allow-headers: "DNT,Keep-Alive,User-Agent,Content-Type"
    higress.io/cors-allow-credentials: "true"
    higress.io/cors-max-age: "86400"
    
    # 灰度发布
    higress.io/canary: "true"
    higress.io/canary-weight: "30"
    
    # 负载均衡
    higress.io/load-balance: "consistent-hash"
    higress.io/upstream-hash-by: "$request_header_user_id"
    
    # 会话保持
    higress.io/affinity: "cookie"
    higress.io/session-cookie-name: "route"
    higress.io/session-cookie-max-age: "3600"
    
    # SSL/TLS
    higress.io/ssl-redirect: "true"
    higress.io/force-ssl-redirect: "true"
    
    # 访问控制
    higress.io/whitelist-source-range: "10.0.0.0/8,172.16.0.0/12"
    
    # 超时配置
    higress.io/timeout: "30s"
    
    # 重试配置
    higress.io/proxy-next-upstream: "error timeout http_502 http_503 http_504"
    higress.io/proxy-next-upstream-tries: "3"
    higress.io/proxy-next-upstream-timeout: "10s"
    
    # 后端配置
    higress.io/backend-protocol: "HTTPS"
    
    # 头部控制
    higress.io/request-header-control-add: "X-Request-ID $request_id"
    higress.io/response-header-control-remove: "X-Powered-By"
    
spec:
  ingressClassName: higress
  rules:
  - host: api.example.com
    http:
      paths:
      - path: /v1(/|$)(.*)
        pathType: ImplementationSpecific
        backend:
          service:
            name: api-service
            port:
              number: 8080
  tls:
  - hosts:
    - api.example.com
    secretName: api-tls-secret
```

---

## 常见问题 FAQ

### Q1：为什么 Higress 不支持 snippet 注解？
**A**：出于安全考虑。Snippet 注解允许用户注入任意 NGINX 配置代码，存在安全风险。Higress 推荐使用 WASM 插件实现自定义逻辑，提供更安全、可控的扩展机制。

### Q2：proxy-connect-timeout、proxy-read-timeout、proxy-send-timeout 如何配置？
**A**：这三个 NGINX 超时注解在 Envoy 中对应不同层级的配置，不能简单用一个配置替代：

| NGINX 注解 | 语义 | Envoy 对应配置 | 配置方式 |
|---|---|---|---|
| proxy-connect-timeout | TCP 连接建立超时 | cluster `connect_timeout`（默认 5s） | EnvoyFilter 或 DestinationRule `connectTimeout` |
| proxy-read-timeout | 两次读操作间的 idle 超时 | HCM `stream_idle_timeout`（默认 5min）或 route `idle_timeout` | 全局：`higress-config` `upstream.idleTimeout`；路由级：EnvoyFilter route `idle_timeout` |
| proxy-send-timeout | 两次写操作间的 idle 超时 | 同上（Envoy 不区分读/写方向） | 同上 |

- `higress.io/timeout` 对应的是 route 级别的 `timeout`（端到端请求总超时，默认 15s），语义不同于 NGINX 的 idle 超时，但可用于控制请求最大耗时
- 若原 NGINX 配置中 read/send timeout 值不同，迁移时只能取较大值作为 Envoy 的统一 `idle_timeout`
- 详见配置示例中的"超时配置"章节

### Q3：缓冲相关的注解都不支持，会影响大文件上传吗？
**A**：Envoy 有自己的缓冲机制，默认配置已能处理大多数场景。但需注意 `proxy-body-size`（请求体大小限制）在 Higress 中也不支持，源码中无对应 annotation parser 实现，Envoy 没有按 Ingress 粒度的请求体大小限制机制。如需全局调整缓冲，可通过 `higress-config` 的 `downstream.connectionBufferLimits` 或 EnvoyFilter 配置 `per_connection_buffer_limit_bytes`，但语义不对等（连接级缓冲 vs 请求体大小）。

### Q4：如何迁移使用了 configuration-snippet 的 Ingress？
**A**：需要根据 snippet 的具体功能选择方案：
- **简单头部操作**：使用 `request-header-control-*` / `response-header-control-*` 注解
- **复杂逻辑**：开发 WASM 插件
- **常见功能**：使用 Higress 内置插件（限流、WAF、认证等）

### Q5：Higress 支持 HTTP/2 到后端服务吗？
**A**：支持。使用 `higress.io/backend-protocol: "GRPC"` 或 `higress.io/backend-protocol: "GRPCS"` 即可启用 HTTP/2。

### Q6：会话保持（Session Affinity）功能完全兼容吗？
**A**：基本兼容但有多处缺口。主要的 session cookie 配置（name、path、max-age、expires）都支持。但存在以下限制：
1. **affinity-mode**：仅支持 "balanced" 模式，"persistent" 模式不支持
2. **domain、samesite、secure** 等 cookie 属性不支持，原因是 Higress 基于 Istio API v1.27，其 HTTPCookie 结构体仅有 Name/Path/Ttl 三个字段。Istio 1.28 已新增 SameSite/Secure/HttpOnly 支持，待 Higress 升级后 samesite 和 secure 可解决，但 domain 属性仍不在 Istio API 中
3. **load-balance**：不支持 ewma 算法
4. **upstream-hash-by**：不支持多变量组合

### Q7：如何验证迁移后的功能是否正常？
**A**：建议采用以下验证步骤：
1. **功能测试**：覆盖所有路由、认证、灰度、负载均衡场景
2. **性能测试**：对比迁移前后的延迟、吞吐量
3. **灰度发布**：先在非生产环境验证，再逐步灰度到生产
4. **监控观察**：持续观察 metrics、日志、告警

### Q8：本文档的兼容性判断与 Higress 官方注解文档有差异怎么办？
**A**：本文档基于 Higress 源码（`pkg/ingress/kube/annotations/*.go`）、Higress 官方注解文档（https://higress.io/docs/latest/user/annotation/）以及 APIG Ingress 官方文档（public.md）三方交叉验证。

主要差异说明：
1. **APIG 文档"兼容"≠ 本文档"✅ 完全兼容"**：APIG 文档的"兼容"统计口径更宽,包含了部分需要特定网关版本的注解(如 denylist-source-range 需 1.2.31、server-alias 需 1.2.30)
2. **auth-type/auth-secret**：APIG 文档分别标注"部分兼容(暂只支持 Basic)"和"兼容",本文档标注为 🔵 可等价替换,推荐通过 `basic-auth` WASM 插件实现(Higress v2.0.0+ 推荐方式)
3. **ssl-ciphers vs ssl-cipher**：NGINX 官方注解名为 `ssl-ciphers`(复数),APIG/Higress 使用 `ssl-cipher`(单数),功能等价但名称不同
4. **server-alias**：APIG 文档标注"部分兼容(仅支持精确域名和泛域名,要求网关版本 1.2.30)",本文档已从 🔴 调整为 ⚠️

对于标注"⚡ APIG 文档差异"的注解,建议以实际网关版本和测试结果为准。

---

## 参考资料

### 官方文档
- [Higress 官方文档](https://higress.io/zh-cn/docs/)
- [Higress 注解列表](https://higress.io/zh-cn/docs/user/annotation/)
- [Higress WASM 插件开发](https://higress.io/zh-cn/docs/plugins/overview/)
- [NGINX Ingress Controller 注解](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/annotations/)
- [Envoy 官方文档](https://www.envoyproxy.io/docs/envoy/latest/)

### 相关资源
- [Higress GitHub](https://github.com/alibaba/higress)
- [Higress 插件市场](https://higress.io/zh-cn/plugins/)
- [Istio EnvoyFilter 文档](https://istio.io/latest/docs/reference/config/networking/envoy-filter/)

### 社区支持
- [Higress 官方钉钉群](https://higress.io/zh-cn/docs/community/community/)
- [GitHub Issues](https://github.com/alibaba/higress/issues)
- [阿里云问答](https://developer.aliyun.com/ask/)

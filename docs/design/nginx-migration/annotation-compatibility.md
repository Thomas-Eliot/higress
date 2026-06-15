# NGINX Ingress 注解在 Higress 中的兼容性分析

> **说明：** 本文档分析了 NGINX Ingress Controller 官方所有注解在 Higress 中的兼容性情况。基于 [NGINX Ingress Controller 官方注解页面](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/annotations/) 的完整注解列表，共计 130 个注解，按功能分类展示。
>
> **版本说明：** 本文档基于 NGINX Ingress Controller 最新版本（v1.x）的注解列表。部分注解在不同版本中引入或变更，已在相关条目中标注版本信息。
>
> **注解来源说明：** NGINX Ingress Controller 官方注解页面包含两部分注解：
> - **顶部索引表（117 个）**：页面顶部的汇总表格中列出的注解，作为核心注解的快速索引
> - **正文补充注解（13 个）**：仅在页面正文各功能章节中描述但未列入顶部索引表的注解（如 auth-signin、limit-rpm 等）。这些注解在代码中均有实现，是当前最新版本完全支持的有效注解，只是文档编排上未被收录到顶部索引表中
> - 本文档中标注 `📋` 的 13 个注解表示仅在正文章节描述、未列入顶部 117 注解索引表；其余 117 个注解均在顶部索引表中
>
> **交叉验证：** 本文档已与 [APIG Ingress 公有云官方注解文档](https://help.aliyun.com/zh/api-gateway/cloud-native-api-gateway/user-guide/annotations-supported-by-higress-ingress-gateways?spm=a2c4g.11186623.help-menu-29462.d_2_10_5.709b6900gDaTsV&scm=20140722.H_2842272._.OR_help-T_cn~zh-V_1#section-sfj-e5e-g26)进行交叉验证，对于 APIG 文档中标注"兼容"但本文档判定不同的注解，已在备注中说明差异原因。
>
> **迁移指南：** 风险等级划分、迁移建议、配置示例及 FAQ 请参阅 [迁移指南](./migration-guide.md)。

## 统计汇总

| 兼容性分类   | 数量    | 占比     | 主要说明                                                     |
| ------------ | ------- | -------- | ------------------------------------------------------------ |
| ✅ 完全兼容   | 39      | 30.0%    | Higress 原生支持，直接使用原注解或 higress.io/* 前缀         |
| 🔵 可等价替换 | 37      | 28.5%    | 通过 WASM 插件/higress-config 全局配置/EnvoyFilter 实现      |
| ❌ 不兼容     | 35      | 26.9%    | Envoy 架构差异导致功能缺失，需评估替代方案                   |
| ⚠️ 部分兼容   | 7       | 5.4%     | 语义不完全一致，部分值/场景可用但有缺口                      |
| 🔴 无需迁移   | 12      | 9.2%     | Envoy 架构天然覆盖或功能已过时，迁移时直接忽略               |
| **总计**     | **130** | **100%** | 包含 NGINX Ingress Controller 官方注解页面列出的所有注解     |

> **与 [APIG Ingress 公有云官方注解文档](https://help.aliyun.com/zh/api-gateway/cloud-native-api-gateway/user-guide/annotations-supported-by-higress-ingress-gateways?spm=a2c4g.11186623.help-menu-29462.d_2_10_5.709b6900gDaTsV&scm=20140722.H_2842272._.OR_help-T_cn~zh-V_1#section-sfj-e5e-g26)统计差异说明：**
> - APIG 文档声称"支持的注解 51 个"，其统计口径包含了"部分兼容"注解（如 server-alias、auth-tls-secret 等），且将 denylist-source-range（需网关 1.2.31）、auth-secret/auth-secret-type 等计入"兼容"。
> - 本文档采用更严格的分类标准：仅当 Higress 原生支持且语义完全一致时标记为 ✅ 完全兼容；通过插件/配置替代的标记为 🔵；有功能子集缺口的标记为 ⚠️。
> - 具体差异见各注解条目中的"⚡ APIG 文档差异"备注。

### 兼容性标识说明

- ✅ **完全兼容**：Higress 原生支持，可直接使用
- 🔵 **可等价替换**：通过插件或其他配置方式实现相同功能
- ❌ **不兼容**：由于架构差异无法支持
- ⚠️ **部分兼容**：语义不完全一致，部分值/场景可用但有缺口
- 🔴 **无需迁移**：Envoy 架构天然覆盖或功能已过时，迁移时直接忽略

---

## 按功能分类的注解兼容性

### 1. 路由与重写(8 个)

| 序号 | 注解名称                                            | 兼容情况 | 功能说明                                                    | 优先级         | 等价方法或说明                                                                                                                                |
| ---- | --------------------------------------------------- | -------- | ----------------------------------------------------------- | -------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| 1    | nginx.ingress.kubernetes.io/rewrite-target          | ✅        | 重写请求路径,将匹配的 URL 路径重写为指定目标路径            | 重要且常用     | API 网关核心功能,前后端分离、微服务路由必备。直接使用原注解,或使用 `higress.io/rewrite-target`                                                |
| 2    | nginx.ingress.kubernetes.io/use-regex               | ✅        | 启用路径正则表达式匹配,配合 rewrite-target 实现复杂路径重写 | 重要且常用     | rewrite-target 的必要配置项,用于灵活路径匹配。直接使用原注解,或使用 `higress.io/use-regex`。⚠️ **路由优先级差异**：NGINX 中优先级为 `exact > regex > prefix`（相同类型按创建时间排序）,Higress 中优先级为 `exact > prefix > regex`（相同类型按路径长度倒序）。这意味着在 NGINX 中 regex 路径优先于 prefix 路径,但迁移到 Higress 后 prefix 路径优先级更高,可能导致流量路由到不同后端。迁移时需检查同一 host 下是否存在 regex 路径与 prefix 路径的优先级冲突                                                    |
| 3    | nginx.ingress.kubernetes.io/upstream-vhost          | ✅        | 修改转发到后端服务的 Host 请求头,用于后端虚拟主机路由       | 重要但不常用   | 后端多租户、虚拟主机场景需要。已在 rewrite.go 验证,或使用 `higress.io/upstream-vhost`                                                         |
| 4    | nginx.ingress.kubernetes.io/app-root                | ✅        | 访问根路径时自动重定向到指定路径,常用于 SPA 应用            | 不重要但常用   | 前端应用默认路由配置。直接使用原注解(已在 redirect.go 验证),或使用 `higress.io/app-root`                                                      |
| 5    | nginx.ingress.kubernetes.io/preserve-trailing-slash | 🔵        | 保留 URL 末尾的斜杠,避免重定向导致请求方法变更              | 不重要且不常用 | 通过 Ingress `pathType: Exact` 实现精确匹配(含尾斜杠),或使用 `pathType: Prefix` 自动处理尾斜杠。无需特殊注解                                  |
| 6    | nginx.ingress.kubernetes.io/proxy-redirect-from     | 🔵        | 修改后端 302/301 响应中 Location 头的源 URL 匹配模式        | 不重要且不常用 | 后端重定向 URL 改写场景,使用较少。使用 WasmPlugin `transformer`,通过 `respRules.replace` 操作配合 `path_pattern` 正则匹配实现 Location 头改写 |
| 7    | nginx.ingress.kubernetes.io/proxy-redirect-to       | 🔵        | 修改后端 302/301 响应中 Location 头的目标 URL               | 不重要且不常用 | 与 proxy-redirect-from 配合使用。使用 WasmPlugin `transformer`,通过 `respRules.replace.newValue` 设置新的 Location 值                         |
| 8    | nginx.ingress.kubernetes.io/x-forwarded-prefix      | 🔵        | 在请求头中添加 X-Forwarded-Prefix,告知后端原始请求路径前缀  | 不重要但常用   | 微服务需要获取原始路径前缀时必需,如基于路径的多租户。通过 `higress.io/request-header-control-add` 实现                                        |

### 2. 重定向(8 个)

| 序号 | 注解名称                                            | 兼容情况 | 功能说明                                           | 优先级         | 等价方法或说明                                                                                                     |
| ---- | --------------------------------------------------- | -------- | -------------------------------------------------- | -------------- | ------------------------------------------------------------------------------------------------------------------ |
| 1    | nginx.ingress.kubernetes.io/ssl-redirect            | ✅        | HTTP 自动重定向到 HTTPS,提升安全性                 | 重要且常用     | 生产环境强制 HTTPS 的标准做法,安全合规必需。直接使用原注解,或使用 `higress.io/ssl-redirect`                        |
| 2    | nginx.ingress.kubernetes.io/force-ssl-redirect      | ✅        | 强制 SSL 重定向,即使 Ingress 未配置 TLS            | 重要但不常用   | 配合负载均衡器 SSL 卸载场景,确保内部流量也重定向。直接使用原注解,或使用 `higress.io/force-ssl-redirect`            |
| 3    | nginx.ingress.kubernetes.io/permanent-redirect      | ✅        | 永久重定向(301)到指定 URL,用于域名迁移、URL 规范化 | 不重要但常用   | 域名变更、SEO 优化场景。直接使用原注解,或使用 `higress.io/permanent-redirect`                                      |
| 4    | nginx.ingress.kubernetes.io/permanent-redirect-code | ✅        | 自定义永久重定向状态码(默认 301,可改为 308)        | 不重要且不常用 | 需要保持请求方法(POST 不变为 GET)时使用。直接使用原注解,或使用 `higress.io/permanent-redirect-code`                |
| 5    | nginx.ingress.kubernetes.io/temporal-redirect       | ✅        | 临时重定向(302)到指定 URL,用于临时维护、A/B 测试   | 不重要但常用   | 临时性流量切换、灰度场景。直接使用原注解,或使用 `higress.io/temporal-redirect`                                     |
| 6    | nginx.ingress.kubernetes.io/temporal-redirect-code  | ❌        | 自定义临时重定向状态码(默认 302,可改为 307)        | 不重要且不常用 | NGINX 中用于自定义临时重定向状态码(如 307 保持请求方法)。Higress 不支持:redirect.go 中 temporal-redirect 硬编码为 302,未实现 temporal-redirect-code 注解的解析,无法自定义临时重定向状态码。 |
| 7    | nginx.ingress.kubernetes.io/from-to-www-redirect    | 🔵        | 自动在带 www 和不带 www 域名间重定向               | 不重要且不常用 | NGINX 中自动在 www 和非 www 域名间重定向。Higress 源码中未实现此注解,但可通过 `higress.io/permanent-redirect` 配合多 Ingress 规则实现等价效果 |
| 8    | nginx.ingress.kubernetes.io/server-alias            | ⚠️        | 为 Ingress 配置域名别名                            | 不重要但常用   | Higress 原生支持此注解,但不支持正则表达式域名别名。 |

### 3. CORS 跨域(7 个)

| 序号 | 注解名称                                           | 兼容情况 | 功能说明                                            | 优先级       | 等价方法或说明                                                                                               |
| ---- | -------------------------------------------------- | -------- | --------------------------------------------------- | ------------ | ------------------------------------------------------------------------------------------------------------ |
| 1    | nginx.ingress.kubernetes.io/enable-cors            | ✅        | 启用 CORS 跨域资源共享,允许前端跨域请求             | 重要且常用   | 前后端分离架构必备,前端 SPA 调用后端 API 必需。直接使用原注解,或使用 `higress.io/enable-cors`                |
| 2    | nginx.ingress.kubernetes.io/cors-allow-origin      | ✅        | 指定允许的跨域源域名,支持通配符 * 或具体域名列表    | 重要且常用   | CORS 安全控制核心配置,生产环境应明确指定域名避免使用 *。直接使用原注解,或使用 `higress.io/cors-allow-origin` |
| 3    | nginx.ingress.kubernetes.io/cors-allow-methods     | ✅        | 指定允许的 HTTP 方法(GET, POST, PUT, DELETE 等)     | 重要且常用   | RESTful API 必需,控制允许的操作类型。直接使用原注解,或使用 `higress.io/cors-allow-methods`                   |
| 4    | nginx.ingress.kubernetes.io/cors-allow-headers     | ✅        | 指定允许的请求头(如 Content-Type, Authorization)    | 重要且常用   | 自定义请求头场景必需(如 JWT 认证、自定义 API Key)。直接使用原注解,或使用 `higress.io/cors-allow-headers`     |
| 5    | nginx.ingress.kubernetes.io/cors-allow-credentials | ✅        | 是否允许发送 Cookie 和认证信息,对应 withCredentials | 重要但不常用 | 需要携带 Cookie 的跨域请求(如 Session 认证)。直接使用原注解,或使用 `higress.io/cors-allow-credentials`       |
| 6    | nginx.ingress.kubernetes.io/cors-expose-headers    | ✅        | 指定允许前端访问的响应头(如自定义头)                | 不重要但常用 | 后端自定义响应头需要前端读取时必需。直接使用原注解,或使用 `higress.io/cors-expose-headers`                   |
| 7    | nginx.ingress.kubernetes.io/cors-max-age           | ✅        | 预检请求(OPTIONS)缓存时间(秒),减少 OPTIONS 请求数量 | 不重要但常用 | 优化 CORS 性能,减少额外请求开销。直接使用原注解,或使用 `higress.io/cors-max-age`                             |

### 4. 灰度发布/金丝雀(8 个)

| 序号 | 注解名称                                             | 兼容情况 | 功能说明                                        | 优先级         | 等价方法或说明                                                                                            |
| ---- | ---------------------------------------------------- | -------- | ----------------------------------------------- | -------------- | --------------------------------------------------------------------------------------------------------- |
| 1    | nginx.ingress.kubernetes.io/canary                   | ✅        | 启用金丝雀发布功能,将流量按条件分配到不同版本   | 重要且常用     | 灰度发布、A/B 测试的必备功能,降低发布风险。直接使用原注解,或使用 `higress.io/canary`                      |
| 2    | nginx.ingress.kubernetes.io/canary-weight            | ✅        | 按权重比例分配流量(0 至 weight-total),用于通用灰度发布 | 重要且常用     | 最常用的灰度方式,逐步增加新版本流量。权重范围为 0 到 canary-weight-total(默认 100)。直接使用原注解,或使用 `higress.io/canary-weight` |
| 3    | nginx.ingress.kubernetes.io/canary-by-header         | ✅        | 根据请求头值分配流量,用于内部测试、特定用户灰度 | 重要且常用     | 精准控制特定用户群体验,内部验证理想方式。直接使用原注解,或使用 `higress.io/canary-by-header`              |
| 4    | nginx.ingress.kubernetes.io/canary-by-header-value   | ✅        | 指定 header 的匹配值,配合 canary-by-header 使用 | 重要且常用     | header 精确匹配场景。直接使用原注解,或使用 `higress.io/canary-by-header-value`                            |
| 5    | nginx.ingress.kubernetes.io/canary-by-header-pattern | ✅        | 使用正则表达式匹配 header 值,更灵活的灰度控制   | 重要但不常用   | header 模式匹配场景,支持复杂规则。直接使用原注解,或使用 `higress.io/canary-by-header-pattern`             |
| 6    | nginx.ingress.kubernetes.io/canary-by-cookie         | ✅        | 根据 Cookie 值(always/never)分配流量,用于定向灰度 | 重要但不常用   | 通过 Cookie 值精确控制是否路由到金丝雀版本(always 路由、never 不路由,其他值忽略)。直接使用原注解,或使用 `higress.io/canary-by-cookie` |
| 7    | nginx.ingress.kubernetes.io/canary-weight-total      | ✅        | 指定金丝雀权重计算基数(默认 100),用于精细权重控制 | 不重要且不常用 | 用于更精细的权重控制(如 canary-weight-total=1000 + canary-weight=5 实现 0.5% 灰度)。注意:NGINX Ingress 仍限制每条 Ingress rule 最多一个 canary Ingress,不支持多金丝雀。Higress 支持 |
| 8    | nginx.ingress.kubernetes.io/affinity-canary-behavior | ✅        | 金丝雀与会话保持的交互行为(sticky/legacy)       | 不重要且不常用 | NGINX Ingress 标准注解,控制启用会话保持时金丝雀的行为:"sticky"(默认)表示被金丝雀服务处理的用户继续走金丝雀,"legacy"恢复旧行为(忽略会话亲和性)。Higress 源码中已定义此注解(loadbalance.go),注释标注行为始终为 legacy |

### 5. 认证与授权(27 个)

#### 5.1 外部认证 External Auth(11 个)

| 序号 | 注解名称                                                          | 兼容情况 | 功能说明                                             | 优先级         | 等价方法或说明                                                                                                                                    |
| ---- | ----------------------------------------------------------------- | -------- | ---------------------------------------------------- | -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1    | nginx.ingress.kubernetes.io/auth-url                              | 🔵        | 外部认证服务 URL,请求转发前先调用认证接口            | 重要且常用     | ⚠️ 源码核实：Higress 控制面未实现此注解的解析（代码库中无 `auth-url` 处理逻辑），不存在 `higress.io/auth-url` 注解。需通过 ext-auth WASM 插件的 `forward_auth` 模式配置 WasmPlugin CRD 实现等价功能，不支持注解级透明迁移 |
| 2    | nginx.ingress.kubernetes.io/auth-signin                           | ❌        | 认证失败后重定向的登录页面 URL                       | 重要但不常用   | 📋 仅在正文"External Authentication"章节描述，未列入顶部索引表。⚠️ 源码核实：Higress 控制面未实现此注解的解析，不存在 `higress.io/auth-signin` 注解。ext-auth WASM 插件也不支持认证失败后重定向到登录页的功能，无法实现。注：仅 Web 页面 SSO 场景需要登录页重定向，API 网关场景直接返回 401 即可，实际使用面窄于 auth-url |
| 3    | nginx.ingress.kubernetes.io/auth-response-headers                 | 🔵        | 将认证服务响应头转发给后端,传递用户信息              | 重要且常用     | 📋 仅在正文"External Authentication"章节描述，未列入顶部索引表。⚠️ 源码核实：Higress 控制面未实现此注解的解析，不存在 `higress.io/auth-response-headers` 注解。需通过 ext-auth WASM 插件的 `authorization_response.allowed_upstream_headers` 配置实现等价功能 |
| 4    | nginx.ingress.kubernetes.io/auth-proxy-set-headers                | 🔵        | 设置转发给认证服务的请求头                           | 重要但不常用   | 传递原始请求信息(IP、User-Agent)给认证服务,风控场景需要。需通过 ext-auth WASM 插件的 `authorization_request.headers_to_add` 配置实现等价功能      |
| 5    | nginx.ingress.kubernetes.io/auth-snippet                          | ❌        | 自定义认证逻辑 Lua 代码片段                          | 不重要且不常用 | Snippet 注解,Higress 不支持。大多数认证需求可通过 ext-auth WASM 插件满足,自定义认证逻辑场景很窄,需自定义 WASM 插件替代 |
| 6    | nginx.ingress.kubernetes.io/auth-method                           | 🔵        | 指定外部认证请求的 HTTP 方法                         | 不重要且不常用 | 📋 仅在正文"External Authentication"章节描述，未列入顶部索引表。⚠️ 源码核实：ext-auth WASM 插件的 `forward_auth` 模式支持通过 `endpoint.request_method` 配置认证请求的 HTTP 方法（GET/POST），可实现等价功能 |
| 7    | nginx.ingress.kubernetes.io/auth-signin-redirect-param            | ❌        | 认证失败重定向 URL 中的原始 URL 参数名               | 不重要且不常用 | 📋 仅在正文"External Authentication"章节描述，未列入顶部索引表。【v1.0.0+ 引入】NGINX 中用于指定 auth-signin 重定向 URL 中携带原始请求 URL 的查询参数名(默认为 `rd`),如 `?rd=https://original-url`。Higress ext-auth 插件不支持自定义重定向参数名 |
| 8    | nginx.ingress.kubernetes.io/auth-request-redirect                 | ❌        | 设置 X-Auth-Request-Redirect 头的值                  | 不重要且不常用 | 📋 仅在正文"External Authentication"章节描述，未列入顶部索引表。【v0.9.0+ 引入】NGINX 中用于设置发送给认证服务的 `X-Auth-Request-Redirect` 请求头值,告知认证服务原始请求的重定向目标。Higress ext-auth 插件不支持此头部的自定义设置 |
| 9    | nginx.ingress.kubernetes.io/auth-always-set-cookie                | ❌        | 是否始终设置认证服务返回的 Cookie                    | 不重要且不常用 | 📋 仅在正文"External Authentication"章节描述，未列入顶部索引表。【v1.1.0+ 引入】NGINX 中默认仅在认证服务返回 2xx/3xx 状态码时设置 Cookie,此注解设为 true 后始终设置。Higress ext-auth 插件不支持此行为控制 |
| 10   | nginx.ingress.kubernetes.io/auth-cache-duration                   | ❌        | 外部认证结果缓存时长,减少认证服务压力                | 不重要且不常用 | Higress ext-auth 插件不支持认证缓存功能,每次请求均实时调用外部认证服务,无法实现。注：NGINX Ingress 自身也是较晚引入的功能（v0.24.0+），实际使用率极低 |
| 11   | nginx.ingress.kubernetes.io/auth-cache-key                        | ❌        | 认证缓存的 key 计算方式                              | 不重要且不常用 | Higress ext-auth 插件不支持认证缓存功能,无法配置缓存 key,无法实现。注：依赖 auth-cache-duration，同样使用率极低                                    |

#### 5.2 Basic 认证(4 个)

| 序号 | 注解名称                                                          | 兼容情况 | 功能说明                                             | 优先级         | 等价方法或说明                                                                                                                                    |
| ---- | ----------------------------------------------------------------- | -------- | ---------------------------------------------------- | -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1    | nginx.ingress.kubernetes.io/auth-type                             | 🔵        | Basic Auth 类型配置                                  | 不重要但常用   | 可等价替换:通过 `basic-auth` WASM 插件实现完整的 Basic Auth 能力(Higress v2.0.0+ 推荐方式),插件支持多用户凭证管理、APR1 加密等,功能更完整。Digest 认证需开发自定义 WASM 插件 |
| 2    | nginx.ingress.kubernetes.io/auth-secret                           | 🔵        | Basic Auth 的用户名密码 Secret                       | 不重要但常用   | Higress 原生注解仅在 auth-type=basic 时有效。可等价替换:迁移到 `basic-auth` WASM 插件后,用户凭证通过插件配置管理(支持 APR1 加密密码),不再依赖 K8s Secret。Higress v2.0.0+ 推荐使用插件方式 |
| 3    | nginx.ingress.kubernetes.io/auth-secret-type                      | 🔵        | 指定认证 Secret 的类型(auth 或 opaque)               | 不重要且不常用 | ⚠️ 源码核实：Higress v2.0.0+ 控制面已移除 auth 注解的解析逻辑（auth.go 的 Parse 方法仅打印废弃日志后直接返回），不再支持平滑迁移。迁移到 `basic-auth` WASM 插件后，用户凭证通过插件配置的 `consumers[].credential` 字段直接管理（格式为 `username:password`），不再依赖 K8s Secret，因此 auth-secret-type 的概念不再适用。无需等价替换 |
| 4    | nginx.ingress.kubernetes.io/auth-realm                            | 🔵        | HTTP Basic Auth 的 realm 参数,浏览器认证弹窗提示文字 | 不重要但常用   | ⚠️ 源码核实：Higress v2.0.0+ 控制面已移除 auth 注解的解析逻辑，不再支持平滑迁移。`basic-auth` WASM 插件的 realm 值硬编码为 `"MSE Gateway"`（见 `protectionSpace` 变量），认证失败时返回 `WWW-Authenticate: Basic realm=MSE Gateway`，不支持通过配置自定义 realm。 |

#### 5.3 认证连接管理 Keepalive(4 个)

| 序号 | 注解名称                                                          | 兼容情况 | 功能说明                                             | 优先级         | 等价方法或说明                                                                                                                                    |
| ---- | ----------------------------------------------------------------- | -------- | ---------------------------------------------------- | -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1    | nginx.ingress.kubernetes.io/auth-keepalive                        | ❌        | 与认证服务的 keepalive 连接数                        | 不重要且不常用 | NGINX 中用于设置与外部认证服务之间的 keepalive 连接池大小,减少 TCP 连接建立开销。Higress 不支持:ext-auth WASM 插件使用 Envoy 的 HTTP 客户端发起认证请求,连接管理由 Envoy 集群配置控制,无法通过注解按 Ingress 粒度配置 keepalive 参数。Envoy 集群本身支持连接池配置,但 ext-auth 插件未暴露此配置项 |
| 2    | nginx.ingress.kubernetes.io/auth-keepalive-requests               | ❌        | keepalive 连接最大请求数                             | 不重要且不常用 | 控制单个 keepalive 连接可服务的最大请求数,超过后关闭连接重建。Higress 不支持:原因同 auth-keepalive,ext-auth 插件未暴露连接池配置 |
| 3    | nginx.ingress.kubernetes.io/auth-keepalive-share-vars             | ❌        | keepalive 连接是否共享变量                           | 不重要且不常用 | NGINX 特有概念,用于在原始请求和认证子请求之间共享 Nginx 变量(如 X-Request-ID)。Higress 不支持:这是 NGINX Lua 子请求的特有机制,Envoy 架构中不存在"子请求共享变量"的概念。ext-auth 插件通过 `headers_to_add` 配置可将指定请求头传递给认证服务,部分替代此功能 |
| 4    | nginx.ingress.kubernetes.io/auth-keepalive-timeout                | ❌        | 与认证服务的 keepalive 超时时间                      | 不重要且不常用 | 控制空闲 keepalive 连接的超时关闭时间。Higress 不支持:原因同 auth-keepalive,ext-auth 插件未暴露连接池超时配置 |

#### 5.4 mTLS 客户端证书认证(6 个)

| 序号 | 注解名称                                                          | 兼容情况 | 功能说明                                             | 优先级         | 等价方法或说明                                                                                                                                    |
| ---- | ----------------------------------------------------------------- | -------- | ---------------------------------------------------- | -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1    | nginx.ingress.kubernetes.io/auth-tls-secret                       | ⚠️        | 配置 mTLS 客户端证书验证的 CA 证书 Secret            | 重要但不常用   | 对应 `higress.io/auth-tls-secret`(已在 downstreamtls.go 验证)。部分兼容原因:CA Secret 名称必须与 TLS 证书 Secret 同名(或加 `-cacert` 后缀)且在同一 namespace,格式限制比 NGINX Ingress 更严格 |
| 2    | nginx.ingress.kubernetes.io/auth-tls-verify-client                | 🔵        | 是否启用客户端证书验证(on/off/optional)              | 重要但不常用   | mTLS 双向认证的必要配置,安全要求极高场景。通过 `higress.io/auth-tls-secret` 配置 CA 证书实现 mTLS 验证。相当于配置auth-tls-secret后,只有一个值:on |
| 3    | nginx.ingress.kubernetes.io/auth-tls-error-page                   | ❌        | mTLS 认证失败时的错误页面                            | 不重要且不常用 | NGINX 中用于在客户端证书验证失败时重定向到自定义错误页面,提升用户体验。Higress 不支持:downstreamtls.go 仅实现了 auth-tls-secret(CA 证书)和 ssl-cipher(加密套件)的解析,未实现错误页面重定向逻辑。Envoy 在 mTLS 验证失败时直接返回 TLS 握手错误,无法在 TLS 层面进行 HTTP 重定向。如需自定义错误响应,可通过 WASM 插件在 HTTP 层检测证书验证结果并返回自定义响应 |
| 4    | nginx.ingress.kubernetes.io/auth-tls-match-cn                     | 🔵        | mTLS 客户端证书 CN 匹配规则,用于细粒度权限控制       | 不重要且不常用 | NGINX 中用于对客户端证书的 CN(Common Name)进行正则匹配,不匹配则返回 403。Higress 可通过 EnvoyFilter 配置 `CertificateValidationContext` 的 `match_typed_subject_alt_names` 实现 SAN 匹配(支持精确匹配和前缀匹配),但注意 Envoy 匹配的是 SAN 而非 CN,语义略有差异。对于严格的 CN 匹配需求,可通过 WASM 插件读取 `x-forwarded-client-cert` 头中的证书信息进行自定义匹配 |
| 5    | nginx.ingress.kubernetes.io/auth-tls-pass-certificate-to-upstream | 🔵        | 是否将客户端证书传递给后端服务                       | 不重要且不常用 | NGINX 中将完整的客户端证书(PEM 格式)通过 `ssl-client-cert` 请求头传递给后端。Higress 可通过 EnvoyFilter 配置 HCM 的 `forward_client_cert_details` 为 `APPEND_FORWARD` 或 `SANITIZE_SET`,并配置 `set_current_client_cert_details` 启用证书信息转发。Envoy 使用 `x-forwarded-client-cert`(XFCC)头传递证书信息(包括 Cert、Chain、Hash、Subject、URI 等),格式与 NGINX 的 `ssl-client-cert` 头不同,后端服务需适配 XFCC 头格式 |
| 6    | nginx.ingress.kubernetes.io/auth-tls-verify-depth                 | 🔵        | mTLS 证书链验证深度                                  | 不重要且不常用 | NGINX 中用于设置客户端证书链的最大验证深度,默认为 1。Higress 可通过 EnvoyFilter 配置 `CertificateValidationContext` 的 `max_verify_depth` 字段实现,Envoy 默认验证深度为 100,语义与 NGINX 一致(不含叶子证书但含信任锚点)。配置方式:在 DownstreamTlsContext 的 `common_tls_context.validation_context` 中设置 `max_verify_depth` |

#### 5.5 认证策略与控制(2 个)

| 序号 | 注解名称                                                          | 兼容情况 | 功能说明                                             | 优先级         | 等价方法或说明                                                                                                                                    |
| ---- | ----------------------------------------------------------------- | -------- | ---------------------------------------------------- | -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1    | nginx.ingress.kubernetes.io/enable-global-auth                    | 🔵        | 是否启用全局认证,影响所有路由                        | 重要但不常用   | NGINX Ingress 中此注解控制某个 Ingress 是否启用全局外部认证(由 ConfigMap 中 `global-auth-url` 配置项定义的全局认证服务)。Higress 中各认证插件(key-auth、basic-auth、jwt-auth、ext-auth 等)均支持 `global_auth` 配置字段控制是否全局生效,且可在域名/路由级别通过 `allow` 列表精细控制。若用户使用的是 `auth-url` 外部认证场景,对应 ext-auth 插件;若使用 `auth-type: basic`,则对应 basic-auth 插件 |
| 2    | nginx.ingress.kubernetes.io/satisfy                               | ❌        | 多认证方式的满足条件(all/any)                        | 不重要且不常用 | NGINX 中用于控制多个认证模块(如 IP 白名单 + Basic Auth)的组合逻辑:"all" 要求全部通过,"any" 只需一个通过。Higress 不支持:Envoy 的认证模型与 NGINX 不同,各认证过滤器(ext-auth、basic-auth、IP 控制等)独立执行且均为"必须通过"语义,没有"any"模式的原生支持。如需实现"any"逻辑,需开发自定义 WASM 插件封装多种认证方式 |

### 6. SSL/TLS 配置(10 个)

| 序号 | 注解名称                                              | 兼容情况 | 功能说明                                   | 优先级         | 等价方法或说明                                                                                                           |
| ---- | ----------------------------------------------------- | -------- | ------------------------------------------ | -------------- | ------------------------------------------------------------------------------------------------------------------------ |
| 1    | nginx.ingress.kubernetes.io/ssl-passthrough           | ❌        | SSL/TLS 透传,不在网关层解密,直接传递到后端 | 重要但不常用   | Higress 源码中 `pkg/ingress/kube/annotations/` 未实现此注解的解析,Ingress 注解层面不支持 TLS 透传功能,不兼容 |
| 2    | nginx.ingress.kubernetes.io/ssl-ciphers               | 🔵        | 配置客户端到网关的 TLS 加密套件            | 重要但不常用   | ⚡ APIG 文档差异：APIG 文档使用 `ssl-cipher`（单数）标注"兼容",NGINX 官方注解名为 `ssl-ciphers`（复数）。Higress 通过 `higress.io/ssl-cipher`（单数）配置,功能等价但注解名称不同 |
| 3    | nginx.ingress.kubernetes.io/ssl-prefer-server-ciphers | 🔴       | 优先使用服务端加密套件顺序                 | 不重要且不常用 | 无需迁移:Envoy 底层使用 BoringSSL,默认行为即为服务端优先选择加密套件顺序,与 NGINX 设置 `ssl_prefer_server_ciphers on` 等价,无需额外配置 | 
| 4    | nginx.ingress.kubernetes.io/proxy-ssl-secret          | ✅        | 配置网关到后端的客户端证书(mTLS 到后端)    | 重要但不常用   | 后端要求客户端证书(内部服务 mTLS)时必需,但应用场景有限。直接使用原注解,或使用 `higress.io/proxy-ssl-secret`              |
| 5    | nginx.ingress.kubernetes.io/proxy-ssl-name            | ✅        | 指定后端 TLS 连接的 SNI 名称               | 重要但不常用   | 后端多域名证书场景必需,配合 HTTPS 后端使用。Higress 支持,后端 TLS SNI 名称                                               |
| 6    | nginx.ingress.kubernetes.io/proxy-ssl-server-name     | ✅        | 是否在后端 TLS 握手中发送 SNI              | 不重要但常用   | 配合 proxy-ssl-name 使用,HTTPS 后端常见配置。Higress 支持,是否在后端 TLS 握手中发送 SNI                                  |
| 7    | nginx.ingress.kubernetes.io/proxy-ssl-verify          | ✅        | 是否验证后端证书(on/off)                   | 重要但不常用   | 生产环境应验证后端证书防中间人攻击,但多数内部后端使用自签证书不验证。直接使用原注解(已在 upstreamtls.go 验证,支持 on/off),或使用 `higress.io/proxy-ssl-verify` |
| 8    | nginx.ingress.kubernetes.io/proxy-ssl-ciphers         | 🔵        | 配置网关到后端的 TLS 加密套件              | 不重要且不常用 | 后端 TLS 安全要求特殊场景,默认配置已够用。Higress 源码 upstreamtls.go 未实现此注解的解析,无 `higress.io/proxy-ssl-ciphers` 注解。需通过 EnvoyFilter 配置 UpstreamTlsContext 的 `common_tls_context.tls_params.cipher_suites` 字段实现 |
| 9    | nginx.ingress.kubernetes.io/proxy-ssl-protocols       | 🔵        | 配置网关到后端的 TLS 协议版本              | 重要但不常用   | 禁用不安全的旧协议(TLSv1.0/1.1),安全合规要求。Higress 源码 upstreamtls.go 未实现此注解的解析,无 `higress.io/proxy-ssl-protocols` 注解。需通过 EnvoyFilter 配置 UpstreamTlsContext 的 `common_tls_context.tls_params.tls_minimum_protocol_version` 和 `tls_maximum_protocol_version` 字段实现 |
| 10   | nginx.ingress.kubernetes.io/proxy-ssl-verify-depth    | 🔵        | 后端证书链验证深度                         | 不重要且不常用 | NGINX 中用于设置网关到后端 TLS 连接的证书链验证深度,默认为 1。Higress 可通过 EnvoyFilter 配置 UpstreamTlsContext 的 `common_tls_context.validation_context.max_verify_depth` 字段实现,Envoy 默认验证深度为 100。upstreamtls.go 中未实现此注解的解析,但 Envoy 底层完全支持此功能 |

### 7. 负载均衡与会话保持(15 个)

| 序号 | 注解名称                                                             | 兼容情况 | 功能说明                                                        | 优先级         | 等价方法或说明                                                                                                             |
| ---- | -------------------------------------------------------------------- | -------- | --------------------------------------------------------------- | -------------- | -------------------------------------------------------------------------------------------------------------------------- |
| 1    | nginx.ingress.kubernetes.io/load-balance                             | ⚠️        | 指定负载均衡算法(round_robin/least_conn/random/consistent_hash) | 重要且常用     | Higress 支持 ROUND_ROBIN、LEAST_REQUEST(对应 least_conn)、RANDOM、PASSTHROUGH 及一致性哈希。部分兼容:NGINX 的 `ewma`(Exponential Weighted Moving Average)算法不支持,Envoy/Istio 无对应实现 |
| 2    | nginx.ingress.kubernetes.io/upstream-hash-by                         | ⚠️        | 一致性哈希负载均衡的 hash key(如 $request_uri)                  | 重要且常用     | Higress 支持单个变量作为 hash key:`$http_*`(请求头)、`$arg_*`(查询参数)、`$request_uri`(映射为 `:path` header)、`$host`(映射为 `:authority` header)、`$remote_addr`(映射为 `useSourceIp`)。部分兼容,源码级限制:(1) 值必须以 `$` 开头,不以 `$` 开头的常量 hash key 会被静默忽略(NGINX 支持任意字符串);(2) 不支持多变量组合(如 `$request_uri$host`),组合值会依次尝试前缀匹配均失败后被静默忽略,不会报错;(3) 底层映射到 Istio `ConsistentHashLB` 的 oneof `HashKey`,只能选 `HttpHeaderName`/`HttpQueryParameterName`/`UseSourceIp` 之一,API 层面天然不支持组合 |
| 3    | nginx.ingress.kubernetes.io/affinity                                 | ✅        | 启用会话保持(cookie),将同一用户请求固定到同一后端               | 重要且常用     | 有状态应用、Session 不共享场景必需,传统应用迁移常用。直接使用原注解(已在 loadbalance.go 验证),或使用 `higress.io/affinity` |
| 4    | nginx.ingress.kubernetes.io/affinity-mode                            | ⚠️        | 会话保持模式(balanced:均衡/persistent:持久)                     | 重要但不常用   | 部分兼容:"balanced" 模式可用(默认行为),"persistent" 模式不支持 |
| 5    | nginx.ingress.kubernetes.io/session-cookie-name                      | ✅        | 会话 Cookie 名称                                                | 不重要但常用   | 自定义 Cookie 名称避免冲突,多服务共存场景需要。已在 loadbalance.go 验证                                                    |
| 6    | nginx.ingress.kubernetes.io/session-cookie-path                      | ✅        | 会话 Cookie 的 path 属性                                        | 不重要但常用   | 控制 Cookie 作用范围,多路径共存场景。已在 loadbalance.go 验证                                                              |
| 7    | nginx.ingress.kubernetes.io/session-cookie-domain                    | ❌        | 会话 Cookie 的 domain 属性                                      | 不重要但常用   | 跨子域名共享会话,多域名应用场景。Higress 不支持:loadbalance.go 中仅实现了 name/path/max-age/expires 四个 cookie 属性,Istio API v1.27 的 `ConsistentHashLB_HTTPCookie` 结构体只有 Name/Path/Ttl 三个字段,不包含 Domain。Istio 1.28 新增了 cookie attributes 支持(SameSite/Secure/HttpOnly),但仍未包含 Domain 属性 |
| 8    | nginx.ingress.kubernetes.io/session-cookie-max-age                   | ✅        | 会话 Cookie 有效期(秒)                                          | 不重要但常用   | 控制会话超时时间,安全和用户体验平衡。已在 loadbalance.go 验证                                                              |
| 9    | nginx.ingress.kubernetes.io/session-cookie-expires                   | ✅        | 会话 Cookie 过期时间(绝对时间)                                  | 不重要且不常用 | 与 max-age 二选一,max-age 更通用,特殊定时场景需要。已在 loadbalance.go 验证                                                |
| 10   | nginx.ingress.kubernetes.io/session-cookie-samesite                  | ❌        | Session cookie SameSite 属性(None/Lax/Strict)                   | 重要且常用     | CSRF 防护必需配置,现代浏览器安全要求。Higress 不支持:Higress 基于 Istio API v1.27,其 `ConsistentHashLB_HTTPCookie` 仅有 Name/Path/Ttl 字段,不支持 SameSite 属性。Istio 1.28 已新增 cookie attributes(SameSite/Secure/HttpOnly)支持,待 Higress 升级 Istio API 后可原生支持 |
| 11   | nginx.ingress.kubernetes.io/session-cookie-secure                    | ❌        | Session cookie Secure 属性(仅 HTTPS 传输)                       | 重要且常用     | HTTPS 环境必须启用防 cookie 泄露,安全合规必需。Higress 不支持:原因同 session-cookie-samesite,Istio API v1.27 的 HTTPCookie 不包含 Secure 属性。Istio 1.28 已新增支持,待 Higress 升级后可用 |
| 12   | nginx.ingress.kubernetes.io/session-cookie-change-on-failure         | 🔴        | 后端失败时是否更换 session cookie                               | 不重要且不常用 | 无需迁移。Envoy 的 outlier detection 和健康检查机制天然覆盖了此注解的核心诉求(后端故障时自动切换到健康节点)。实现路径不同:NGINX 通过更换 cookie  值让客户端下次请求路由到不同后端,Envoy 的一致性哈希在节点不可用时自动将请求路由到其他节点(cookie 值不变但路由目标改变),最终效果等效 |
| 13   | nginx.ingress.kubernetes.io/session-cookie-conditional-samesite-none | ❌        | 条件性设置 SameSite=None(兼容旧浏览器)                          | 不重要且不常用 | 浏览器兼容性处理,对不支持 SameSite=None 的旧浏览器(如 Chrome 5X、Safari on OSX 14)自动省略该属性。Higress 不支持:前提是 session-cookie-samesite 本身不支持,此注解自然也无法实现。即使未来 Higress 升级支持 SameSite 属性,此条件性逻辑也需要额外的 User-Agent 判断,可能需要 WASM 插件实现 |
| 14   | nginx.ingress.kubernetes.io/upstream-hash-by-subset               | ❌        | 启用一致性哈希的 subset 模式                                     | 不重要且不常用 | 📋 仅在正文"Custom NGINX upstream hashing"章节描述，未列入顶部索引表。【v0.24.0+ 引入】NGINX 中设为 true 时,一致性哈希将请求映射到上游服务器子集而非单个服务器,在粘性和负载分布之间取得平衡。Higress 不支持:Envoy 的一致性哈希实现没有 subset 模式的概念,`ConsistentHashLB` 仅支持直接映射到单个端点 |
| 15   | nginx.ingress.kubernetes.io/upstream-hash-by-subset-size          | ❌        | 一致性哈希 subset 的大小,默认为 3                                | 不重要且不常用 | 📋 仅在正文"Custom NGINX upstream hashing"章节描述，未列入顶部索引表。【v0.24.0+ 引入】NGINX 中用于设置 upstream-hash-by-subset 模式下每个子集的服务器数量(默认 3)。Higress 不支持:前提是 upstream-hash-by-subset 本身不支持 |

### 8. 访问控制(2 个)

| 序号 | 注解名称                                           | 兼容情况 | 功能说明                                   | 优先级     | 等价方法或说明                                                                                                    |
| ---- | -------------------------------------------------- | -------- | ------------------------------------------ | ---------- | ----------------------------------------------------------------------------------------------------------------- |
| 1    | nginx.ingress.kubernetes.io/whitelist-source-range | ✅        | 配置 IP 白名单,仅允许指定 IP/CIDR 范围访问 | 重要且常用 | 安全防护第一道防线,管理后台/内部 API 必备,应用非常广泛。直接使用原注解,或使用 `higress.io/whitelist-source-range` |
| 2    | nginx.ingress.kubernetes.io/denylist-source-range  | 🔵        | 配置 IP 黑名单,禁止指定 IP/CIDR 范围访问   | 重要且常用 | ⚡ APIG 文档差异：APIG 文档标注"兼容"（要求网关版本 1.2.31）,即 Higress 1.2.31+ 已原生支持此注解。对于 1.2.31 以下版本,Higress 源码 ip_access_control.go 仅实现了 whitelist-source-range,可通过 ip-restriction WASM 插件的 deny 模式实现 IP 黑名单功能 |

### 9. 限流与限速(7 个)

| 序号 | 注解名称                                      | 兼容情况 | 功能说明                                         | 优先级       | 等价方法或说明                                                                                                  |
| ---- | --------------------------------------------- | -------- | ------------------------------------------------ | ------------ | --------------------------------------------------------------------------------------------------------------- |
| 1    | nginx.ingress.kubernetes.io/limit-rps         | 🔵        | 限制每秒请求数(RPS),防止 API 滥用、服务过载      | 重要且常用   | 生产环境必备的流量控制手段,保障服务稳定性,防恶意攻击。使用 Higress `key-rate-limit` 插件,配置 `limit_by_per_ip` |
| 2    | nginx.ingress.kubernetes.io/limit-connections | 🔵        | 限制并发连接数,防止慢速攻击(如慢速HTTP GET/POST) | 重要但不常用 | 防止连接耗尽攻击,安全防护重要手段,但应用场景比 RPS 限制少。Higress 现有限流插件(`key-rate-limit`/`cluster-key-rate-limit`)仅支持请求速率限制,不支持并发连接数限制。推荐通过 EnvoyFilter 配置 `envoy.filters.network.connection_limit` 限制下游入站并发连接数(与 NGINX 语义一致);也可通过 DestinationRule 的 `trafficPolicy.connectionPool.tcp.maxConnections` 限制到上游的最大连接数 |
| 3    | nginx.ingress.kubernetes.io/limit-rpm         | 🔵        | 限制每分钟请求数(RPM),更粗粒度的限流控制         | 重要但不常用 | 📋 仅在正文"Rate Limiting"章节描述，未列入顶部索引表。【v0.24.0+ 引入】NGINX 中按每分钟请求数限流,突发限制为该值乘以 burst multiplier。Higress 可通过 `key-rate-limit` 插件配置等价的每分钟限流策略 |
| 4    | nginx.ingress.kubernetes.io/limit-burst-multiplier | ❌   | 限流突发倍数因子,默认为 5                        | 不重要且不常用 | 📋 仅在正文"Rate Limiting"章节描述，未列入顶部索引表。【v0.24.0+ 引入】NGINX 中用于设置 limit-rps/limit-rpm 的突发请求倍数(默认 5,即 limit-rps=10 时突发允许 50)。Higress 限流插件不支持配置突发倍数:C++ 版 `key-rate-limit` 使用令牌桶算法(桶容量=限流阈值,天然允许瞬时突发到桶容量,但无独立 burst 参数);Go 版 `cluster-key-rate-limit` 使用 Redis 固定窗口计数器,完全没有突发概念。迁移时此注解直接忽略 |
| 5    | nginx.ingress.kubernetes.io/limit-rate-after  | ❌        | 响应传输速率限制的起始字节数                     | 不重要且不常用 | 📋 仅在正文"Rate Limiting"章节描述，未列入顶部索引表。【v0.24.0+ 引入】NGINX 中用于设置在传输指定字节数后开始限制响应速率(配合 limit-rate 使用,需启用 proxy-buffering)。Higress 不支持:Envoy 采用流式(streaming)架构,数据从上游到达后经 filter chain 逐步转发给下游,没有 NGINX 那种"缓存完整响应再限速发送"的 proxy-buffering 机制,因此按连接的响应传输速率限制无法实现。Envoy 的 `per_connection_buffer_limit_bytes` 和 Buffer filter 仅用于流控和请求缓冲,语义完全不同 |
| 6    | nginx.ingress.kubernetes.io/limit-rate        | ❌        | 响应传输速率限制(KB/s)                           | 不重要且不常用 | 📋 仅在正文"Rate Limiting"章节描述，未列入顶部索引表。【v0.24.0+ 引入】NGINX 中用于限制每个连接的响应传输速率(单位 KB/s,0 表示不限制,需启用 proxy-buffering)。Higress 不支持:Envoy 天然采用流式转发架构,没有 NGINX 的"缓存响应+限速发送"模型(proxy-buffering)。NGINX 的 proxy-buffering 是先将上游响应完整缓存到内存/磁盘再按指定速率发给客户端,而 Envoy 收到上游数据后即刻转发,不存在按连接的响应速率限制功能 |
| 7    | nginx.ingress.kubernetes.io/limit-whitelist   | 🔵        | 限流白名单 CIDR 列表                             | 不重要且不常用 | 📋 仅在正文"Rate Limiting"章节描述，未列入顶部索引表。【v0.24.0+ 引入】NGINX 中用于指定不受限流约束的客户端 IP CIDR 列表。可通过 `cluster-key-rate-limit` 插件的 `limit_by_per_ip` 等价替换：为白名单 CIDR 配置极大的限流阈值（如 `query_per_second: 1000000`），兜底 `0.0.0.0/0` 配置正常阈值，`limit_keys` 按顺序匹配，白名单 CIDR 放前面即可实现"白名单 IP 不受限流约束"的语义。注意：C++ 版 `key-rate-limit` 插件仅支持 `limit_by_header`/`limit_by_param`，不支持按 IP/CIDR 限流，需使用 Go 版 `cluster-key-rate-limit` 插件（依赖 Redis） |

### 10. 后端服务配置(19 个)

| 序号 | 注解名称                                                | 兼容情况 | 功能说明                                | 优先级         | 等价方法或说明                                                                                                                             |
| ---- | ------------------------------------------------------- | -------- | --------------------------------------- | -------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| 1    | nginx.ingress.kubernetes.io/backend-protocol            | ⚠️        | 指定后端协议类型(HTTP/HTTPS/GRPC/GRPCS) | 重要且常用     | Higress 支持 HTTP/HTTP2/HTTPS/GRPC/GRPCS 五种协议,但不支持 NGINX Ingress 的 AJP 和 FCGI 协议。部分兼容:绝大多数场景(HTTP/HTTPS/gRPC)完全可用,仅 AJP(Tomcat)和 FastCGI(PHP-FPM)场景不支持 |
| 2    | nginx.ingress.kubernetes.io/proxy-body-size             | 🔴        | 限制请求体大小,防止大文件上传滥用资源   | 重要且常用     | 迁移时可安全忽略。此注解在 NGINX 中的核心作用是保护网关自身——NGINX 架构为"先收完请求体再转发",超大请求体会直接吃掉 worker 内存/磁盘,因此需要主动拒绝。而 Envoy 采用流式转发架构,数据到达后逐块转发,单个连接内存占用上界仅为 `per_connection_buffer_limit_bytes`(默认 32KB),不管请求体多大都不会导致内存爆炸,因此从"保护网关"角度该限制不再必要。如需全局调整连接缓冲,可通过 `higress-config` 的 `downstream.connectionBufferLimits` 配置。对于少数确需在网关层拦截超大请求的业务场景(不想让流量到达后端),可通过 WasmPlugin 在 `OnHttpRequestHeaders` 阶段检查 `Content-Length` 或在 `OnHttpRequestBody` 阶段累计 body 大小,超限返回 413 实现路由粒度的请求体限制 |
| 3    | nginx.ingress.kubernetes.io/proxy-connect-timeout       | 🔵        | 连接后端超时时间                        | 重要但不常用   | NGINX 中仅控制 TCP 连接建立超时。Higress 替代方式：①通过 EnvoyFilter 配置 cluster 的 `connect_timeout` 字段（语义完全一致，默认 5s）；②通过 DestinationRule 的 `trafficPolicy.connectionPool.tcp.connectTimeout` 实现（Istio API 声明式配置）。注意：`higress.io/timeout` 是端到端请求总超时（route 级别，默认 15s），语义不同于 NGINX 的连接建立超时，仅在不需要精确区分连接/读写超时的简单场景下可作为粗粒度替代 |
| 4    | nginx.ingress.kubernetes.io/proxy-read-timeout          | 🔵        | 从后端读取响应超时时间                  | 重要且常用     | 后端处理耗时请求(AI、报表)必需,应用非常广泛。通过 `higress-config` ConfigMap 中 `upstream.idleTimeout` 实例级配置替代                      |
| 5    | nginx.ingress.kubernetes.io/proxy-send-timeout          | 🔵        | 向后端发送请求超时时间                  | 不重要但常用   | 大文件上传场景,配合 proxy-body-size 使用。通过 `higress-config` ConfigMap 中 `upstream.idleTimeout` 实例级配置替代                         |
| 6    | nginx.ingress.kubernetes.io/proxy-next-upstream         | ✅        | 配置重试条件(哪些错误码触发重试)        | 重要且常用     | 高可用保障,自动失败转移,微服务常见配置。Higress 支持,重试条件配置                                                                          |
| 7    | nginx.ingress.kubernetes.io/proxy-next-upstream-timeout | ✅        | 重试总超时时间,防止无限重试             | 重要且常用     | 配合 proxy-next-upstream 使用,防止重试雪崩。Higress 支持,重试超时配置                                                                      |
| 8    | nginx.ingress.kubernetes.io/proxy-next-upstream-tries   | ✅        | 重试最大次数,防止无限重试               | 重要且常用     | 配合 proxy-next-upstream 使用,控制重试资源消耗。直接使用原注解,或使用 `higress.io/proxy-next-upstream-tries`                               |
| 9    | nginx.ingress.kubernetes.io/proxy-http-version          | ⚠️        | 指定后端 HTTP 协议版本(1.0/1.1/2.0)     | 重要但不常用   | NGINX 中用于指定网关到后端的 HTTP 协议版本,支持 1.0、1.1、2.0。部分兼容原因:Envoy 向后端只支持 HTTP/1.1(默认)和 HTTP/2,不支持 HTTP/1.0。HTTP/2 可通过 `backend-protocol: GRPC/GRPCS` 启用。配置值为 `"1.1"` 或 `"2.0"` 时可兼容,`"1.0"` 无法实现,但实际需要 HTTP/1.0 的后端极为罕见 |
| 10   | nginx.ingress.kubernetes.io/service-upstream            | 🔴        | 是否直接使用 Service 而非 Endpoints     | 不重要且不常用 | Higress 默认通过 EDS 直接路由到 Endpoints(Pod IP),这本身就是更优的做法(跳过 kube-proxy,性能更好)。迁移时直接删除此注解即可,不会有功能缺失 |
| 11   | nginx.ingress.kubernetes.io/proxy-cookie-domain         | 🔵        | 修改响应 Cookie 的 Domain 属性          | 不重要且不常用 | Higress 源码中未实现此注解的解析。可通过 WasmPlugin(transformer 插件)或 EnvoyFilter 修改响应头中 Set-Cookie 的 Domain 属性实现等价替换 |
| 12   | nginx.ingress.kubernetes.io/proxy-cookie-path           | 🔵        | 修改响应 Cookie 的 Path 属性            | 不重要且不常用 | Higress 源码中未实现此注解的解析。可通过 WasmPlugin(transformer 插件)或 EnvoyFilter 修改响应头中 Set-Cookie 的 Path 属性实现等价替换 |
| 13   | nginx.ingress.kubernetes.io/client-body-buffer-size     | ❌        | 客户端请求体缓冲区大小                  | 不重要且不常用 | NGINX 中用于设置读取客户端请求体的缓冲区大小,超出后写入磁盘临时文件,可按 Ingress 粒度配置。Higress 不兼容原因:①Envoy 不会将请求体写入磁盘,全部在内存中处理,通过 `per_connection_buffer_limit_bytes` 控制连接级缓冲上限;②仅支持通过 `higress-config` 的 `downstream.connectionBufferLimits`(默认 32768)全局配置,无法按 Ingress 粒度设置;③语义不对等,NGINX 控制的是"请求体缓冲区大小",Envoy 控制的是"连接级读写缓冲区总限制" |
| 14   | nginx.ingress.kubernetes.io/proxy-buffering             | 🔴        | 启用/禁用后端响应缓冲                   | 不重要且不常用 | NGINX 的 proxy-buffering 控制反向代理对上游响应的缓冲行为:开启时(默认)先将上游响应完整缓存到内存/磁盘再发给客户端,上游连接可快速释放;关闭时收到数据立即转发(streaming),适用于 SSE/长轮询场景。Envoy 架构根本没有 NGINX 这种 proxy-buffering 的等价机制——Envoy 天然就是流式转发的,数据从上游到达后经 filter chain 逐步转发给下游,不会"攒够了再发"。Envoy 的 Buffer filter 仅用于请求方向的缓冲,`per_connection_buffer_limit_bytes` 是 L4 层流控(默认 1MB),语义完全不同。因此 SSE/长轮询等场景在 Envoy 上天然可用,迁移时直接删除此注解即可 |
| 15   | nginx.ingress.kubernetes.io/proxy-buffer-size           | 🔴        | 后端响应缓冲区大小                      | 不重要且不常用 | NGINX 中用于设置读取后端响应第一部分(通常是响应头)的缓冲区大小。Envoy 响应头处理机制不同,默认配置已够用,不会因缺少此配置导致问题,迁移时直接删除即可 |
| 16   | nginx.ingress.kubernetes.io/proxy-buffers-number        | ❌        | 后端响应缓冲区数量                      | 不重要且不常用 | Higress 全局配置 `upstream.connectionBufferLimits` 可控制上游连接级缓冲限制(默认 10485760),但语义不同(总大小 vs 缓冲区数量)                |
| 17   | nginx.ingress.kubernetes.io/proxy-busy-buffers-size     | 🔴        | 繁忙状态缓冲区大小                      | 不重要且不常用 | NGINX 内部优化参数,控制响应尚未完全读取时可向客户端发送数据的缓冲区大小。Envoy 流式架构天然不需要此概念,数据到达即转发,迁移时直接删除即可 |
| 18   | nginx.ingress.kubernetes.io/proxy-max-temp-file-size    | 🔴        | 缓冲临时文件最大大小                    | 不重要且不常用 | NGINX 中响应体超过内存缓冲区时写入磁盘临时文件,此注解控制临时文件最大大小。Envoy 完全不使用磁盘缓冲,不存在此问题,迁移时直接删除即可 |
| 19   | nginx.ingress.kubernetes.io/proxy-request-buffering     | 🔴        | 启用/禁用请求缓冲                       | 不重要且不常用 | NGINX 中控制是否缓冲完整请求体再转发后端。Envoy 的请求处理方式不同,默认行为已满足大文件上传等场景需求,迁移时直接删除即可 |

### 11. 请求/响应头控制(2 个)

| 序号 | 注解名称                                            | 兼容情况 | 功能说明                                 | 优先级     | 等价方法或说明                                                                                                                                   |
| ---- | --------------------------------------------------- | -------- | ---------------------------------------- | ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| 1    | nginx.ingress.kubernetes.io/custom-headers          | 🔵        | 自定义请求/响应头,添加/修改/删除 HTTP 头 | 重要且常用 | 微服务间传递上下文(trace-id、user-id)、安全头配置(CSP、HSTS)必需。NGINX 中此注解引用一个 ConfigMap（格式 `namespace/configmap-name`）,ConfigMap 的 key-value 作为请求头添加到所有代理请求。Higress 不支持 ConfigMap 引用模式,改为在 Ingress 注解中直接内联声明头部操作：`higress.io/request-header-control-add`（追加头部）、`request-header-control-update`（覆盖已有头部）、`request-header-control-remove`（删除头部）,响应头同理使用 `response-header-control-*` 系列。迁移时需将 ConfigMap 中的 key-value 逐行写入注解值（每行格式 `header-name header-value`）。详见 [迁移指南 §6.1 头部控制迁移](./migration-guide.md#61-头部控制迁移替代-custom-headers--auth-proxy-set-headers--x-forwarded-prefix) |
| 2    | nginx.ingress.kubernetes.io/connection-proxy-header | 🔴        | 修改代理连接头                           | -          | NGINX Ingress Controller 官方注解,用于覆盖 NGINX 默认的 `proxy_set_header Connection ""`,常见用法如设为 `keep-alive` 以确保到后端的长连接。Envoy 作为 L7 代理,按 RFC 7230 规范自动处理 Connection 等 hop-by-hop 头,不会向 upstream 转发;且 Envoy 连接池默认即为 keep-alive,无需通过 Connection 头控制,直接忽略即可 |

### 12. 错误处理(2 个)

| 序号 | 注解名称                                       | 兼容情况 | 功能说明                           | 优先级       | 等价方法或说明                                                                          |
| ---- | ---------------------------------------------- | -------- | ---------------------------------- | ------------ | --------------------------------------------------------------------------------------- |
| 1    | nginx.ingress.kubernetes.io/custom-http-errors | ✅        | 自定义 HTTP 错误响应码的处理逻辑   | 重要但不常用 | 统一错误页面、用户体验优化,但应用场景有限。直接使用原注解(已在 default_backend.go 验证) |
| 2    | nginx.ingress.kubernetes.io/default-backend    | ✅        | 指定默认后端服务(无匹配路由时使用) | 重要但不常用 | 全局 404 页面、备用服务,但应用场景不多。Higress 支持,指定默认后端服务                   |

### 13. 流量镜像(3 个)

| 序号 | 注解名称                                        | 兼容情况 | 功能说明                       | 优先级         | 等价方法或说明                                                                          |
| ---- | ----------------------------------------------- | -------- | ------------------------------ | -------------- | --------------------------------------------------------------------------------------- |
| 1    | nginx.ingress.kubernetes.io/mirror-target       | 🔵        | 配置流量镜像目标后端服务       | 重要但不常用   | NGINX 中通过 URL 形式(如 `https://test.env.com$request_uri`)指定镜像目标。Higress 使用不同的注解名称实现相同功能:`higress.io/mirror-target-service`(K8s Service 引用,格式为 `serviceName:port`)或 `higress.io/mirror-target-fqdn`(FQDN 形式),配合 `higress.io/mirror-percentage` 控制镜像比例。已在 mirror.go 中验证实现,功能完全可达,仅注解名称和参数格式不同 |
| 2    | nginx.ingress.kubernetes.io/mirror-host         | ❌        | 配置镜像请求的 Host 头         | 不重要但常用   | NGINX 中用于覆盖镜像请求的 Host 头(默认使用 mirror-target URL 中的 host 部分)。Higress 不支持:mirror.go 实现中,镜像请求的 Host 由 `mirror-target-fqdn` 或 Service FQDN 决定,没有独立的 Host 覆盖机制。Envoy 的 `route.mirror` 配置中也没有单独设置镜像请求 Host 的字段。如需修改镜像请求的 Host,需通过 EnvoyFilter 或 WASM 插件实现 |
| 3    | nginx.ingress.kubernetes.io/mirror-request-body | 🔴        | 是否同时镜像请求体(默认不镜像) | 不重要且不常用 | NGINX 中默认镜像请求体(`mirror_request_body on`),可通过此注解设为 `off` 关闭。Envoy 的流量镜像机制天然包含完整请求(含请求体),且没有"不镜像请求体"的选项。由于 Envoy 始终镜像完整请求,此注解的"关闭请求体镜像"功能无法实现,但默认行为(镜像请求体)与 NGINX 默认行为一致,绝大多数使用场景不受影响。迁移时直接删除即可 |

### 14. 安全防护(4 个)

| 序号 | 注解名称                                               | 兼容情况 | 功能说明                               | 优先级     | 等价方法或说明                                                                            |
| ---- | ------------------------------------------------------ | -------- | -------------------------------------- | ---------- | ----------------------------------------------------------------------------------------- |
| 1    | nginx.ingress.kubernetes.io/enable-modsecurity         | 🔵        | 启用 ModSecurity WAF 引擎              | 重要且常用 | Web 应用安全防护必备,防SQL注入、XSS攻击,应用广泛。使用 Higress `waf` WASM 插件替代,该插件基于 Coraza 引擎（纯 Go 实现的 ModSecurity 兼容引擎），内置 SQL 注入/XSS 检测能力，编译为 WASM 运行在 Envoy 内部，无需外部服务依赖。配置 `useCRS: true` 即可启用 OWASP 核心规则集 |
| 2    | nginx.ingress.kubernetes.io/enable-owasp-core-rules    | 🔵        | 启用 OWASP 核心规则集防护常见 Web 攻击 | 重要且常用 | 应对 SQL 注入、XSS 等攻击,安全合规必备。Higress `waf` 插件已内嵌 OWASP CRS 规则集（通过 `@owasp_crs/*.conf` 加载），配置 `useCRS: true` 即可启用，无需额外下载或部署规则文件 |
| 3    | nginx.ingress.kubernetes.io/modsecurity-snippet        | ❌        | 自定义 ModSecurity 规则代码片段        | 不重要且不常用 | Snippet 注解,Higress 不支持。Higress `waf` 插件支持通过 `secRules` 字段传入自定义 SecRule 规则，可部分替代 snippet 场景，但不支持任意 ModSecurity 指令。大多数用户使用 OWASP 核心规则集即可满足需求 |
| 4    | nginx.ingress.kubernetes.io/modsecurity-transaction-id | ❌        | ModSecurity 事务 ID 配置               | 不重要且不常用 | Higress 底层为 Envoy，WAF 能力通过基于 Coraza 的 WASM 插件实现，无 ModSecurity 事务模型和审计日志体系，该注解无对应语义。如需请求级别的安全事件追踪，可结合 OpenTelemetry tracing 配置与 WAF 插件日志实现 |

### 15. 可观测性(4 个)

| 序号 | 注解名称                                                      | 兼容情况 | 功能说明                      | 优先级         | 等价方法或说明                                                                                                      |
| ---- | ------------------------------------------------------------- | -------- | ----------------------------- | -------------- | ------------------------------------------------------------------------------------------------------------------- |
| 1    | nginx.ingress.kubernetes.io/enable-opentelemetry              | ❌        | 启用 OpenTelemetry 追踪功能   | 重要但不常用   | 该注解的核心语义是 per-Ingress 粒度的 tracing 开关（某些路由开、某些路由关）。Higress 支持 OpenTelemetry tracing 能力本身（通过 `higress-config` 全局配置 `tracing.opentelemetry`），但 Envoy 的 tracing provider 配置在 HCM（listener）级别，无法按路由粒度开关，因此该注解的 per-Ingress 语义不可达 |
| 2    | nginx.ingress.kubernetes.io/opentelemetry-trust-incoming-span | ❌        | 是否信任上游传入的 trace span | 不重要且不常用 | 该注解控制是否信任上游传入的 trace context，属于 per-Ingress 粒度配置。Envoy 默认信任并传播 W3C Trace Context（traceparent/tracestate），行为不可按路由粒度调整，该注解语义不可达 |
| 3    | nginx.ingress.kubernetes.io/enable-access-log                 | 🔵        | 按 Ingress 粒度禁用访问日志   | 不重要且不常用 | NGINX 全局默认开启 access log,此注解设为 `"false"` 时在 location 块插入 `access_log off;` 关闭该路由的日志输出（常见场景：健康检查路由关闭日志减少噪音）；设为 `"true"` 或不设时沿用全局配置,无额外行为。Higress 源码中无对应 annotation parser,`higress-config` 也无访问日志相关字段。Envoy access log 配置在 HCM 级别,没有原生的按路由开关机制,必须通过 EnvoyFilter 在路由上打元数据标记（`filter_metadata`）,并在 HCM access_log 中配置 `metadata_filter` 过滤已标记路由,配置复杂度显著高于 NGINX 单注解方式,但功能可达 |
| 4    | nginx.ingress.kubernetes.io/enable-rewrite-log                | ❌        | 启用 rewrite 操作的调试日志   | 不重要且不常用 | NGINX 中会在 error log 中逐条输出 rewrite 规则的匹配过程(命中规则、重写前后路径),可按 Ingress 粒度开关。Envoy 完全没有对应的 rewrite 调试日志机制,调高全局日志级别虽能看到部分路由匹配信息,但在语义、粒度、输出格式上均不等价。排查 rewrite 问题可通过 accesslog 中 `%REQ(:PATH)%` 和 `%UPSTREAM_HOST%` 等字段间接验证 |

### 16. Snippet 配置(3 个)

| 序号 | 注解名称                                          | 兼容情况 | 功能说明                                | 优先级 | 等价方法或说明                                                                   |
| ---- | ------------------------------------------------- | -------- | --------------------------------------- | ------ | -------------------------------------------------------------------------------- |
| 1    | nginx.ingress.kubernetes.io/configuration-snippet | ❌        | 在 location 块注入自定义 NGINX 配置代码 | 重要且常用     | **安全风险**,Higress 不支持 snippet。NGINX Ingress 用户中使用非常广泛,是实现各种自定义逻辑的万能手段(加头、限流、Lua 逻辑等),迁移时必须逐个分析 snippet 内容,通过 WASM 插件或 Higress 内置插件组合替代 |
| 2    | nginx.ingress.kubernetes.io/server-snippet        | ❌        | 在 server 块注入自定义 NGINX 配置代码   | 重要但不常用   | **安全风险**,Higress 不支持 snippet。用于配置 server 级别行为(如自定义错误页、全局变量),使用频率低于 configuration-snippet。需 WASM 插件替代 |
| 3    | nginx.ingress.kubernetes.io/stream-snippet        | ❌        | 在 TCP/UDP stream 块注入配置代码        | 不重要且不常用 | TCP/UDP 代理场景才用,非常小众。Higress 不支持 snippet                                    |

### 17. 其他特性(1 个)

| 序号 | 注解名称                                       | 兼容情况 | 功能说明                           | 优先级 | 等价方法或说明                                                                        |
| ---- | ---------------------------------------------- | -------- | ---------------------------------- | ------ | ------------------------------------------------------------------------------------- |
| 1    | nginx.ingress.kubernetes.io/http2-push-preload | 🔴        | 启用 HTTP/2 Server Push 预加载资源 | -      | HTTP/2 Server Push 已被主流浏览器废弃(Chrome 106+ 移除),且性能优化效果不明显,直接忽略 |

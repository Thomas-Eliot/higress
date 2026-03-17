---
inclusion: manual
---

# NGINX Ingress 注解兼容性分析规范

本文档定义了分析 NGINX Ingress 注解在 Higress 中兼容性时的分类标准、分析思路和输出规范。适用于对 `ls-test/migration/summary-v3.md` 文档中注解的持续审视和更新。

## 兼容性分类标准（6 类）

### ✅ 完全兼容
Higress 原生支持，可直接使用 NGINX Ingress 原注解或对应的 `higress.io/*` 前缀注解，语义一致。

### 🔵 可等价替换
Higress 没有直接的注解兼容，但通过其他机制（WASM 插件、higress-config 全局配置、EnvoyFilter、header-control 注解等）可以实现相同功能。判断关键：功能可达，只是接口形式不同。

典型场景：
- NGINX 注解功能被 WASM 插件替代（如 auth-type → basic-auth 插件，enable-modsecurity → waf 插件）
- 通过 higress-config ConfigMap 全局配置实现（如 tracing、超时）
- 通过 header-control 系列注解组合实现（如 custom-headers、x-forwarded-prefix）
- 虽然粒度或配置复杂度有差异，但功能可达（如 enable-access-log 通过 accesslog filter 表达式实现）

### ❌ 不兼容
由于 Envoy 与 NGINX 的架构差异，存在真实的功能缺失，迁移时需要评估影响并寻找替代方案。判断关键：功能不可达或有明确缺口。

与 🔴 无需迁移的区别：不兼容意味着"功能缺失，可能需要想办法补"。

### ⚠️ 部分兼容
语义不完全一致，部分值/场景可用但有缺口。判断关键：功能部分可达，有明确的不支持子集。

示例：proxy-http-version 支持 1.1 和 2.0 但不支持 1.0。

### ❓ 待验证
需要进一步测试验证 Higress 是否支持或是否有替代方案。

### 🔴 无需迁移
Envoy 架构天然覆盖、K8s 原生已解决、或功能已过时，迁移时直接删除注解即可，不会产生任何功能缺失。判断关键：不是"功能缺失"，而是"问题本身不存在了"。

典型场景：
- Envoy 流式架构天然解决了 NGINX 缓冲相关配置需求（proxy-buffering、proxy-buffer-size、proxy-body-size 等）
- K8s 原生能力已覆盖（server-alias → spec.rules 多 host）
- 功能已被行业废弃（http2-push-preload）
- Envoy 自动处理，无需手动配置（connection-proxy-header → hop-by-hop 头自动处理）
- 默认行为已是更优做法（service-upstream → 直接路由到 Endpoints 性能更好）

## 单个注解分析思路

对每个注解，按以下顺序分析：

### 1. 功能说明
这个注解在 NGINX 中具体做什么？什么场景下使用？用一两句话说清楚。

### 2. 兼容性判断
在 Higress/Envoy 中：
- 能否直接使用？→ ✅
- 能否通过其他机制实现相同功能？→ 🔵
- 是否存在真实功能缺口？→ ❌
- 是否部分场景可用？→ ⚠️
- Envoy 架构是否天然解决了这个问题？→ 🔴
- 不确定？→ ❓

### 3. 原因说明
说明为什么是这个分类。重点解释：
- 架构差异的具体表现（不是笼统说"架构不同"）
- Envoy 中对应的机制是什么（或为什么没有）
- 如果有替代方案，具体是什么

### 4. 优先级评估
- 重要且常用：生产环境广泛使用，迁移必须处理
- 重要但不常用：特定场景需要，按需处理
- 不重要但常用：有替代方案或影响小
- 不重要且不常用：可低优先级处理或忽略

优先级判断依据：
- 该注解在实际 NGINX Ingress 部署中的使用频率
- 缺失该功能对业务的实际影响
- 是否有简单的替代方案

## 文档更新规范

更新 `ls-test/migration/summary-v3.md` 时需同步修改：

1. **功能表格中的条目**：兼容情况标记、优先级、等价方法或说明
2. **统计汇总表**：各分类的数量和占比
3. **关键兼容性分析章节**：对应分类的汇总列表
4. **待验证列表**：如果注解从待验证移出，需同步移除

## 分类调整原则

- 从 ❌ 调整为 🔴：确认 Envoy 架构天然解决了问题，不存在功能缺失
- 从 ⚠️ 调整为 🔵：确认功能完全可达，只是接口形式不同
- 从 ⚠️ 调整为 ❌：确认存在无法弥补的功能缺口
- 从 ❓ 调整为其他：经过分析或验证后确定分类
- 从 ✅ 调整为 ⚠️：官方文档标注"部分兼容"或源码验证存在不支持的子集

## 验证方法与工具

### 源码验证路径
分析注解兼容性时，按以下路径查找源码实现：

1. **注解解析器**：`pkg/ingress/kube/annotations/*.go`
   - 每个功能模块一个文件（如 `loadbalance.go`、`redirect.go`、`upstreamtls.go`）
   - 查看常量定义确认支持哪些注解名称
   - 查看 `Parse()` 函数确认实际解析逻辑
   - 查看 `Apply*()` 函数确认如何转换为 Envoy/Istio 配置

2. **注解注册入口**：`pkg/ingress/kube/annotations/annotations.go`
   - `NewAnnotationHandlerManager()` 中注册了所有 parser
   - 未注册的注解不会被处理（无 passthrough 机制）

3. **WASM 插件**：`plugins/wasm-go/extensions/*/`
   - 各插件目录下的 `main.go` 和 `config.go`
   - 如 `ext-auth/`、`ip-restriction/`、`key-rate-limit/` 等

4. **注解前缀处理**：`pkg/ingress/kube/annotations/parser.go`
   - `ParseStringASAP` / `HasASAP` 方法同时检查 `nginx.ingress.kubernetes.io/` 和 `higress.io/` 前缀

### 官方文档交叉验证
- Higress 注解文档：https://higress.io/docs/latest/user/annotation/
- Higress 注解用例：https://higress.io/docs/latest/user/annotation-use-case/
- 官方文档仅列出部分常用注解，不代表完整支持列表
- 官方文档标注"部分兼容"的注解，summary-v3.md 中应同步标注为 ⚠️

## 已确认的分类决策

以下决策在讨论中已确认，后续分析时应遵循：

### ⚠️ 部分兼容（经官方文档/源码交叉验证确认）
| 注解 | 原因 | 验证依据 |
|------|------|----------|
| load-balance | 不支持 ewma 算法 | 官方文档标注"部分兼容"；源码 `loadbalance.go` 使用 Istio SimpleLB 枚举，无 ewma |
| upstream-hash-by | 不支持多变量组合 | 官方文档标注"部分兼容"；源码仅支持单个 `$http_*`/`$arg_*`/`$request_uri`/`$host`/`$remote_addr` |
| affinity-mode | 不支持 persistent 模式 | 官方文档标注"部分兼容"；源码注释 "always be balanced"，Parse 中未使用此值 |
| backend-protocol | 不支持 AJP 和 FCGI | 官方文档标注"部分兼容"；源码 `validProtocols` 正则仅匹配 `HTTP|HTTP2|HTTPS|GRPC|GRPCS` |
| auth-tls-secret | Secret 命名格式限制 | 官方文档标注"部分兼容"；源码 `downstreamtls.go` 要求 CA Secret 与 TLS Secret 同名或加 `-cacert` 后缀 |
| ssl-passthrough | Ingress 注解层未实现 | 官方文档未列出；源码中无对应 parser；Gateway API TLSRoute 可实现 |
| proxy-http-version | 不支持 HTTP/1.0 | Envoy 向后端仅支持 HTTP/1.1 和 HTTP/2 |
| server-alias | 仅支持精确域名和泛域名 | APIG 文档标注"部分兼容"（要求网关版本 1.2.30）；不支持正则域名别名 |

### 🔵 可等价替换（经确认的插件替代方案）
| 注解 | 替代方案 | 决策依据 |
|------|----------|----------|
| auth-type | `basic-auth` WASM 插件 | Higress 原生注解仅支持 Basic；v2.0.0+ 推荐通过插件实现,功能更完整；Digest 认证需自定义 WASM 插件 |
| auth-secret | `basic-auth` WASM 插件 | 用户凭证从 K8s Secret 迁移到插件配置,支持 APR1 加密密码 |
| denylist-source-range | ip-restriction 插件 deny 模式 | 源码 `ip_access_control.go` 仅实现 whitelist；ip-restriction 插件完整支持黑白名单 |
| proxy-cookie-domain | WasmPlugin（transformer）或 EnvoyFilter | 源码中无注解解析；通过修改 Set-Cookie 响应头实现 |
| proxy-cookie-path | WasmPlugin（transformer）或 EnvoyFilter | 同上 |
| from-to-www-redirect | permanent-redirect + 多 Ingress 规则 | 源码中无实现；通过组合现有注解实现等价效果 |

### ❌ 不兼容（经源码验证确认）
| 注解 | 原因 | 验证依据 |
|------|------|----------|
| temporal-redirect-code | redirect.go 硬编码 302 | 源码中 temporal-redirect 使用 `defaultTemporalRedirectCode = 302`，未解析 temporal-redirect-code |
| session-cookie-domain | Istio API 不支持 | `ConsistentHashLB_HTTPCookie` 仅有 Name/Path/Ttl，无 Domain 字段 |

### 🔴 无需迁移（经架构分析确认）
| 注解 | 原因 | 决策依据 |
|------|------|----------|
| proxy-body-size | Envoy 流式转发架构天然规避 | NGINX 需要此限制是因为"先收完请求体再转发"架构会导致内存/磁盘爆炸；Envoy 逐块流式转发，单连接内存上界仅为 `per_connection_buffer_limit_bytes`（默认 32KB），不管请求体多大都不会打爆网关。迁移时直接删除即可；极少数需在网关层拦截超大请求的场景可通过 WasmPlugin 实现 |

## 当前文档状态

- **文档路径**：`ls-test/migration/summary-v3.md`
- **统计**：✅43 / 🔵35 / ❌33 / ⚠️8 / 🔴11 = 130 个注解
- **注解来源**：117 个在官方页面顶部索引表中 + 13 个仅在正文章节中描述（均为当前最新版本支持的有效注解）
- **📋 标记**：13 个仅在正文章节描述的注解已全部标注 `📋 仅在正文"XXX"章节描述，未列入顶部索引表`
  - External Authentication 章节（6 个）：auth-signin、auth-response-headers、auth-method、auth-signin-redirect-param、auth-request-redirect、auth-always-set-cookie
  - Rate Limiting 章节（5 个）：limit-rpm、limit-burst-multiplier、limit-rate-after、limit-rate、limit-whitelist
  - Custom NGINX upstream hashing 章节（2 个）：upstream-hash-by-subset、upstream-hash-by-subset-size
- **已完成**：
  - 全部 17 个 ❓ 待验证注解已分类
  - 与 Higress 官方注解文档交叉验证完成
  - 与 APIG Ingress 官方文档（public.md）交叉验证完成
  - 与 NGINX Ingress Controller 官方注解页面交叉验证完成
  - session-cookie-domain 从 ✅ 修正为 ❌（源码验证无实现）
  - server-alias 从 🔴 修正为 ⚠️（APIG 文档确认 1.2.30+ 部分兼容）
  - auth-type 从 🔵 修正为 ⚠️（APIG 文档确认仅支持 Basic）
  - auth-secret 从 🔵 修正为 ⚠️（配合 auth-type 仅 Basic 可用）
  - 新增 11 个 NGINX 官方注解（auth-method、auth-signin-redirect-param、auth-request-redirect、auth-always-set-cookie、limit-rpm、limit-burst-multiplier、limit-rate-after、limit-rate、limit-whitelist、upstream-hash-by-subset、upstream-hash-by-subset-size）
  - proxy-body-size 从 ❌ 修正为 🔴（Envoy 流式转发架构天然规避内存爆炸问题，该注解的核心作用"保护网关"在 Envoy 下不再必要）

# MCP Server REST 配置校验逻辑参考文档

本文档提取自 Higress MCP Server 插件源码，供第三方实现配置校验时参考。仅覆盖 `server` 模式（含 REST 和 mcp-proxy 两种 type）。

## 1. 配置结构

```json
{
  "server": {
    "name": "weather-api",
    "type": "rest",
    "config": { ... },
    "securitySchemes": [ ... ],
    "defaultDownstreamSecurity": { ... },
    "defaultUpstreamSecurity": { ... },
    "passthroughAuthHeader": false
  },
  "tools": [ ... ],
  "allowTools": [ "get_weather" ]
}
```

顶层必须存在 `server` 字段，否则校验失败。

---

## 2. server 字段校验

| 字段 | 必填 | 校验规则 |
|------|------|----------|
| `server.name` | 是 | 不能为空，否则报错 `"server.name field is missing for single server config"` |
| `server.type` | 否 | 默认 `"rest"`，可选 `"rest"` / `"mcp-proxy"` |
| `server.config` | 否 | 任意 JSON，透传给 server 实例 |
| `server.securitySchemes` | 否 | 数组，每项需通过 SecurityScheme 校验（见第 4 节） |
| `server.defaultDownstreamSecurity` | 否 | SecurityRequirement 结构（见第 5 节） |
| `server.defaultUpstreamSecurity` | 否 | SecurityRequirement 结构（见第 5 节） |
| `server.passthroughAuthHeader` | 否 | 布尔值，默认 false |

---

## 3. tools 数组校验

### 3.1 type = "rest"（默认）

`tools` 数组必须存在且非空。每个 tool 反序列化为 `RestTool`，然后通过 `parseTemplates()` 校验。

#### RestTool 结构

```json
{
  "name": "get_weather",
  "description": "获取天气信息",
  "args": [
    {
      "name": "city",
      "description": "城市名称",
      "type": "string",
      "required": true,
      "default": null,
      "enum": ["beijing", "shanghai"],
      "items": null,
      "properties": null,
      "position": "query"
    }
  ],
  "requestTemplate": {
    "url": "https://api.weather.com/v1/current?city={{.args.city}}",
    "method": "GET",
    "headers": [
      { "key": "Authorization", "value": "Bearer {{.config.apiKey}}" }
    ],
    "body": "",
    "argsToJsonBody": false,
    "argsToUrlParam": false,
    "argsToFormBody": false,
    "security": { "id": "bearer-auth" }
  },
  "responseTemplate": {
    "body": "天气: {{.temperature}}°C",
    "prependBody": "",
    "appendBody": ""
  },
  "errorResponseTemplate": "",
  "outputSchema": {}
}
```

#### parseTemplates() 校验规则

```
1. requestTemplate.url 为空 → 标记为"直接响应模式"（isDirectResponseTool = true）
   - 此模式下 responseTemplate.body 必须设置
     否则报错："direct response mode must set responseTemplate.body"

2. requestTemplate.url 非空 → 正常 REST 请求模式：
   a. argsToJsonBody / argsToUrlParam / argsToFormBody 三者最多只能设一个为 true
      否则报错："only one of argsToJsonBody, argsToUrlParam, or argsToFormBody can be set to true"

   b. requestTemplate.url 必须是合法的 Go template 语法
      否则报错："error parsing URL template: ..."

   c. requestTemplate.headers 中每个 header：
      - key 为空则跳过（warn 日志）
      - value 必须是合法的 Go template 语法
      否则报错："error parsing header template for <key>: ..."

   d. requestTemplate.body 如果非空，必须是合法的 Go template 语法
      否则报错："error parsing body template: ..."

3. responseTemplate 校验：
   a. responseTemplate.body 非空时：
      - prependBody 和 appendBody 不能同时使用
        否则报错："PrependBody and AppendBody cannot be used when Body is specified"
      - body 必须是合法的 Go template 语法
        否则报错："error parsing response template: ..."

4. errorResponseTemplate 如果非空，必须是合法的 Go template 语法
   否则报错："error parsing error response template: ..."

5. args 中的 position 字段会被收集到 argPositions map 中（转小写）
   有效值：query, path, header, cookie, body
```

### 3.2 type = "mcp-proxy"

`tools` 数组可选。每个 tool 反序列化为 `McpProxyToolConfig`。

#### McpProxyToolConfig 结构

```json
{
  "name": "test-tool",
  "description": "Test tool",
  "args": [
    {
      "name": "input",
      "description": "Input parameter",
      "type": "string",
      "required": true
    }
  ],
  "requestTemplate": {
    "security": { "id": "ApiKeyAuth" }
  },
  "outputSchema": {}
}
```

#### mcp-proxy 专属 server 字段校验

| 字段 | 必填 | 校验规则 |
|------|------|----------|
| `server.transport` | 是 | 只能是 `"http"` 或 `"sse"`，否则报错 `"invalid transport value"` |
| `server.mcpServerURL` | 是 | 不能为空，且通过 URL 校验（见第 7 节） |
| `server.timeout` | 否 | 正整数，毫秒 |

#### McpProxyToolConfig 校验规则（ValidateToolConfig）

```
1. name 必填，不能为空 → "tool name is required"
2. description 必填，不能为空 → "tool description is required"
3. args 中每个参数：
   - name 必填 → "argument name is required"
   - name 不能重复 → "duplicate argument name: <name>"
   - description 必填 → "argument description is required for <name>"
   - type 必须是以下之一：string, number, integer, boolean, array, object
     否则报错："invalid argument type <type> for <name>"
```

---

## 4. SecurityScheme 校验

```
1. id 必填，不能为空
   → "security scheme ID is required"

2. type 只能是 "apiKey" 或 "http"
   → "invalid security scheme type: <type>"

3. type = "apiKey" 时：
   - name 必填 → "security scheme name is required for apiKey type"
   - in 只能是 "header" / "query" / "cookie"
     → "invalid security scheme location: <in>"

4. type = "http" 时：
   - scheme 必填（如 "bearer" / "basic"）
     → "security scheme scheme is required for http type"
```

结构：

```json
{
  "id": "ApiKeyAuth",
  "type": "apiKey",
  "in": "header",
  "name": "X-API-Key",
  "scheme": "",
  "defaultCredential": "your-key"
}
```

---

## 5. SecurityRequirement 结构

```json
{
  "id": "ApiKeyAuth",
  "credential": "override-credential",
  "passthrough": false
}
```

JSON 反序列化失败即报错，无额外字段级校验。

---

## 6. allowTools 校验

`allowTools` 是可选的字符串数组：
- 不存在（nil）→ 允许所有 tools
- 存在 → 只有列表中的 tool 名称才会暴露给客户端

---

## 7. URL 校验（validateURL）

用于 mcp-proxy 模式的 `mcpServerURL`：

```
1. 不能为空
2. 必须是合法的 URL 格式（url.Parse 不报错）
3. 如果有 scheme，必须同时有 host
4. scheme 只允许 "http" 或 "https"
```

REST 模式的 tool URL 通过 Go template 解析校验，不走此函数。

---

## 8. Go Template 语法说明

REST 配置中的 URL、Header、Body、Response 模板使用 Go template 语法（基于 gjson_template 库）。

可用的模板变量：
- `{{.args.<argName>}}` — 工具参数
- `{{.config.<key>}}` — server.config 中的配置项
- `{{.<responseField>}}` — 响应 JSON 中的字段（用于 responseTemplate）

内置模板函数：
- `getSocketIP` — 获取请求来源 socket IP
- `getRealIP` — 从 X-Forwarded-For 获取真实 IP，回退到 socket IP

---

## 9. 独立校验入口（供第三方使用）

项目已提供 `validator` 包，可脱离 Wasm 运行时独立校验：

```go
import "github.com/alibaba/higress/plugins/wasm-go/pkg/mcp/validator"

// JSON 格式
result, err := validator.ValidateConfig(jsonString)

// YAML 格式（内部先转 JSON）
result, err := validator.ValidateConfigYAML(yamlString)

// 从 byte 数组
result, err := validator.ValidateConfigFromBytes(configBytes)

// 从 map
result, err := validator.ValidateConfigFromMap(configMap)
```

返回值：

```go
type ValidationResult struct {
    IsValid    bool   // 配置是否合法
    Error      error  // 校验错误信息
    ServerName string // 解析出的服务器名称
    IsComposed bool   // 是否为组合服务器
}
```

---

## 10. 完整校验流程伪代码

```
function validateConfig(config):
    if config has no "server" → ERROR

    serverName = server.name
    if serverName is empty → ERROR "server.name field is missing"

    serverType = server.type (default "rest")

    if serverType == "mcp-proxy":
        validate transport (required, must be "http" or "sse")
        validate mcpServerURL (required, validateURL)
        parse timeout (optional)
        parse passthroughAuthHeader (optional)
        parse securitySchemes → each ValidateSecurityScheme()
        parse defaultDownstreamSecurity, defaultUpstreamSecurity
        for each tool in tools (optional):
            unmarshal as McpProxyToolConfig
            ValidateToolConfig() → name, description 非空, args 校验

    else (REST mode):
        tools must exist and be non-empty
        parse securitySchemes → each ValidateSecurityScheme()
        parse defaultDownstreamSecurity, defaultUpstreamSecurity
        parse passthroughAuthHeader
        for each tool in tools:
            unmarshal as RestTool
            call tool.parseTemplates()  ← 核心校验逻辑

    parse allowTools (optional string array)
```

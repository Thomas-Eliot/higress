---
title: AI 上下文窗口限制
keywords: [ AI网关, 上下文窗口, Token ]
description: AI 上下文窗口限制插件配置参考
---

## 功能说明

`ai-context-limit` 用于在请求转发到上游大模型前，对 OpenAI Chat Completions 兼容请求中的文本输入进行 token 估算。当估算结果超过配置的上下文窗口大小时，插件会直接返回错误响应，避免超长上下文继续进入后端模型服务。

该插件适用于按路由、服务、域名或 MCP Server 控制请求上下文规模的场景，可用于为不同业务、模型或调用入口设置独立的上下文窗口上限。

## 运行属性

插件执行阶段：`认证阶段`

插件执行优先级：`1000`

## 配置字段

| 名称 | 数据类型 | 填写要求 | 默认值 | 描述 |
|------|---------|---------|--------|------|
| `max_context_tokens` | int | 必填 | - | 最大上下文 token 数。输入估算结果超过该值时，请求会被拦截。 |
| `buffer_ratio` | float | 非必填 | 1.10 | 安全缓冲系数。插件会将估算 token 数乘以该系数后再与阈值比较。 |
| `error_status_code` | int | 非必填 | 400 | 请求超出上下文窗口限制时返回的 HTTP 状态码。 |

## 配置示例

```yaml
max_context_tokens: 128000
buffer_ratio: 1.10
error_status_code: 400
```

## 返回示例

当请求输入超过配置限制时，插件会返回如下格式的错误响应：

```json
{
  "error": {
    "message": "This model's maximum context length is 128000 tokens. Your request had approximately 140000 tokens.",
    "type": "invalid_request_error",
    "code": "context_length_exceeded"
  }
}
```

## buffer_ratio 选择建议

| 主要模型 | 推荐 buffer_ratio | 理由 |
|---|---|---|
| Qwen（通用场景） | **1.10** | 默认值，覆盖通用文本估算偏差 |
| DeepSeek（通用场景） | **1.10** | 默认值，覆盖通用文本估算偏差 |
| Qwen/DeepSeek（代码路由） | **1.15** | 代码场景分词粒度更细，需更大缓冲 |
| GLM-5.1 | **1.05** 或 **1.10** | 估算偏保守，不会漏放 |
| Kimi | **1.05** 或 **1.10** | 估算偏保守，不会漏放 |
| MiniMax | **1.05** 或 **1.10** | 估算偏保守，不会漏放 |

## 注意事项

- 当前版本仅统计文本输入内容。
- 非 JSON 请求或非 OpenAI Chat Completions 兼容请求不会触发上下文限制。

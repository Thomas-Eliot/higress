---
title: AI Context Limit
keywords: [ AI Gateway, Context Window, Token ]
description: AI Context Limit plugin configuration reference
---

## Functional Description

`ai-context-limit` estimates the input token count of OpenAI Chat Completions compatible requests before forwarding them to the upstream model service. When the estimated input size exceeds the configured context window limit, the plugin returns an error response directly.

This plugin can be used to control context window size by route, service, domain, or MCP Server. It is suitable for setting independent context limits for different applications, models, or traffic entry points.

## Runtime Properties

Plugin execution phase: `Authentication Phase`

Plugin execution priority: `1000`

## Configuration Fields

| Name | Data Type | Requirement | Default Value | Description |
|------|-----------|-------------|---------------|-------------|
| `max_context_tokens` | int | Required | - | Maximum context token limit. Requests whose estimated input size exceeds this value will be blocked. |
| `buffer_ratio` | float | Optional | 1.10 | Safety buffer ratio. The estimated token count is multiplied by this ratio before comparison. |
| `error_status_code` | int | Optional | 400 | HTTP status code returned when the request exceeds the context limit. |

## Configuration Example

```yaml
max_context_tokens: 128000
buffer_ratio: 1.10
error_status_code: 400
```

## Response Example

When a request exceeds the configured limit, the plugin returns an error response in the following format:

```json
{
  "error": {
    "message": "This model's maximum context length is 128000 tokens. Your request had approximately 140000 tokens.",
    "type": "invalid_request_error",
    "code": "context_length_exceeded"
  }
}
```

## buffer_ratio Selection Guide

| Model | Recommended buffer_ratio | Reason |
|---|---|---|
| Qwen (general scenarios) | **1.10** | Default value, covers general text estimation deviation |
| DeepSeek (general scenarios) | **1.10** | Default value, covers general text estimation deviation |
| Qwen/DeepSeek (code routes) | **1.15** | Code scenarios have finer tokenization granularity, requiring a larger buffer |
| GLM-5.1 | **1.05** or **1.10** | Estimation tends conservative, will not miss blocks |
| Kimi | **1.05** or **1.10** | Estimation tends conservative, will not miss blocks |
| MiniMax | **1.05** or **1.10** | Estimation tends conservative, will not miss blocks |

## Notes

- The current version only counts text input.
- Non-JSON requests and requests that are not compatible with OpenAI Chat Completions will not trigger the context limit.
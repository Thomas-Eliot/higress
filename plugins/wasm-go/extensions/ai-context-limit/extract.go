// Copyright (c) 2026 Alibaba Group Holding Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"strings"

	"github.com/tidwall/gjson"
)

// extractResult 文本抽取结果
type extractResult struct {
	// Text 拼接后的所有可计 token 文本（messages/tools/system）
	Text string
	// HasMultimodal 是否检测到非 text 类型 part（image_url/audio/...），命中即放行
	HasMultimodal bool
}

// extractPromptText 从 OpenAI Chat Completions 请求体抽取所有需要计入 input tokens 的文本
//
// 协议参考：https://platform.openai.com/docs/api-reference/chat/create
//
// 抽取范围：
//   - messages[].content：string 或 array of {type:"text",text:"..."}
//   - messages[].name：可选 role 标识
//   - tools[].function.name / .description / .parameters（JSON 序列化整体计数）
//   - 顶层 system 字段：兜底兼容部分上游协议（OpenAI 标准是放在 messages 里）
//
// 多模态降级：messages[].content 数组中出现任一 type != "text" 的 part 即视为多模态，
// 整个请求放行（HasMultimodal=true）。
func extractPromptText(body []byte) extractResult {
	var sb strings.Builder
	result := extractResult{}

	// 1. messages[]
	messages := gjson.GetBytes(body, "messages").Array()
	for _, msg := range messages {
		if name := msg.Get("name").String(); name != "" {
			sb.WriteString(name)
			sb.WriteByte('\n')
		}
		if role := msg.Get("role").String(); role != "" {
			sb.WriteString(role)
			sb.WriteByte('\n')
		}
		content := msg.Get("content")
		switch {
		case content.Type == gjson.String:
			sb.WriteString(content.String())
			sb.WriteByte('\n')
		case content.IsArray():
			for _, part := range content.Array() {
				partType := part.Get("type").String()
				if partType == "text" {
					sb.WriteString(part.Get("text").String())
					sb.WriteByte('\n')
					continue
				}
				// 任意非 text part → 多模态，立即返回触发放行
				result.HasMultimodal = true
				return result
			}
		}
	}

	// 2. tools[]
	tools := gjson.GetBytes(body, "tools").Array()
	for _, tool := range tools {
		fn := tool.Get("function")
		if !fn.Exists() {
			continue
		}
		if name := fn.Get("name").String(); name != "" {
			sb.WriteString(name)
			sb.WriteByte('\n')
		}
		if desc := fn.Get("description").String(); desc != "" {
			sb.WriteString(desc)
			sb.WriteByte('\n')
		}
		if params := fn.Get("parameters"); params.Exists() {
			// parameters 是 JSON Schema 对象，整体序列化参与计数
			sb.WriteString(params.Raw)
			sb.WriteByte('\n')
		}
	}

	// 3. 顶层 system 字段（OpenAI 标准放在 messages，但部分上游会拆出来）
	if sys := gjson.GetBytes(body, "system"); sys.Exists() {
		switch {
		case sys.Type == gjson.String:
			sb.WriteString(sys.String())
			sb.WriteByte('\n')
		case sys.IsArray():
			for _, part := range sys.Array() {
				if part.Get("type").String() == "text" {
					sb.WriteString(part.Get("text").String())
					sb.WriteByte('\n')
				}
			}
		}
	}

	result.Text = sb.String()
	return result
}

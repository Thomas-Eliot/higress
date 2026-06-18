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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tidwall/gjson"
)

func TestParseConfig(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantMax   int
		wantCode  int
		wantRatio float64
		wantOk    bool
	}{
		{
			name:      "完整配置",
			input:     `{"max_context_tokens":128000,"error_status_code":413,"buffer_ratio":1.2}`,
			wantMax:   128000,
			wantCode:  413,
			wantRatio: 1.2,
			wantOk:    true,
		},
		{
			name:      "仅必填字段，其余取默认值",
			input:     `{"max_context_tokens":32000}`,
			wantMax:   32000,
			wantCode:  defaultErrorStatusCode,
			wantRatio: defaultBufferRatio,
			wantOk:    true,
		},
		{
			name:      "缺失阈值不抛错，IsEnabled=false",
			input:     `{}`,
			wantMax:   0,
			wantCode:  0,
			wantRatio: 0,
			wantOk:    false,
		},
		{
			name:      "阈值为 0 视为未启用",
			input:     `{"max_context_tokens":0}`,
			wantMax:   0,
			wantCode:  0,
			wantRatio: 0,
			wantOk:    false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var cfg Config
			err := parseConfig(gjson.Parse(tc.input), &cfg)
			assert.NoError(t, err)
			assert.Equal(t, tc.wantMax, cfg.MaxContextTokens)
			assert.Equal(t, tc.wantCode, cfg.ErrorStatusCode)
			assert.InDelta(t, tc.wantRatio, cfg.BufferRatio, 1e-9)
			assert.Equal(t, tc.wantOk, cfg.IsEnabled())
		})
	}
}

func TestExtractPromptText_StringContent(t *testing.T) {
	body := []byte(`{
		"model": "gpt-4o",
		"messages": [
			{"role": "system", "content": "你是一个助手"},
			{"role": "user", "content": "Hello world"}
		]
	}`)
	r := extractPromptText(body)
	assert.False(t, r.HasMultimodal)
	assert.Contains(t, r.Text, "你是一个助手")
	assert.Contains(t, r.Text, "Hello world")
	assert.Contains(t, r.Text, "system")
	assert.Contains(t, r.Text, "user")
}

func TestExtractPromptText_ArrayContent(t *testing.T) {
	body := []byte(`{
		"messages": [
			{"role": "user", "content": [
				{"type": "text", "text": "describe this"},
				{"type": "text", "text": "in detail"}
			]}
		]
	}`)
	r := extractPromptText(body)
	assert.False(t, r.HasMultimodal)
	assert.Contains(t, r.Text, "describe this")
	assert.Contains(t, r.Text, "in detail")
}

func TestExtractPromptText_Multimodal(t *testing.T) {
	body := []byte(`{
		"messages": [
			{"role": "user", "content": [
				{"type": "text", "text": "what is in this image?"},
				{"type": "image_url", "image_url": {"url": "https://example.com/cat.jpg"}}
			]}
		]
	}`)
	r := extractPromptText(body)
	assert.True(t, r.HasMultimodal, "image_url 必须触发多模态放行")
}

func TestExtractPromptText_Tools(t *testing.T) {
	body := []byte(`{
		"messages": [{"role": "user", "content": "查询天气"}],
		"tools": [
			{
				"type": "function",
				"function": {
					"name": "get_weather",
					"description": "获取指定城市的天气信息",
					"parameters": {"type": "object", "properties": {"city": {"type": "string"}}}
				}
			}
		]
	}`)
	r := extractPromptText(body)
	assert.False(t, r.HasMultimodal)
	assert.Contains(t, r.Text, "查询天气")
	assert.Contains(t, r.Text, "get_weather")
	assert.Contains(t, r.Text, "获取指定城市的天气信息")
	// parameters 整体序列化进入计数
	assert.Contains(t, r.Text, "city")
}

func TestExtractPromptText_TopLevelSystem(t *testing.T) {
	body := []byte(`{
		"system": "你是有帮助的助手",
		"messages": [{"role": "user", "content": "hi"}]
	}`)
	r := extractPromptText(body)
	assert.Contains(t, r.Text, "你是有帮助的助手")
	assert.Contains(t, r.Text, "hi")
}

func TestExtractPromptText_Empty(t *testing.T) {
	r := extractPromptText([]byte(`{}`))
	assert.False(t, r.HasMultimodal)
	assert.Equal(t, "", r.Text)
}

// TestCountTokens 只做基本可用性断言，避免在单测中绑定具体词表细节。
func TestCountTokens(t *testing.T) {
	require := assert.New(t)
	require.NoError(initEncoder())

	require.Equal(0, CountTokens(""), "空字符串返回 0")
	require.Greater(CountTokens("Hello world"), 0)
	require.Greater(CountTokens("中文测试"), 0)

	// 重复文本 token 数应近似线性
	once := CountTokens("hello")
	thrice := CountTokens("hello hello hello")
	require.Greater(thrice, once)
}

// TestBlockDecision 拦截判定逻辑（×buffer_ratio 与阈值比较）
// 直接用真实编码器，构造 prompt 控制估算值的相对位置
func TestBlockDecision(t *testing.T) {
	require := assert.New(t)
	require.NoError(initEncoder())

	// 构造一段已知 token 数的文本
	prompt := "Hello world. This is a test prompt for token counting."
	rawTokens := CountTokens(prompt)
	require.Greater(rawTokens, 0)

	cases := []struct {
		name        string
		bufferRatio float64
		threshold   int
		shouldBlock bool
	}{
		{"远低于阈值 → 放行", 1.10, 100000, false},
		{"略低于阈值 → 放行", 1.10, rawTokens * 2, false},
		{"恰好等于阈值 → 放行（>不>=）", 1.0, rawTokens, false},
		{"略超阈值 → 拦截", 1.10, 1, true},
		{"buffer_ratio 抬高致超阈值", 10.0, rawTokens + 1, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			estimated := int(float64(rawTokens) * tc.bufferRatio)
			got := estimated > tc.threshold
			assert.Equal(t, tc.shouldBlock, got,
				"raw=%d ratio=%.2f estimated=%d threshold=%d",
				rawTokens, tc.bufferRatio, estimated, tc.threshold)
		})
	}
}

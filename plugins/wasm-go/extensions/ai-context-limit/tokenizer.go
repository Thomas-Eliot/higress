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
	_ "embed"
	"encoding/base64"
	"strconv"
	"strings"

	"github.com/pkoukk/tiktoken-go"
)

// 内嵌 o200k_base 词表（约 3.4MB）
//
//go:embed bpe/o200k_base.tiktoken
var o200kBaseRaw []byte

// embedBpeLoader 实现 tiktoken-go 的 BpeLoader 接口
// 离线加载内嵌词表，避免运行时下载（WASM 环境无外网访问）
type embedBpeLoader struct{}

// LoadTiktokenBpe 解析 .tiktoken 格式（每行 "<base64-token> <rank>"）
func (l *embedBpeLoader) LoadTiktokenBpe(_ string) (map[string]int, error) {
	bpeRanks := make(map[string]int, 200000)
	for _, line := range strings.Split(string(o200kBaseRaw), "\n") {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, " ", 2)
		if len(parts) != 2 {
			continue
		}
		token, err := base64.StdEncoding.DecodeString(parts[0])
		if err != nil {
			continue
		}
		rank, err := strconv.Atoi(parts[1])
		if err != nil {
			continue
		}
		bpeRanks[string(token)] = rank
	}
	return bpeRanks, nil
}

// encoder 全局编码器实例（init 阶段加载，零拷贝复用）
var encoder *tiktoken.Tiktoken

// initEncoder 初始化 o200k_base 编码器
// 必须在插件 parseConfig 阶段或更早被调用
func initEncoder() error {
	tiktoken.SetBpeLoader(&embedBpeLoader{})
	enc, err := tiktoken.GetEncoding("o200k_base")
	if err != nil {
		return err
	}
	encoder = enc
	return nil
}

// CountTokens 用 o200k_base 编码计算文本 token 数
// 输入空字符串返回 0
func CountTokens(text string) int {
	if text == "" || encoder == nil {
		return 0
	}
	return len(encoder.Encode(text, nil, nil))
}

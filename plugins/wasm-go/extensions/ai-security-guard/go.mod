module github.com/alibaba/higress/plugins/wasm-go/extensions/ai-security-guard

go 1.24.1

toolchain go1.24.4

replace github.com/alibaba/higress/plugins/wasm-go/extensions/ai-security-guard/my-credentials => /Users/lvshui/Dev/code_repo/higress/higress/plugins/wasm-go/extensions/ai-security-guard/my-credentials

require (
	github.com/aliyun/alibaba-cloud-sdk-go v1.63.107
	github.com/higress-group/proxy-wasm-go-sdk v0.0.0-20250611100342-5654e89a7a80
	github.com/higress-group/wasm-go v1.0.0
	github.com/tidwall/gjson v1.18.0
)

require (
	github.com/google/uuid v1.6.0 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.1 // indirect
	github.com/tidwall/resp v0.1.1 // indirect
)

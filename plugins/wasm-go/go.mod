module github.com/alibaba/higress/plugins/wasm-go

go 1.24.4

replace github.com/alibaba/higress/plugins/wasm-go/extensions/ai-security-guard/my-credentials => /Users/lvshui/Dev/code_repo/higress/higress/plugins/wasm-go/extensions/ai-security-guard/my-credentials

require (
	github.com/google/uuid v1.6.0
	github.com/higress-group/proxy-wasm-go-sdk v0.0.0-20250611100342-5654e89a7a80
	// github.com/higress-group/proxy-wasm-go-sdk v0.0.0-20250611100342-5654e89a7a80

	github.com/stretchr/testify v1.9.0
	github.com/tidwall/gjson v1.18.0
	github.com/tidwall/resp v0.1.1
	github.com/tidwall/sjson v1.2.5
)

require (
	github.com/alibaba/higress/plugins/wasm-go/extensions/ai-security-guard/my-credentials v0.0.0-00010101000000-000000000000 // indirect
	github.com/aliyun/alibaba-cloud-sdk-go v1.63.107 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/higress-group/wasm-go v1.0.0 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.1 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

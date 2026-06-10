package tianjian

import (
	cfg "github.com/alibaba/higress/plugins/wasm-go/extensions/ai-security-guard/config"
	"github.com/higress-group/proxy-wasm-go-sdk/proxywasm/types"
	"github.com/higress-group/wasm-go/pkg/log"
	"github.com/higress-group/wasm-go/pkg/wrapper"
)

func OnHttpRequestHeaders(ctx wrapper.HttpContext, config cfg.AISecurityConfig) types.Action {
	return types.ActionContinue
}

func OnHttpRequestBody(ctx wrapper.HttpContext, config cfg.AISecurityConfig, body []byte) types.Action {
	switch config.ApiType {
	case cfg.ApiTextGeneration:
		return HandleTextGenerationRequestBody(ctx, config, body)
	default:
		log.Warnf("tianjian doesn't support api: %s", config.ApiType)
		return types.ActionContinue
	}
}

func OnHttpResponseHeaders(ctx wrapper.HttpContext, config cfg.AISecurityConfig) types.Action {
	switch config.ApiType {
	case cfg.ApiTextGeneration:
		return HandleTextGenerationResponseHeader(ctx, config)
	default:
		log.Warnf("tianjian doesn't support api: %s", config.ApiType)
		return types.ActionContinue
	}
}

func OnHttpStreamingResponseBody(ctx wrapper.HttpContext, config cfg.AISecurityConfig, data []byte, endOfStream bool) []byte {
	switch config.ApiType {
	case cfg.ApiTextGeneration:
		return HandleTextGenerationStreamingResponseBody(ctx, config, data, endOfStream)
	default:
		log.Warnf("tianjian doesn't support api: %s", config.ApiType)
		return data
	}
}

func OnHttpResponseBody(ctx wrapper.HttpContext, config cfg.AISecurityConfig, body []byte) types.Action {
	switch config.ApiType {
	case cfg.ApiTextGeneration:
		return HandleTextGenerationResponseBody(ctx, config, body)
	default:
		log.Warnf("tianjian doesn't support api: %s", config.ApiType)
		return types.ActionContinue
	}
}
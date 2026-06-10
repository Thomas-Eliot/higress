package tianjian

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	cfg "github.com/alibaba/higress/plugins/wasm-go/extensions/ai-security-guard/config"
	"github.com/alibaba/higress/plugins/wasm-go/extensions/ai-security-guard/utils"
	"github.com/higress-group/proxy-wasm-go-sdk/proxywasm"
	"github.com/higress-group/proxy-wasm-go-sdk/proxywasm/types"
	"github.com/higress-group/wasm-go/pkg/log"
	"github.com/higress-group/wasm-go/pkg/wrapper"
	"github.com/tidwall/gjson"
)

const (
	responseStartTimeCtxKey           = "tianjian_response_start_time"
	responseFallbackPathsCtxKey       = "tianjian_response_fallback_paths"
	responseStreamFallbackPathsCtxKey = "tianjian_response_stream_fallback_paths"
	streamingCtxKey                   = "tianjian_streaming"
	bufferQueueCtxKey                 = "tianjian_buffer_queue"
	bufferPendingContentCtxKey        = "tianjian_buffer_pending_content"
	startTsCtxKey                     = "tianjian_start_ts"
	duringCallCtxKey                  = "tianjian_during_call"
	endOfStreamReceivedCtxKey         = "tianjian_end_of_stream_received"
	riskDetectedCtxKey                = "tianjian_risk_detected"
	sessionIDCtxKey                   = "tianjian_session_id"
)

// ================== Request Body Handler ==================

func HandleTextGenerationRequestBody(ctx wrapper.HttpContext, config cfg.AISecurityConfig, body []byte) types.Action {
	_, _ = ctx.GetContext("consumer").(string)
	startTime := time.Now().UnixMilli()
	content := gjson.GetBytes(body, config.RequestContentJsonPath).String()
	if len(content) == 0 {
		log.Info("request content is empty, skip tianjian check")
		return types.ActionContinue
	}

	contentIndex := 0
	lastChunkStart := 0
	sessionID, _ := utils.GenerateHexID(20)
	currentSubmissionIndex := 0
	retryCount := 0
	var singleCall func()

	callback := func(statusCode int, responseHeaders http.Header, responseBody []byte) {
		if statusCode != 200 {
			log.Errorf("Tianjian request check failed with status code %d", statusCode)
			if retryCount < 1 {
				retryCount++
				log.Warnf("Tianjian request check: retrying after error (retry %d)", retryCount)
				contentIndex = lastChunkStart
				singleCall()
			} else {
				log.Errorf("Tianjian request check: retry exhausted")
				denyMessage := resolveDenyMessage(config, content, "")
				proxywasm.SendHttpResponse(uint32(config.DenyCode), [][2]string{{"content-type", "application/json"}}, []byte(denyMessage), -1)
				ctx.DontReadResponseBody()
				config.IncrementCounter("ai_sec_request_deny", 1)
				cfg.MarkGuardrailRequestError(ctx, currentSubmissionIndex, responseBody, startTime)
			}
			return
		}

		var outerResp cfg.TianjianOuterResponse
		err := json.Unmarshal(responseBody, &outerResp)
		if err != nil {
			log.Errorf("failed to unmarshal tianjian response at request phase: %v", err)
			if retryCount < 1 {
				retryCount++
				log.Warnf("Tianjian request check: retrying after unmarshal error (retry %d)", retryCount)
				contentIndex = lastChunkStart
				singleCall()
			} else {
				log.Errorf("Tianjian request check: retry exhausted after unmarshal error")
				denyMessage := resolveDenyMessage(config, content, "")
				proxywasm.SendHttpResponse(uint32(config.DenyCode), [][2]string{{"content-type", "application/json"}}, []byte(denyMessage), -1)
				ctx.DontReadResponseBody()
				config.IncrementCounter("ai_sec_request_deny", 1)
				cfg.MarkGuardrailRequestError(ctx, currentSubmissionIndex, responseBody, startTime)
			}
			return
		}
		tianjianResp := outerResp.Response
		// Retry on Tianjian error response (e.g., INTERNAL_ERROR with empty action_code)
		if tianjianResp.ActionCode == "" && retryCount < 1 {
			retryCount++
			log.Warnf("Tianjian request check: tianjian returned error response, retrying (retry %d, result_code=%s)", retryCount, tianjianResp.ResultCode)
			contentIndex = lastChunkStart
			singleCall()
			return
		}

		if cfg.IsTianjianRiskAcceptable(tianjianResp) {
			if contentIndex >= len(content) {
				endTime := time.Now().UnixMilli()
				ctx.SetUserAttribute("safecheck_request_rt", endTime-startTime)
				ctx.SetUserAttribute("safecheck_status", "request pass")
			}
			cfg.CompleteGuardrailSubmissionEvent(ctx, currentSubmissionIndex, responseBody, cfg.GuardrailResultPass)
			if contentIndex >= len(content) {
				cfg.WriteGuardrailLog(ctx)
				proxywasm.ResumeHttpRequest()
			} else {
				singleCall()
			}
			return
		}

		// Risk detected — send deny response
		log.Infof("Tianjian request blocked: actionCode=%s", tianjianResp.ActionCode)
		tianjianAnswer := tianjianDenyAnswer(tianjianResp)
		denyMessage := resolveDenyMessage(config, content, tianjianAnswer)
		if config.ProtocolOriginal {
			proxywasm.SendHttpResponse(uint32(config.DenyCode), [][2]string{{"content-type", "application/json"}}, []byte(denyMessage), -1)
		} else {
			denyData, buildErr := buildTianjianDenyData(config, isStreamingFromCtx(ctx), content, tianjianAnswer)
			if buildErr != nil {
				log.Errorf("failed to build tianjian deny data: %v", buildErr)
				cfg.MarkGuardrailRequestError(ctx, currentSubmissionIndex, responseBody, startTime)
				proxywasm.ResumeHttpRequest()
				return
			}
			proxywasm.SendHttpResponse(uint32(config.DenyCode), openAIDenyContentType(isStreamingFromCtx(ctx)), denyData, -1)
		}
		ctx.DontReadResponseBody()
		config.IncrementCounter("ai_sec_request_deny", 1)
		endTime := time.Now().UnixMilli()
		ctx.SetUserAttribute("safecheck_request_rt", endTime-startTime)
		ctx.SetUserAttribute("safecheck_status", "request deny")
		if len(tianjianResp.Labels) > 0 {
			ctx.SetUserAttribute("safecheck_riskLabel", tianjianResp.Labels[0].Label)
		}
		cfg.CompleteGuardrailSubmissionEvent(ctx, currentSubmissionIndex, responseBody, cfg.GuardrailResultDeny)
		cfg.WriteGuardrailLog(ctx)
	}

	singleCall = func() {
		currentSubmissionIndex = cfg.BeginGuardrailSubmissionEvent(ctx, cfg.GuardrailPhaseRequest, cfg.GuardrailModalityText)
		lastChunkStart = contentIndex
		var nextContentIndex int
		if contentIndex+cfg.LengthLimit >= len(content) {
			nextContentIndex = len(content)
		} else {
			nextContentIndex = contentIndex + cfg.LengthLimit
		}
		contentPiece := content[contentIndex:nextContentIndex]
		contentIndex = nextContentIndex
		path, headers, reqBody := GenerateRequestForInputCheck(config, contentPiece, sessionID)
		err := config.Client.Post(path, headers, reqBody, callback, config.Timeout)
		if err != nil {
			log.Errorf("failed to call tianjian security check service: %v", err)
			cfg.MarkGuardrailRequestError(ctx, currentSubmissionIndex, nil, startTime)
			proxywasm.ResumeHttpRequest()
		}
	}
	singleCall()
	return types.ActionPause
}

// ================== Response Header Handler ==================

func HandleTextGenerationResponseHeader(ctx wrapper.HttpContext, config cfg.AISecurityConfig) types.Action {
	contentType, _ := proxywasm.GetHttpResponseHeader("content-type")
	ctx.SetContext(endOfStreamReceivedCtxKey, false)
	ctx.SetContext(duringCallCtxKey, false)
	ctx.SetContext(riskDetectedCtxKey, false)
	ctx.SetContext(responseStartTimeCtxKey, time.Now().UnixMilli())
	ctx.SetContext(responseFallbackPathsCtxKey, buildEffectiveFallbackPaths(config.ResponseContentJsonPath, config.ResponseContentFallbackJsonPaths))
	ctx.SetContext(responseStreamFallbackPathsCtxKey, buildEffectiveFallbackPaths(config.ResponseStreamContentJsonPath, config.ResponseStreamContentFallbackJsonPaths))
	sessionID, _ := utils.GenerateHexID(20)
	ctx.SetContext(sessionIDCtxKey, sessionID)
	ctx.SetContext(startTsCtxKey, time.Now().UnixMilli())
	var emptyQueue [][]byte
	ctx.SetContext(bufferQueueCtxKey, emptyQueue)
	ctx.SetContext(bufferPendingContentCtxKey, "")

	if strings.Contains(contentType, "text/event-stream") {
		ctx.SetContext(streamingCtxKey, true)
		ctx.NeedPauseStreamingResponse()
		return types.ActionContinue
	} else {
		ctx.SetContext(streamingCtxKey, false)
		ctx.BufferResponseBody()
		return types.HeaderStopIteration
	}
}

// ================== Streaming Response Body Handler ==================

func HandleTextGenerationStreamingResponseBody(ctx wrapper.HttpContext, config cfg.AISecurityConfig, data []byte, endOfStream bool) []byte {
	_, _ = ctx.GetContext("consumer").(string)
	streamFallbackPaths := getEffectiveFallbackPathsFromContext(ctx, responseStreamFallbackPathsCtxKey, config.ResponseStreamContentJsonPath, config.ResponseStreamContentFallbackJsonPaths)

	var sessionID string
	if ctx.GetContext(sessionIDCtxKey) == nil {
		sessionID, _ = utils.GenerateHexID(20)
		ctx.SetContext(sessionIDCtxKey, sessionID)
	} else {
		sessionID, _ = ctx.GetContext(sessionIDCtxKey).(string)
	}

	var bufferQueue [][]byte
	if ctx.GetContext(bufferQueueCtxKey) != nil {
		bufferQueue, _ = ctx.GetContext(bufferQueueCtxKey).([][]byte)
	} else {
		bufferQueue = [][]byte{}
	}
	buffer := ctx.GetStringContext(bufferPendingContentCtxKey, "")
	startTs := ctx.GetContext(startTsCtxKey)
	if startTs == nil {
		startTs = time.Now().UnixMilli()
		ctx.SetContext(startTsCtxKey, startTs)
	}

	currentSubmissionIndex := 0
	retryCount := 0
	var singleCall func()

	callback := func(statusCode int, responseHeaders http.Header, responseBody []byte) {
		if statusCode != 200 {
			if retryCount < 1 {
				retryCount++
				log.Warnf("Tianjian streaming response: retrying after non-200 error (retry %d)", retryCount)
				singleCall()
				return
			}
			log.Errorf("Tianjian streaming response: retry exhausted after non-200")
			startTime, _ := ctx.GetContext(responseStartTimeCtxKey).(int64)
			cfg.MarkGuardrailResponseError(ctx, currentSubmissionIndex, responseBody, startTime)
			if ctx.GetContext(endOfStreamReceivedCtxKey).(bool) {
				proxywasm.ResumeHttpResponse()
			}
			bufferQueue = clearBufferState(ctx, true)
			return
		}

		var outerResp cfg.TianjianOuterResponse
		err := json.Unmarshal(responseBody, &outerResp)
		if err != nil {
			log.Errorf("failed to unmarshal tianjian response at streaming response phase: %v", err)
			if retryCount < 1 {
				retryCount++
				log.Warnf("Tianjian streaming response: retrying after unmarshal error (retry %d)", retryCount)
				singleCall()
				return
			}
			log.Errorf("Tianjian streaming response: retry exhausted after unmarshal error")
			startTime, _ := ctx.GetContext(responseStartTimeCtxKey).(int64)
			cfg.MarkGuardrailResponseError(ctx, currentSubmissionIndex, responseBody, startTime)
			if ctx.GetContext(endOfStreamReceivedCtxKey).(bool) {
				proxywasm.ResumeHttpResponse()
			}
			bufferQueue = clearBufferState(ctx, true)
			return
		}
		tianjianResp := outerResp.Response
		// Retry on Tianjian error response (e.g., INTERNAL_ERROR with empty action_code)
		if tianjianResp.ActionCode == "" && retryCount < 1 {
			retryCount++
			log.Warnf("Tianjian streaming response: tianjian returned error response, retrying (retry %d, result_code=%s)", retryCount, tianjianResp.ResultCode)
			singleCall()
			return
		}

		if cfg.IsTianjianRiskAcceptable(tianjianResp) {
			// Content is safe — pass through
			cfg.CompleteGuardrailSubmissionEvent(ctx, currentSubmissionIndex, responseBody, cfg.GuardrailResultPass)
			cfg.WriteGuardrailLog(ctx)
			endStream := ctx.GetContext(endOfStreamReceivedCtxKey).(bool) && ctx.BufferQueueSize() == 0
			proxywasm.InjectEncodedDataToFilterChain(bytes.Join(bufferQueue, []byte("")), endStream)
			bufferQueue = clearBufferState(ctx, true)

			if !endStream {
				singleCall()
			}
			return
		}

		// Risk detected — inject deny data
		log.Infof("Tianjian streaming response blocked: actionCode=%s", tianjianResp.ActionCode)
		denyData, buildErr := buildTianjianDenyData(config, true, buffer, tianjianDenyAnswer(tianjianResp))
		if buildErr != nil {
			log.Errorf("failed to build tianjian deny data: %v", buildErr)
			cfg.CompleteGuardrailSubmissionEvent(ctx, currentSubmissionIndex, responseBody, cfg.GuardrailResultError)
			// Fail-open: inject buffered upstream content
			endStream := ctx.GetContext(endOfStreamReceivedCtxKey).(bool) && ctx.BufferQueueSize() == 0
			proxywasm.InjectEncodedDataToFilterChain(bytes.Join(bufferQueue, []byte("")), endStream)
			bufferQueue = clearBufferState(ctx, true)
			config.IncrementCounter("ai_sec_response_deny_buildfail", 1)
			startTime, _ := ctx.GetContext(responseStartTimeCtxKey).(int64)
			ctx.SetUserAttribute("safecheck_response_rt", time.Now().UnixMilli()-startTime)
			ctx.SetUserAttribute("safecheck_status", "build_fallback_pass")
			if len(tianjianResp.Labels) > 0 {
				ctx.SetUserAttribute("safecheck_riskLabel", tianjianResp.Labels[0].Label)
			}
			ctx.WriteUserAttributeToLogWithKey(wrapper.AILogKey)
			if !endStream {
				singleCall()
			}
			return
		}

		cfg.CompleteGuardrailSubmissionEvent(ctx, currentSubmissionIndex, responseBody, cfg.GuardrailResultDeny)
		proxywasm.InjectEncodedDataToFilterChain(denyData, true)

		ctx.SetContext(riskDetectedCtxKey, true)
		config.IncrementCounter("ai_sec_response_deny", 1)
		startTime, _ := ctx.GetContext(responseStartTimeCtxKey).(int64)
		ctx.SetUserAttribute("safecheck_response_rt", time.Now().UnixMilli()-startTime)
		ctx.SetUserAttribute("safecheck_status", "response deny")
		if len(tianjianResp.Labels) > 0 {
			ctx.SetUserAttribute("safecheck_riskLabel", tianjianResp.Labels[0].Label)
		}
		cfg.WriteGuardrailLog(ctx)
		bufferQueue = clearBufferState(ctx, false)
	}

	singleCall = func() {
		if ctx.GetContext(duringCallCtxKey).(bool) {
			return
		}
		endOfStreamReceived := ctx.GetContext(endOfStreamReceivedCtxKey).(bool)
		if ctx.BufferQueueSize() == 0 && !endOfStreamReceived {
			return
		}


		var needFlush = false
		for ctx.BufferQueueSize() > 0 {
			front := ctx.PopBuffer()
			bufferQueue = append(bufferQueue, front)
			ctx.SetContext(bufferQueueCtxKey, bufferQueue)
			msg := gjson.GetBytes(front, config.ResponseStreamContentJsonPath).String()
			if len(msg) == 0 {
				msg = autoExtractStreamingResponseContent(front, streamFallbackPaths)
			}
			buffer += msg
			bufferRuneLen := len([]rune(buffer))
			if bufferRuneLen >= config.BufferLimit {
				needFlush = true
			} else if config.BufferFlushTimeInterval > 0 {
				endTs := time.Now().UnixMilli()
				if endTs-startTs.(int64) > int64(config.BufferFlushTimeInterval) {
					needFlush = true
				}
			}

			needFlush = needFlush || endOfStreamReceived
			if !needFlush {
				ctx.SetContext(bufferPendingContentCtxKey, buffer)
				continue
			}

			if len(buffer) == 0 {
				proxywasm.InjectEncodedDataToFilterChain(bytes.Join(bufferQueue, []byte("")), endOfStreamReceived)
				bufferQueue = clearBufferState(ctx, false)
				continue
			}

			ctx.SetContext(duringCallCtxKey, true)
			currentSubmissionIndex = cfg.BeginGuardrailSubmissionEvent(ctx, cfg.GuardrailPhaseResponse, cfg.GuardrailModalityText)
			path, headers, reqBody := GenerateRequestForOutputCheck(config, buffer, sessionID)
			err := config.Client.Post(path, headers, reqBody, callback, config.Timeout)
			if err != nil {
				log.Errorf("failed to call tianjian security check service: %v", err)
				startTime, _ := ctx.GetContext(responseStartTimeCtxKey).(int64)
				cfg.MarkGuardrailResponseError(ctx, currentSubmissionIndex, nil, startTime)
				proxywasm.InjectEncodedDataToFilterChain(bytes.Join(bufferQueue, []byte("")), endOfStreamReceived)
				bufferQueue = clearBufferState(ctx, true)
			}
		}

		if endOfStreamReceived && len(bufferQueue) > 0 {

			if len(buffer) == 0 {
				proxywasm.InjectEncodedDataToFilterChain(bytes.Join(bufferQueue, []byte("")), endOfStreamReceived)
				bufferQueue = clearBufferState(ctx, false)
				proxywasm.ResumeHttpResponse()
				return
			}

			ctx.SetContext(duringCallCtxKey, true)
			currentSubmissionIndex = cfg.BeginGuardrailSubmissionEvent(ctx, cfg.GuardrailPhaseResponse, cfg.GuardrailModalityText)
			path, headers, reqBody := GenerateRequestForOutputCheck(config, buffer, sessionID)
			err := config.Client.Post(path, headers, reqBody, callback, config.Timeout)
			if err != nil {
				log.Errorf("failed to call tianjian security check service: %v", err)
				startTime, _ := ctx.GetContext(responseStartTimeCtxKey).(int64)
				cfg.MarkGuardrailResponseError(ctx, currentSubmissionIndex, nil, startTime)
				proxywasm.InjectEncodedDataToFilterChain(bytes.Join(bufferQueue, []byte("")), true)
				bufferQueue = clearBufferState(ctx, false)
				proxywasm.ResumeHttpResponse()
			}
		}
	}

	if !ctx.GetContext(riskDetectedCtxKey).(bool) {
		unifiedChunk := wrapper.UnifySSEChunk(data)
		hasTrailingSeparator := bytes.HasSuffix(unifiedChunk, []byte("\n\n"))
		trimmedChunk := bytes.TrimSpace(unifiedChunk)
		chunks := bytes.Split(trimmedChunk, []byte("\n\n"))
		nonEmptyChunks := make([][]byte, 0, len(chunks))
		for _, chunk := range chunks {
			if len(chunk) > 0 {
				nonEmptyChunks = append(nonEmptyChunks, chunk)
			}
		}
		for i := range len(nonEmptyChunks) - 1 {
			nonEmptyChunks[i] = append(nonEmptyChunks[i], []byte("\n\n")...)
		}
		if hasTrailingSeparator && len(nonEmptyChunks) > 0 {
			nonEmptyChunks[len(nonEmptyChunks)-1] = append(nonEmptyChunks[len(nonEmptyChunks)-1], []byte("\n\n")...)
		}
		for _, chunk := range nonEmptyChunks {
			ctx.PushBuffer(chunk)
		}
		ctx.SetContext(endOfStreamReceivedCtxKey, endOfStream)

		if !ctx.GetContext(duringCallCtxKey).(bool) {
			singleCall()
		}
	} else if endOfStream {
		proxywasm.ResumeHttpResponse()
	}
	return []byte{}
}

// ================== Response Body Handler ==================

func HandleTextGenerationResponseBody(ctx wrapper.HttpContext, config cfg.AISecurityConfig, body []byte) types.Action {
	_, _ = ctx.GetContext("consumer").(string)
	responseFallbackPaths := getEffectiveFallbackPathsFromContext(ctx, responseFallbackPathsCtxKey, config.ResponseContentJsonPath, config.ResponseContentFallbackJsonPaths)
	streamFallbackPaths := getEffectiveFallbackPathsFromContext(ctx, responseStreamFallbackPathsCtxKey, config.ResponseStreamContentJsonPath, config.ResponseStreamContentFallbackJsonPaths)

	startTime := time.Now().UnixMilli()
	contentType, _ := proxywasm.GetHttpResponseHeader("content-type")
	isStreamingResponse := strings.Contains(contentType, "event-stream")

	var content string
	if isStreamingResponse {
		content = utils.ExtractMessageFromStreamingBody(body, config.ResponseStreamContentJsonPath)
		if len(content) == 0 {
			content = autoExtractStreamingResponseFromSSE(body, streamFallbackPaths)
		}
	} else {
		content = gjson.GetBytes(body, config.ResponseContentJsonPath).String()
		if len(content) == 0 {
			content = autoExtractResponseContent(body, responseFallbackPaths)
		}
	}
	if len(content) == 0 {
		log.Info("response content is empty. skip tianjian check")
		return types.ActionContinue
	}

	contentIndex := 0
	lastChunkStart := 0
	sessionID, _ := utils.GenerateHexID(20)
	currentSubmissionIndex := 0
	retryCount := 0
	var singleCall func()

	callback := func(statusCode int, responseHeaders http.Header, responseBody []byte) {
		if statusCode != 200 {
			log.Errorf("Tianjian response check failed with status code %d", statusCode)
			if retryCount < 1 {
				retryCount++
				log.Warnf("Tianjian response check: retrying after error (retry %d)", retryCount)
				contentIndex = lastChunkStart
				singleCall()
			} else {
				log.Errorf("Tianjian response check: retry exhausted")
				denyMessage := resolveDenyMessage(config, content, "")
				proxywasm.SendHttpResponse(uint32(config.DenyCode), [][2]string{{"content-type", "application/json"}}, []byte(denyMessage), -1)
				config.IncrementCounter("ai_sec_response_deny", 1)
				cfg.MarkGuardrailResponseError(ctx, currentSubmissionIndex, responseBody, startTime)
			}
			return
		}

		var outerResp cfg.TianjianOuterResponse
		err := json.Unmarshal(responseBody, &outerResp)
		if err != nil {
			log.Errorf("failed to unmarshal tianjian response at response phase: %v", err)
			if retryCount < 1 {
				retryCount++
				log.Warnf("Tianjian response check: retrying after unmarshal error (retry %d)", retryCount)
				contentIndex = lastChunkStart
				singleCall()
			} else {
				log.Errorf("Tianjian response check: retry exhausted after unmarshal error")
				denyMessage := resolveDenyMessage(config, content, "")
				proxywasm.SendHttpResponse(uint32(config.DenyCode), [][2]string{{"content-type", "application/json"}}, []byte(denyMessage), -1)
				config.IncrementCounter("ai_sec_response_deny", 1)
				cfg.MarkGuardrailResponseError(ctx, currentSubmissionIndex, responseBody, startTime)
			}
			return
		}
		tianjianResp := outerResp.Response
		// Retry on Tianjian error response (e.g., INTERNAL_ERROR with empty action_code)
		if tianjianResp.ActionCode == "" && retryCount < 1 {
			retryCount++
			log.Warnf("Tianjian response check: tianjian returned error response, retrying (retry %d, result_code=%s)", retryCount, tianjianResp.ResultCode)
			contentIndex = lastChunkStart
			singleCall()
			return
		}

		if cfg.IsTianjianRiskAcceptable(tianjianResp) {
			if contentIndex >= len(content) {
				endTime := time.Now().UnixMilli()
				ctx.SetUserAttribute("safecheck_response_rt", endTime-startTime)
				ctx.SetUserAttribute("safecheck_status", "response pass")
			}
			cfg.CompleteGuardrailSubmissionEvent(ctx, currentSubmissionIndex, responseBody, cfg.GuardrailResultPass)
			if contentIndex >= len(content) {
				cfg.WriteGuardrailLog(ctx)
				proxywasm.ResumeHttpResponse()
			} else {
				singleCall()
			}
			return
		}

		// Risk detected — send deny response
		log.Infof("Tianjian response blocked: actionCode=%s", tianjianResp.ActionCode)
		tianjianAnswer := tianjianDenyAnswer(tianjianResp)
		denyMessage := resolveDenyMessage(config, content, tianjianAnswer)
		if config.ProtocolOriginal {
			proxywasm.SendHttpResponse(uint32(config.DenyCode), [][2]string{{"content-type", "application/json"}}, []byte(denyMessage), -1)
		} else {
			denyData, buildErr := buildTianjianDenyData(config, isStreamingResponse, content, tianjianAnswer)
			if buildErr != nil {
				log.Errorf("failed to build tianjian deny data: %v", buildErr)
				cfg.MarkGuardrailResponseError(ctx, currentSubmissionIndex, responseBody, startTime)
				proxywasm.ResumeHttpResponse()
				return
			}
			proxywasm.SendHttpResponse(uint32(config.DenyCode), openAIDenyContentType(isStreamingResponse), denyData, -1)
		}
		config.IncrementCounter("ai_sec_response_deny", 1)
		endTime := time.Now().UnixMilli()
		ctx.SetUserAttribute("safecheck_response_rt", endTime-startTime)
		ctx.SetUserAttribute("safecheck_status", "response deny")
		if len(tianjianResp.Labels) > 0 {
			ctx.SetUserAttribute("safecheck_riskLabel", tianjianResp.Labels[0].Label)
		}
		cfg.CompleteGuardrailSubmissionEvent(ctx, currentSubmissionIndex, responseBody, cfg.GuardrailResultDeny)
		cfg.WriteGuardrailLog(ctx)
	}

	singleCall = func() {
		lastChunkStart = contentIndex
		var nextContentIndex int
		if contentIndex+cfg.LengthLimit >= len(content) {
			nextContentIndex = len(content)
		} else {
			nextContentIndex = contentIndex + cfg.LengthLimit
		}
		contentPiece := content[contentIndex:nextContentIndex]
		contentIndex = nextContentIndex
		currentSubmissionIndex = cfg.BeginGuardrailSubmissionEvent(ctx, cfg.GuardrailPhaseResponse, cfg.GuardrailModalityText)
		path, headers, reqBody := GenerateRequestForOutputCheck(config, contentPiece, sessionID)
		err := config.Client.Post(path, headers, reqBody, callback, config.Timeout)
		if err != nil {
			log.Errorf("failed to call tianjian security check service: %v", err)
			cfg.MarkGuardrailResponseError(ctx, currentSubmissionIndex, nil, startTime)
			proxywasm.ResumeHttpResponse()
		}
	}
	singleCall()
	return types.ActionPause
}

// ================== Helper Functions ==================

func resolveDenyMessage(config cfg.AISecurityConfig, userInput string, tianjianAnswer string) string {
	// Priority 1: User-configured custom denyMessage
	if config.DenyMessage != "" {
		return config.DenyMessage
	}
	// Priority 2: Tianjian's security_answer or limit_answer
	if tianjianAnswer != "" {
		return tianjianAnswer
	}
	// Priority 3: Language-aware default message based on input
	return cfg.ResolveDenyMessageForInput(config, userInput)
}

// tianjianDenyAnswer extracts the deny message from Tianjian response (security_answer or limit_answer)
func tianjianDenyAnswer(resp cfg.TianjianResponse) string {
	if resp.SecurityAnswer != "" {
		return resp.SecurityAnswer
	}
	return resp.LimitAnswer
}

func isStreamingFromCtx(ctx wrapper.HttpContext) bool {
	streaming, _ := ctx.GetContext(streamingCtxKey).(bool)
	return streaming
}

func buildTianjianDenyData(config cfg.AISecurityConfig, isStream bool, userInput string, tianjianAnswer string) ([]byte, error) {
	marshalledDenyMessage := wrapper.MarshalStr(resolveDenyMessage(config, userInput, tianjianAnswer))
	randomID := utils.GenerateRandomChatID()
	createdTs := time.Now().Unix()

	if config.OpenAIDenyResponseFormat == cfg.OpenAIDenyResponseFormatStructured {
		guardrailBody, err := cfg.BuildOpenAIFallbackDenyResponseBody(config)
		if err != nil {
			return nil, err
		}
		if isStream {
			return []byte(fmt.Sprintf(cfg.OpenAIStreamResponseFormatStructured, randomID, createdTs, marshalledDenyMessage, randomID, createdTs, string(guardrailBody))), nil
		}
		return []byte(fmt.Sprintf(cfg.OpenAIResponseFormatStructured, randomID, createdTs, marshalledDenyMessage, string(guardrailBody))), nil
	}

	if isStream {
		return []byte(fmt.Sprintf(cfg.OpenAIStreamResponseFormatLegacy, randomID, createdTs, marshalledDenyMessage, randomID, createdTs)), nil
	}
	return []byte(fmt.Sprintf(cfg.OpenAIResponseFormatLegacy, randomID, createdTs, marshalledDenyMessage)), nil
}

func clearBufferState(ctx wrapper.HttpContext, resetDuringCall bool) [][]byte {
	var emptyQueue [][]byte
	ctx.SetContext(bufferQueueCtxKey, emptyQueue)
	ctx.SetContext(bufferPendingContentCtxKey, "")
	ctx.SetContext(startTsCtxKey, time.Now().UnixMilli())
	if resetDuringCall {
		ctx.SetContext(duringCallCtxKey, false)
	}
	return emptyQueue
}

func openAIDenyContentType(isStream bool) [][2]string {
	if isStream {
		return [][2]string{{"content-type", "text/event-stream;charset=UTF-8"}}
	}
	return [][2]string{{"content-type", "application/json"}}
}

// ================== Fallback Path & Content Extraction Helpers ==================

func buildEffectiveFallbackPaths(primaryPath string, fallbackPaths []string) []string {
	primaryPath = strings.TrimSpace(primaryPath)
	if len(fallbackPaths) == 0 {
		return []string{}
	}
	deduped := make([]string, 0, len(fallbackPaths))
	seen := make(map[string]struct{}, len(fallbackPaths))
	for _, path := range fallbackPaths {
		path = strings.TrimSpace(path)
		if len(path) == 0 || path == primaryPath {
			continue
		}
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		deduped = append(deduped, path)
	}
	if len(deduped) == 0 {
		return []string{}
	}
	return deduped
}

type fallbackPathContext interface {
	GetContext(key string) interface{}
	SetContext(key string, value interface{})
}

func getEffectiveFallbackPathsFromContext(ctx fallbackPathContext, ctxKey string, primaryPath string, fallbackPaths []string) []string {
	if cached, ok := ctx.GetContext(ctxKey).([]string); ok {
		return cached
	}
	effective := buildEffectiveFallbackPaths(primaryPath, fallbackPaths)
	ctx.SetContext(ctxKey, effective)
	return effective
}

func autoExtractResponseContent(body []byte, fallbackPaths []string) string {
	if len(fallbackPaths) == 0 {
		return ""
	}
	parsed := gjson.ParseBytes(body)
	return extractTextByPaths(parsed, fallbackPaths)
}

func autoExtractStreamingResponseContent(chunk []byte, fallbackPaths []string) string {
	if len(fallbackPaths) == 0 {
		return ""
	}
	payload := bytes.TrimSpace(chunk)
	if len(payload) == 0 {
		return ""
	}
	if !isJSONPayload(payload) {
		payload = extractSSEDataPayload(payload)
		if len(payload) == 0 {
			return ""
		}
	}
	if !json.Valid(payload) {
		return ""
	}
	parsed := gjson.ParseBytes(payload)
	return extractTextByPaths(parsed, fallbackPaths)
}

func isJSONPayload(payload []byte) bool {
	return len(payload) > 0 && (payload[0] == '{' || payload[0] == '[')
}

func extractSSEDataPayload(chunk []byte) []byte {
	lines := bytes.Split(chunk, []byte("\n"))
	dataLines := make([][]byte, 0, len(lines))
	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if !bytes.HasPrefix(line, []byte("data:")) {
			continue
		}
		data := bytes.TrimSpace(bytes.TrimPrefix(line, []byte("data:")))
		if len(data) == 0 {
			continue
		}
		if bytes.Equal(data, []byte("[DONE]")) {
			return nil
		}
		dataLines = append(dataLines, data)
	}
	if len(dataLines) == 0 {
		return nil
	}
	return bytes.TrimSpace(bytes.Join(dataLines, []byte("\n")))
}

func extractTextByPaths(parsed gjson.Result, paths []string) string {
	for _, path := range paths {
		path = strings.TrimSpace(path)
		if len(path) == 0 {
			continue
		}
		result := parsed.Get(path)
		if !result.Exists() {
			continue
		}
		if text := extractTextFromResult(result); len(text) > 0 {
			log.Debugf("response fallback path matched: %s", path)
			return text
		}
	}
	return ""
}

func extractTextFromResult(result gjson.Result) string {
	if result.IsArray() {
		var parts []string
		for _, item := range result.Array() {
			if s := item.String(); len(s) > 0 {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, "")
	}
	return result.String()
}

func autoExtractStreamingResponseFromSSE(data []byte, fallbackPaths []string) string {
	if len(fallbackPaths) == 0 {
		return ""
	}
	chunks := bytes.Split(bytes.TrimSpace(wrapper.UnifySSEChunk(data)), []byte("\n\n"))
	var parts []string
	for _, chunk := range chunks {
		if s := autoExtractStreamingResponseContent(chunk, fallbackPaths); len(s) > 0 {
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, "")
}
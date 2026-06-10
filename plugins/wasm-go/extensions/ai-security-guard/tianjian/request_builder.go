package tianjian

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"net/url"
	"strings"
	"time"

	cfg "github.com/alibaba/higress/plugins/wasm-go/extensions/ai-security-guard/config"
	"github.com/alibaba/higress/plugins/wasm-go/extensions/ai-security-guard/utils"
)

const (
	AntchainGatewayPath         = "/gateway.do"
	AntchainAPIVersion          = "1.0"
	AntchainMethodInputCheck    = "aitech.comm.security.question.query"
	AntchainMethodOutputCheck   = "aitech.comm.security.answer.query"
)

// GenerateRequestForInputCheck builds the HTTP request for Tianjian input detection.
// Returns path, headers, and request body suitable for config.Client.Post().
// Matches the official antchain-openapi-sdk-go request construction exactly.
func GenerateRequestForInputCheck(config cfg.AISecurityConfig, content string, sessionID string) (path string, headers [][2]string, reqBody []byte) {
	// Build business params (form-urlencoded body)
	formParams := url.Values{}
	formParams.Set("enterprise", config.Enterprise)
	formParams.Set("businessId", config.BusinessId)
	formParams.Set("question", content)
	formParams.Set("sceneCode", config.TianjianSceneCodeInput)
	formParams.Set("sessionId", sessionID)

	if config.TianjianPromptAttackDefense {
		formParams.Set("promptAttackDefense", "Y")
	}
	if config.TianjianMultiSessionDetect {
		formParams.Set("multiSessionDetect", "Y")
	}
	if config.TianjianFinanceComplianceDetection {
		formParams.Set("financeComplianceDetection", "Y")
	}
	if config.TianjianPrivacyDataDetection {
		formParams.Set("privacyDataDetection", "Y")
	}
	if config.TianjianFieldIdentify {
		formParams.Set("fieldIdentify", "Y")
	}
	if config.TianjianPromptReword {
		formParams.Set("promptReword", "Y")
	}

	reqBodyStr := formParams.Encode()

	// Build common query params (matching SDK exactly)
	commonParams := buildCommonParams(config, AntchainMethodInputCheck)

	// Compute signature over (common params + business params) — matches SDK:
	//   signedParam := tea.Merge(request_.Query, rpcutil.Query(request))
	signedParams := make(map[string]string)
	for k, v := range commonParams {
		signedParams[k] = v
	}
	businessParams := parseFormUrlencoded(reqBodyStr)
	for k, v := range businessParams {
		signedParams[k] = v
	}

	// Compute signature
	sign := computeAntchainSignature(signedParams, config.TianjianSK)

	// Build final URL: ONLY common params + sign in query string
	// In the SDK: request_.Query contains only common params, then sign is added
	// Business params go ONLY in the body, NOT in the URL
	queryParams := make(map[string]string)
	for k, v := range commonParams {
		queryParams[k] = v
	}
	queryParams["sign"] = sign

	path = AntchainGatewayPath + "?" + encodeSortedParams(queryParams)

	headers = [][2]string{
		{"content-type", "application/x-www-form-urlencoded"},
	}

	return path, headers, []byte(reqBodyStr)
}

// GenerateRequestForOutputCheck builds the HTTP request for Tianjian output detection.
// Returns path, headers, and request body suitable for config.Client.Post().
func GenerateRequestForOutputCheck(config cfg.AISecurityConfig, content string, sessionID string) (path string, headers [][2]string, reqBody []byte) {
	// Build business params (form-urlencoded body)
	formParams := url.Values{}
	formParams.Set("enterprise", config.Enterprise)
	formParams.Set("businessId", config.BusinessId)
	formParams.Set("content", content)
	formParams.Set("sceneCode", config.TianjianSceneCodeOutput)
	formParams.Set("sessionId", sessionID)

	if config.TianjianPrivacyDataObfuscation {
		formParams.Set("privacyDataObfuscation", "Y")
	}
	if config.TianjianPromptReword {
		formParams.Set("promptReword", "Y")
	}
	if config.TianjianPrivacyDataDetection {
		formParams.Set("privacyDataDetection", "Y")
	}

	reqBodyStr := formParams.Encode()

	// Build common query params
	commonParams := buildCommonParams(config, AntchainMethodOutputCheck)

	// Compute signature over (common params + business params)
	signedParams := make(map[string]string)
	for k, v := range commonParams {
		signedParams[k] = v
	}
	businessParams := parseFormUrlencoded(reqBodyStr)
	for k, v := range businessParams {
		signedParams[k] = v
	}

	// Compute signature
	sign := computeAntchainSignature(signedParams, config.TianjianSK)

	// Build final URL: ONLY common params + sign in query string
	queryParams := make(map[string]string)
	for k, v := range commonParams {
		queryParams[k] = v
	}
	queryParams["sign"] = sign

	path = AntchainGatewayPath + "?" + encodeSortedParams(queryParams)

	headers = [][2]string{
		{"content-type", "application/x-www-form-urlencoded"},
	}

	return path, headers, []byte(reqBodyStr)
}

// buildCommonParams constructs the common query parameters required by all antchain API calls.
// Matches the official SDK's request construction exactly:
//   request_.Query = map[string]*string{
//       "method":           action,
//       "version":          version,
//       "sign_type":        "HmacSHA1",
//       "req_time":         antchainutil.GetTimestamp(),
//       "req_msg_id":       antchainutil.GetNonce(),
//       "access_key":       client.AccessKeyId,
//       "base_sdk_version": "TeaSDK-2.0",
//       "sdk_version":      "1.1.62",
//       "_prod_code":       "AITECH",
//       "_prod_channel":    "default",
//   }
func buildCommonParams(config cfg.AISecurityConfig, method string) map[string]string {
	gmt := time.FixedZone("GMT", 0)
	reqTime := time.Now().In(gmt).Format("2006-01-02T15:04:05Z")
	reqMsgId, _ := utils.GenerateHexID(32)

	return map[string]string{
		"method":           method,
		"version":          AntchainAPIVersion,
		"sign_type":        "HmacSHA1",
		"req_time":         reqTime,
		"req_msg_id":       reqMsgId,
		"access_key":       config.TianjianAK,
		"base_sdk_version": "TeaSDK-2.0",
		"sdk_version":      "1.1.62",
		"_prod_code":       "AITECH",
		"_prod_channel":    "default",
	}
}

// computeAntchainSignature computes the HMAC-SHA1 signature for antchain API requests.
// Matches the official antchain-openapi-util-sdk Go implementation:
// 1. Use url.Values.Encode() for standard URL encoding
// 2. Apply 3 post-encoding replacements: + -> %20, * -> %2A, %7E -> ~
// 3. HMAC-SHA1 sign with secret key, then base64 encode
func computeAntchainSignature(params map[string]string, secretKey string) string {
	// Step 1: Build the string to sign using url.Values.Encode() (same as official SDK)
	values := url.Values{}
	for k, v := range params {
		values.Set(k, v)
	}
	stringToSign := values.Encode()

	// Step 2: Apply the 3 replacements from the official SDK's buildStringToSign
	stringToSign = strings.Replace(stringToSign, "+", "%20", -1)
	stringToSign = strings.Replace(stringToSign, "*", "%2A", -1)
	stringToSign = strings.Replace(stringToSign, "%7E", "~", -1)

	// Step 3: HMAC-SHA1 sign, base64 encode
	h := hmac.New(sha1.New, []byte(secretKey))
	h.Write([]byte(stringToSign))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// encodeSortedParams encodes all parameters into a URL query string.
// Uses url.Values.Encode() which sorts keys and uses standard URL encoding.
func encodeSortedParams(params map[string]string) string {
	values := url.Values{}
	for k, v := range params {
		values.Set(k, v)
	}
	return values.Encode()
}

// parseFormUrlencoded parses a form-urlencoded string into a map[string]string.
func parseFormUrlencoded(encoded string) map[string]string {
	result := map[string]string{}
	values, err := url.ParseQuery(encoded)
	if err != nil {
		return result
	}
	for k, vs := range values {
		if len(vs) > 0 {
			result[k] = vs[0]
		}
	}
	return result
}
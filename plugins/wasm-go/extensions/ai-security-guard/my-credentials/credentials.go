package my_credentials

import (
	"encoding/json"
	"fmt"
	"github.com/higress-group/proxy-wasm-go-sdk/proxywasm"
	"github.com/higress-group/wasm-go/pkg/log"
	"github.com/higress-group/wasm-go/pkg/wrapper"
	"github.com/tidwall/gjson"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/errors"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/utils"
)

const (
	AliyunUserAgent = "CIPFrom/AIGateway"
)

type assumedRoleUser struct {
}

type credentials struct {
	SecurityToken   *string `json:"SecurityToken"`
	Expiration      *string `json:"Expiration"`
	AccessKeySecret *string `json:"AccessKeySecret"`
	AccessKeyId     *string `json:"AccessKeyId"`
}

type assumeRoleResponse struct {
	RequestID       *string          `json:"RequestId"`
	AssumedRoleUser *assumedRoleUser `json:"AssumedRoleUser"`
	Credentials     *credentials     `json:"Credentials"`
}

type generateSessionAccessKeyResponse struct {
	RequestID        *string           `json:"RequestId"`
	SessionAccessKey *sessionAccessKey `json:"SessionAccessKey"`
}

type sessionAccessKey struct {
	SessionAccessKeyId     *string `json:"SessionAccessKeyId"`
	SessionAccessKeySecret *string `json:"SessionAccessKeySecret"`
	Expiration             *string `json:"Expiration"`
}

type SessionCredentials struct {
	AccessKeyId     string
	AccessKeySecret string
	SecurityToken   string
	Expiration      string
}

type Credentials struct {
	AccessKeyId     string
	AccessKeySecret string
	SecurityToken   string
	BearerToken     string
	ProviderName    string
}

type do func(req *http.Request) (*http.Response, error)

var hookDo = func(fn do) do {
	return fn
}

type newReuqest func(method, url string, body io.Reader) (*http.Request, error)

var hookNewRequest = func(fn newReuqest) newReuqest {
	return fn
}

type HttpOptions struct {
	// Connection timeout
	ConnectTimeout time.Duration
	// Read timeout
	ReadTimeout time.Duration
}

type CredentialsProvider interface {
	GetCredentials(func(cred *Credentials))
	GetProviderName() string
}

type OIDCCredentialsProvider struct {
	rrsaServiceClient wrapper.HttpClient
	stsServiceClient  wrapper.HttpClient
	oidcProviderARN   string
	oidcTokenFilePath string
	roleArn           string
	roleSessionName   string
	durationSeconds   int
	policy            string
	// for sts endpoint
	stsRegion           string
	enableVpc           bool
	lastUpdateTimestamp int64
	expirationTimestamp int64
	sessionCredentials  *SessionCredentials
	// for http options
	httpOptions *HttpOptions

	rrsaInfoServiceName string
	rrsaInfoServicePort int64
	oidcTokenContent    string
	stsServiceHost      string
	stsServiceName      string
	stsServicePort      int64
}

type OIDCCredentialsProviderBuilder struct {
	provider *OIDCCredentialsProvider
}

func NewOIDCCredentialsProviderBuilder() *OIDCCredentialsProviderBuilder {
	return &OIDCCredentialsProviderBuilder{
		provider: &OIDCCredentialsProvider{},
	}
}

func (b *OIDCCredentialsProviderBuilder) WithOIDCProviderARN(oidcProviderArn string) *OIDCCredentialsProviderBuilder {
	b.provider.oidcProviderARN = oidcProviderArn
	return b
}

func (b *OIDCCredentialsProviderBuilder) WithOIDCTokenFilePath(oidcTokenFilePath string) *OIDCCredentialsProviderBuilder {
	b.provider.oidcTokenFilePath = oidcTokenFilePath
	return b
}
func (b *OIDCCredentialsProviderBuilder) WithRrsaInfoServiceName(rrsaInfoServiceName string) *OIDCCredentialsProviderBuilder {
	b.provider.rrsaInfoServiceName = rrsaInfoServiceName
	return b
}
func (b *OIDCCredentialsProviderBuilder) WithRrsaInfoServicePort(rrsaInfoServicePort int64) *OIDCCredentialsProviderBuilder {
	b.provider.rrsaInfoServicePort = rrsaInfoServicePort
	return b
}
func (b *OIDCCredentialsProviderBuilder) WithOIDCTokenContent(oidcTokenContent string) *OIDCCredentialsProviderBuilder {
	b.provider.oidcTokenContent = oidcTokenContent
	return b
}

func (b *OIDCCredentialsProviderBuilder) WithRoleArn(roleArn string) *OIDCCredentialsProviderBuilder {
	b.provider.roleArn = roleArn
	return b
}

func (b *OIDCCredentialsProviderBuilder) WithRoleSessionName(roleSessionName string) *OIDCCredentialsProviderBuilder {
	b.provider.roleSessionName = roleSessionName
	return b
}

func (b *OIDCCredentialsProviderBuilder) WithDurationSeconds(durationSeconds int) *OIDCCredentialsProviderBuilder {
	b.provider.durationSeconds = durationSeconds
	return b
}

func (b *OIDCCredentialsProviderBuilder) WithStsRegion(region string) *OIDCCredentialsProviderBuilder {
	b.provider.stsRegion = region
	return b
}

func (b *OIDCCredentialsProviderBuilder) WithEnableVpc(enableVpc bool) *OIDCCredentialsProviderBuilder {
	b.provider.enableVpc = enableVpc
	return b
}
func (b *OIDCCredentialsProviderBuilder) WithStsServiceHost(stsServiceHost string) *OIDCCredentialsProviderBuilder {
	b.provider.stsServiceHost = stsServiceHost
	return b
}
func (b *OIDCCredentialsProviderBuilder) WithStsServiceName(stsServiceName string) *OIDCCredentialsProviderBuilder {
	b.provider.stsServiceName = stsServiceName
	return b
}

func (b *OIDCCredentialsProviderBuilder) WithStsServicePort(stsServicePort int64) *OIDCCredentialsProviderBuilder {
	b.provider.stsServicePort = stsServicePort
	return b
}

func (b *OIDCCredentialsProviderBuilder) WithPolicy(policy string) *OIDCCredentialsProviderBuilder {
	b.provider.policy = policy
	return b
}

func (b *OIDCCredentialsProviderBuilder) WithHttpOptions(httpOptions *HttpOptions) *OIDCCredentialsProviderBuilder {
	b.provider.httpOptions = httpOptions
	return b
}

func (b *OIDCCredentialsProviderBuilder) Build() (provider *OIDCCredentialsProvider, err error) {
	provider = b.provider

	if provider.roleSessionName == "" {
		provider.roleSessionName = "aliyun-go-sdk-" + strconv.FormatInt(time.Now().UnixNano()/1000, 10)
	}
	if provider.rrsaInfoServiceName == "" || provider.rrsaInfoServicePort == 0 {
		err = errors.NewClientError(errors.InvalidParamErrorCode, "rrsaInfoServiceName or rrsaInfoServicePort can not be empty", nil)
		return
	}
	// sts endpoint
	//if provider.stsServiceName == "" || provider.stsServicePort == 0 {
	//	err = errors.NewClientError(errors.InvalidParamErrorCode, "stsServiceName or stsServicePort  can not be empty", nil)
	//	return
	//}
	//provider.stsServiceClient = wrapper.NewClusterClient(wrapper.FQDNCluster{
	//	FQDN: provider.stsServiceName,
	//	Port: provider.stsServicePort,
	//	Host: provider.stsServiceHost,
	//})
	provider.rrsaServiceClient = wrapper.NewClusterClient(wrapper.FQDNCluster{
		FQDN: provider.rrsaInfoServiceName,
		Port: provider.rrsaInfoServicePort,
	})

	if provider.durationSeconds == 0 {
		provider.durationSeconds = 3600
	}

	if provider.durationSeconds < 900 || provider.durationSeconds > 3600 {
		err = errors.NewClientError(errors.InvalidParamErrorCode, "Assume Role session duration should be in the range of 15min - 1hr", nil)
	}
	return
}

func (provider *OIDCCredentialsProvider) getCredentialsV3(getCredentialsCb func(sessionCredentials *SessionCredentials)) {
	log.Debug("start getCredentialsV3")
	callback := func(statusCode int, responseHeaders http.Header, responseBody []byte) {
		log.Debug("start rrsa server info api callback")
		if statusCode != 200 || gjson.GetBytes(responseBody, "code").Int() != 200 {
			log.Errorf("failed to get rrsa info  response at request phase. response: %v", string(responseBody))
			proxywasm.ResumeHttpRequest()
			return
		}
		var response SessionCredentialsResponse
		err := json.Unmarshal(responseBody, &response)
		if err != nil {
			log.Error("failed to unmarshal aliyun content security response at request phase")
			proxywasm.ResumeHttpRequest()
			return
		}
		getCredentialsCb(&response.Data)
	}

	singleCall := func() {
		err := provider.rrsaServiceClient.Get("/get_json/sts_credentials", [][2]string{{"User-Agent", AliyunUserAgent}}, callback, 5*1000)
		if err != nil {
			log.Errorf("failed call the safe check service: %v", err)
		}
	}
	singleCall()
}

// 这里能否发出http请求？
func (provider *OIDCCredentialsProvider) getCredentialsV2(callback func(sessionCredentials *SessionCredentials)) {
	log.Info("start getCredentialsV2")

	var responseCallback = func(statusCode int, responseHeaders http.Header, responseBody []byte) {
		log.Info("start getCredentialsV2 responseCallback")
		proxywasm.ResumeHttpRequest()
		//if statusCode != http.StatusOK {
		//	log.Errorf("get session token failed. ststusCode: %s. response: %v", statusCode, string(responseBody))
		//	proxywasm.ResumeHttpRequest()
		//	return
		//}
		//var response assumeRoleResponse
		//err := json.Unmarshal(responseBody, &response)
		//if err != nil {
		//	log.Errorf("get oidc sts token err, json.Unmarshal fail: %s", err.Error())
		//	proxywasm.ResumeHttpRequest()
		//	return
		//}
		//if response.Credentials == nil {
		//	log.Error("get oidc sts token err, fail to get credentials")
		//	proxywasm.ResumeHttpRequest()
		//	return
		//}
		//
		//if response.Credentials.AccessKeyId == nil || response.Credentials.AccessKeySecret == nil || response.Credentials.SecurityToken == nil {
		//	log.Error("refresh RoleArn sts token err, fail to get credentials")
		//	proxywasm.ResumeHttpRequest()
		//	return
		//}
		//
		//sessionCredentials := &SessionCredentials{
		//	AccessKeyId:     *response.Credentials.AccessKeyId,
		//	AccessKeySecret: *response.Credentials.AccessKeySecret,
		//	SecurityToken:   *response.Credentials.SecurityToken,
		//	Expiration:      *response.Credentials.Expiration,
		//}
		//callback(sessionCredentials)
	}

	var singleCall = func() {
		queries := make(map[string]string)
		queries["Version"] = "2015-04-01"
		queries["Action"] = "AssumeRoleWithOIDC"
		queries["Format"] = "JSON"
		queries["Timestamp"] = utils.GetTimeInFormatISO8601()

		bodyForm := make(map[string]string)
		bodyForm["RoleArn"] = provider.roleArn
		bodyForm["OIDCProviderArn"] = provider.oidcProviderARN
		bodyForm["OIDCToken"] = provider.oidcTokenContent
		if provider.policy != "" {
			bodyForm["Policy"] = provider.policy
		}
		bodyForm["RoleSessionName"] = provider.roleSessionName
		bodyForm["DurationSeconds"] = strconv.Itoa(provider.durationSeconds)

		querystring := utils.GetUrlFormedMap(queries)
		body := utils.GetUrlFormedMap(bodyForm)
		log.Infof("querystring is: %s", querystring)
		//log.Infof("body is: %s", body)
		rawUrl := fmt.Sprintf("/?%s", querystring)
		log.Infof("rawUrl is: %s", rawUrl)

		err := provider.stsServiceClient.Post(fmt.Sprintf("/?%s", querystring), [][2]string{{"User-Agent", AliyunUserAgent}}, []byte(body), responseCallback, 10*1000)
		if err != nil {
			log.Errorf("failed call sts service: %+v", err)
			proxywasm.ResumeHttpRequest()
		}
	}
	singleCall()
}

func (provider *OIDCCredentialsProvider) getCredentials() (sessionCredentials *SessionCredentials, err error) {
	log.Info("start getCredentials")
	method := "POST"
	var host string
	if provider.stsServiceName != "" {
		host = provider.stsServiceName
	} else if provider.stsRegion != "" {
		host = fmt.Sprintf("sts.%s.aliyuncs.com", provider.stsRegion)
	} else {
		host = "sts.aliyuncs.com"
	}

	queries := make(map[string]string)
	queries["Version"] = "2015-04-01"
	queries["Action"] = "AssumeRoleWithOIDC"
	queries["Format"] = "JSON"
	queries["Timestamp"] = utils.GetTimeInFormatISO8601()

	bodyForm := make(map[string]string)
	bodyForm["RoleArn"] = provider.roleArn
	bodyForm["OIDCProviderArn"] = provider.oidcProviderARN
	tokenStr := provider.oidcTokenContent
	if tokenStr == "" {
		token, err := ioutil.ReadFile(provider.oidcTokenFilePath)
		if err != nil {
			return nil, err
		}
		tokenStr = string(token)
	}
	bodyForm["OIDCToken"] = tokenStr
	if provider.policy != "" {
		bodyForm["Policy"] = provider.policy
	}

	bodyForm["RoleSessionName"] = provider.roleSessionName
	bodyForm["DurationSeconds"] = strconv.Itoa(provider.durationSeconds)

	// caculate signature
	signParams := make(map[string]string)
	for key, value := range queries {
		signParams[key] = value
	}
	for key, value := range bodyForm {
		signParams[key] = value
	}

	stringToSign := utils.GetUrlFormedMap(signParams)
	stringToSign = strings.Replace(stringToSign, "+", "%20", -1)
	stringToSign = strings.Replace(stringToSign, "*", "%2A", -1)
	stringToSign = strings.Replace(stringToSign, "%7E", "~", -1)
	stringToSign = url.QueryEscape(stringToSign)
	stringToSign = method + "&%2F&" + stringToSign

	secret := provider.sessionCredentials.AccessKeySecret
	queries["Signature"] = utils.ShaHmac1(stringToSign, secret)

	querystring := utils.GetUrlFormedMap(queries)
	// do request
	httpUrl := fmt.Sprintf("https://%s/?%s", host, querystring)

	body := utils.GetUrlFormedMap(bodyForm)

	httpRequest, err := hookNewRequest(http.NewRequest)(method, httpUrl, strings.NewReader(body))
	if err != nil {
		return
	}

	// set headers
	httpRequest.Header["Accept-Encoding"] = []string{"identity"}
	httpRequest.Header["Content-Type"] = []string{"application/x-www-form-urlencoded"}

	connectTimeout := 5 * time.Second
	readTimeout := 10 * time.Second
	if provider.httpOptions != nil && provider.httpOptions.ConnectTimeout > 0 {
		connectTimeout = provider.httpOptions.ConnectTimeout
	}
	if provider.httpOptions != nil && provider.httpOptions.ReadTimeout > 0 {
		readTimeout = provider.httpOptions.ReadTimeout
	}
	transport := http.DefaultTransport.(*http.Transport)

	httpClient := &http.Client{
		Timeout:   connectTimeout + readTimeout,
		Transport: transport,
	}

	httpResponse, err := hookDo(httpClient.Do)(httpRequest)
	if err != nil {
		return
	}

	defer httpResponse.Body.Close()

	responseBody, err := ioutil.ReadAll(httpResponse.Body)
	if err != nil {
		return
	}

	if httpResponse.StatusCode != http.StatusOK {
		message := "get session token failed"
		err = errors.NewServerError(httpResponse.StatusCode, string(responseBody), message)
		return
	}
	var data assumeRoleResponse
	err = json.Unmarshal(responseBody, &data)
	if err != nil {
		err = fmt.Errorf("get oidc sts token err, json.Unmarshal fail: %s", err.Error())
		return
	}
	if data.Credentials == nil {
		err = fmt.Errorf("get oidc sts token err, fail to get credentials")
		return
	}

	if data.Credentials.AccessKeyId == nil || data.Credentials.AccessKeySecret == nil || data.Credentials.SecurityToken == nil {
		err = fmt.Errorf("refresh RoleArn sts token err, fail to get credentials")
		return
	}

	sessionCredentials = &SessionCredentials{
		AccessKeyId:     *data.Credentials.AccessKeyId,
		AccessKeySecret: *data.Credentials.AccessKeySecret,
		SecurityToken:   *data.Credentials.SecurityToken,
		Expiration:      *data.Credentials.Expiration,
	}
	return
}

func (provider *OIDCCredentialsProvider) needUpdateCredential() (result bool) {
	if provider.expirationTimestamp == 0 {
		return true
	}

	return provider.expirationTimestamp-time.Now().Unix() <= 180
}

func getRrsaEnvInfo(provider *OIDCCredentialsProvider, getRrsaEnvInfoCb func()) {
	callback := func(statusCode int, responseHeaders http.Header, responseBody []byte) {
		log.Info("start rrsa server info api callback")
		if statusCode != 200 || gjson.GetBytes(responseBody, "code").Int() != 200 {
			log.Errorf("failed to get rrsa info  response at request phase. response: %v", string(responseBody))
			proxywasm.ResumeHttpRequest()
			return
		}
		var response RrsaEnvInfoResponse
		err := json.Unmarshal(responseBody, &response)
		if err != nil {
			log.Error("failed to unmarshal aliyun content security response at request phase")
			proxywasm.ResumeHttpRequest()
			return
		}
		rrsaInfo := response.Data
		provider.oidcProviderARN = rrsaInfo.OidcProviderArn
		provider.roleArn = rrsaInfo.RoleArn
		provider.oidcTokenContent = rrsaInfo.Token
		getRrsaEnvInfoCb()
	}

	singleCall := func() {
		err := provider.rrsaServiceClient.Get("/get_json/data", [][2]string{{"User-Agent", AliyunUserAgent}}, callback, 60*1000)
		if err != nil {
			log.Errorf("failed call the safe check service: %v", err)
		}
	}
	singleCall()
}

type SessionCredentialsResponse struct {
	Data      SessionCredentials `json:"data"`
	Code      int                `json:"code"`
	Message   string             `json:"message"`
	RequestId string             `json:"requestId"`
}

type RrsaEnvInfoResponse struct {
	Data      rrsaEnvInfo `json:"data"`
	Code      int         `json:"code"`
	Message   string      `json:"message"`
	RequestId string      `json:"requestId"`
}

type rrsaEnvInfo struct {
	RoleArn         string `json:"roleArn"`
	OidcProviderArn string `json:"oidcProviderArn"`
	Token           string `json:"token"`
}

func (provider *OIDCCredentialsProvider) GetCredentialsV3(callback func(cred *Credentials)) {
	log.Debug("start GetCredentials")
	if provider.sessionCredentials == nil || provider.needUpdateCredential() {

		var getCredentialsCb = func(sessionCredentials *SessionCredentials) {
			provider.sessionCredentials = sessionCredentials
			expirationTime, err2 := time.Parse("2006-01-02T15:04:05Z", sessionCredentials.Expiration)
			if err2 != nil {
				log.Errorf("failed to parse expiration time: %v", err2)
				proxywasm.ResumeHttpRequest()
				return
			}

			provider.lastUpdateTimestamp = time.Now().Unix()
			provider.expirationTimestamp = expirationTime.Unix()
			cc := &Credentials{
				AccessKeyId:     provider.sessionCredentials.AccessKeyId,
				AccessKeySecret: provider.sessionCredentials.AccessKeySecret,
				SecurityToken:   provider.sessionCredentials.SecurityToken,
				ProviderName:    provider.GetProviderName(),
			}
			callback(cc)
		}

		provider.getCredentialsV3(getCredentialsCb)
	} else {
		cc := &Credentials{
			AccessKeyId:     provider.sessionCredentials.AccessKeyId,
			AccessKeySecret: provider.sessionCredentials.AccessKeySecret,
			SecurityToken:   provider.sessionCredentials.SecurityToken,
			ProviderName:    provider.GetProviderName(),
		}
		callback(cc)
	}
}

func (provider *OIDCCredentialsProvider) GetCredentials(callback func(cred *Credentials)) {
	log.Info("start GetCredentials")
	if provider.sessionCredentials == nil || provider.needUpdateCredential() {

		var getCredentialsCb = func(sessionCredentials *SessionCredentials) {
			provider.sessionCredentials = sessionCredentials
			expirationTime, err2 := time.Parse("2006-01-02T15:04:05Z", sessionCredentials.Expiration)
			if err2 != nil {
				log.Errorf("failed to parse expiration time: %v", err2)
				proxywasm.ResumeHttpRequest()
				return
			}

			provider.lastUpdateTimestamp = time.Now().Unix()
			provider.expirationTimestamp = expirationTime.Unix()
			cc := &Credentials{
				AccessKeyId:     provider.sessionCredentials.AccessKeyId,
				AccessKeySecret: provider.sessionCredentials.AccessKeySecret,
				SecurityToken:   provider.sessionCredentials.SecurityToken,
				ProviderName:    provider.GetProviderName(),
			}
			callback(cc)
		}
		// 实际是： getCredentials
		var getRrsaEnvInfoCb = func() {
			log.Info("start getRrsaEnvInfoCb")
			provider.getCredentialsV2(getCredentialsCb)
		}
		getRrsaEnvInfo(provider, getRrsaEnvInfoCb)
	} else {
		cc := &Credentials{
			AccessKeyId:     provider.sessionCredentials.AccessKeyId,
			AccessKeySecret: provider.sessionCredentials.AccessKeySecret,
			SecurityToken:   provider.sessionCredentials.SecurityToken,
			ProviderName:    provider.GetProviderName(),
		}
		callback(cc)
	}
}

func (provider *OIDCCredentialsProvider) GetProviderName() string {
	return "oidc_role_arn"
}

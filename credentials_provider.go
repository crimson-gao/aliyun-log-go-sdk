package sls

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-kit/kit/log/level"
)

const CRED_TIME_FORMAT = time.RFC3339

type CredentialsProvider interface {
	GetCredentials() (Credentials, error)
}

/**
 * A static credetials provider that always returns the same long-lived credentials.
 * For back compatible.
 */
type StaticCredProvider struct {
	Cred Credentials
}

// Create a static credential provider with AccessKeyID/AccessKeySecret/SecurityToken.
//
// Param accessKeyID and accessKeySecret must not be an empty string.
func NewStaticCredProvider(accessKeyID, accessKeySecret, securityToken string) *StaticCredProvider {
	return &StaticCredProvider{
		Cred: Credentials{
			AccessKeyID:     accessKeyID,
			AccessKeySecret: accessKeySecret,
			SecurityToken:   securityToken,
		},
	}
}

func (p *StaticCredProvider) GetCredentials() (Credentials, error) {
	return p.Cred, nil
}

type RequestBuilder = func() (*http.Request, error)
type RespParser = func(*http.Response) (*TempCredentials, error)
type CredentialsFetcher = func() (*TempCredentials, error)

// Combine RequestBuilder and RespParser, return a CredentialsFetcher
func NewCredentialsFetcher(builder RequestBuilder, parser RespParser) CredentialsFetcher {
	return func() (*TempCredentials, error) {
		req, err := builder()
		if err != nil {
			return nil, fmt.Errorf("fail to build http request: %w", err)
		}
		client := http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("fail to do http request: %w", err)
		}
		defer resp.Body.Close()
		cred, err := parser(resp)
		if err != nil {
			return nil, fmt.Errorf("fail to parse http response: %w", err)
		}
		return cred, nil
	}
}

// Wraps a CredentialsFetcher with retry.
//
// @param retryTimes If <= 0, no retry will be performed.
func fetcherWithRetry(fetcher CredentialsFetcher, retryTimes int) CredentialsFetcher {
	return func() (*TempCredentials, error) {
		times := retryTimes
		errs := make([]error, 0)
		for times >= 0 {
			times--
			cred, err := fetcher()
			if err == nil {

				return cred, nil
			}
			errs = append(errs, err)
		}
		return nil, fmt.Errorf("exceed max retry times, errors: %w",
			joinErrors(errs...))
	}
}

// Replace this with errors.Join when go version >= 1.20
func joinErrors(errs ...error) error {
	if errs == nil {
		return nil
	}
	errStrs := make([]string, 0, len(errs))
	for _, e := range errs {
		errStrs = append(errStrs, e.Error())
	}
	return fmt.Errorf("[%s]", strings.Join(errStrs, ", "))
}

const UPDATE_FUNC_RETRY_TIMES = 3
const UPDATE_FUNC_FETCH_ADVANCED_DURATION = time.Second * 60 * 10

// Adapter for porting UpdateTokenFunc to a CredentialsProvider.
type UpdateFuncProviderAdapter struct {
	cred    *Credentials
	fetcher CredentialsFetcher

	expirationInMills int64
	advanceDuration   time.Duration // fetch before credentials expires in advance
}

// Returns a new CredentialsProvider.
func NewUpdateFuncProviderAdapter(updateFunc UpdateTokenFunction) *UpdateFuncProviderAdapter {
	retryTimes := UPDATE_FUNC_RETRY_TIMES
	fetcher := fetcherWithRetry(updateFuncFetcher(updateFunc), retryTimes)

	return &UpdateFuncProviderAdapter{
		advanceDuration: UPDATE_FUNC_FETCH_ADVANCED_DURATION,
		fetcher:         fetcher,
	}
}

func updateFuncFetcher(updateFunc UpdateTokenFunction) CredentialsFetcher {
	return func() (*TempCredentials, error) {
		id, secret, token, expireTime, err := updateFunc()
		if err != nil {
			return nil, fmt.Errorf("updateTokenFunc fetch credentials failed: %w", err)
		}

		if !checkValid(id, secret, token, expireTime) {
			return nil, fmt.Errorf("updateTokenFunc result not valid, expirationTime:%s",
				expireTime.Format(time.RFC3339))
		}
		return NewTempCredentials(id, secret, token, expireTime.UnixMilli(), -1), nil
	}

}

// If credentials expires or will be exipred soon, fetch a new credentials and return it.
//
// Otherwise returns the credentials fetched last time.
//
// Retry at most maxRetryTimes if failed to fetch.
func (adp *UpdateFuncProviderAdapter) GetCredentials() (Credentials, error) {
	if !adp.shouldRefresh() {
		return *adp.cred, nil
	}
	level.Debug(Logger).Log("reason", "updateTokenFunc start to fetch new credentials")

	res, err := adp.fetcher() // res.lastUpdatedTime is not valid, do not use it

	if err != nil {
		return Credentials{}, fmt.Errorf("updateTokenFunc fail to fetch credentials, err:%w", err)
	}
	adp.cred = &res.Credentials
	adp.expirationInMills = res.expirationInMills
	level.Debug(Logger).Log("reason", "updateTokenFunc fetch new credentials succeed",
		"expirationTime", time.UnixMilli(adp.expirationInMills).Format(CRED_TIME_FORMAT),
	)
	return *adp.cred, nil
}

// Returns true if no credentials ever fetched or credentials expired,
// or credentials will be expired soon
func (adp *UpdateFuncProviderAdapter) shouldRefresh() bool {
	if adp.cred == nil {
		return true
	}
	now := time.Now()
	return time.UnixMilli(adp.expirationInMills).Sub(now) <= adp.advanceDuration
}

func checkValid(accessKeyID, accessKeySecret, securityToken string, expirationTime time.Time) bool {
	return accessKeyID != "" && accessKeySecret != "" && expirationTime.UnixMilli() > 0
}

const ECS_RAM_ROLE_URL_PREFIX = "http://100.100.100.200/latest/meta-data/ram/security-credentials/"
const ECS_RAM_ROLE_RETRY_TIMES = 3

// The ECS instance RAM role is a kind of RAM role, which allows the ECS instance to
// act as a role with certain permissions. The ECS instance can use the temporary
// access credentials of the role to access specified Alibaba Cloud services,
// such as SLS, OSS, RDS, and realize secured communication between the ECS
// instance and other Alibaba Cloud services.
type EcsRamRoleCredentialsProvider struct {
	ramRole   string
	fetcher   CredentialsFetcher
	cred      *TempCredentials
	urlPrefix string
}

// Return an ecs ram role credentials provider.
func NewEcsRamRoleCredProvider(ramRole string) *EcsRamRoleCredentialsProvider {
	reqBuider := newEcsRamRoleReqBuilder(ECS_RAM_ROLE_URL_PREFIX, ramRole)
	fetcher := NewCredentialsFetcher(reqBuider, ecsRamRoleParser)
	retryFetcher := fetcherWithRetry(fetcher, ECS_RAM_ROLE_RETRY_TIMES)

	return &EcsRamRoleCredentialsProvider{
		ramRole:   ramRole,
		fetcher:   retryFetcher,
		cred:      nil,
		urlPrefix: ECS_RAM_ROLE_URL_PREFIX,
	}
}

// Build http GET request with url(urlPrefix + ramRole)
func newEcsRamRoleReqBuilder(urlPrefix, ramRole string) func() (*http.Request, error) {
	return func() (*http.Request, error) {
		url := urlPrefix + ramRole
		return http.NewRequest(http.MethodGet, url, nil)
	}
}

// Parse ECS Ram Role http response, convert it to TempCredentials
func ecsRamRoleParser(resp *http.Response) (*TempCredentials, error) {
	// 1. read body
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("fail to read http resp body: %w", err)
	}
	fetchResp := EcsRamRoleHttpResp{}
	// 2. unmarshal
	err = json.Unmarshal(data, &fetchResp)
	if err != nil {
		return nil, fmt.Errorf("fail to unmarshal json: %w, body: %s", err, string(data))
	}
	// 3. check json param
	if !fetchResp.isValid() {
		return nil, fmt.Errorf("invalid fetch result, body: %s", string(data))
	}
	return NewTempCredentials(
		fetchResp.AccessKeyID,
		fetchResp.AccessKeySecret,
		fetchResp.SecurityToken, fetchResp.Expiration, fetchResp.LastUpdated), nil
}

// Response struct for http response of ecs ram role fetch request
type EcsRamRoleHttpResp struct {
	Code            string `json:"Code"`
	AccessKeyID     string `json:"AccessKeyId"`
	AccessKeySecret string `json:"AccessKeySecret"`
	SecurityToken   string `json:"SecurityToken"`
	Expiration      int64  `json:"Expiration"`
	LastUpdated     int64  `json:"LastUpdated"`
}

func (r *EcsRamRoleHttpResp) isValid() bool {
	return strings.ToLower(r.Code) == "success" && r.AccessKeyID != "" &&
		r.AccessKeySecret != "" && r.Expiration > 0 && r.LastUpdated > 0
}

// If credentials expires or will be exipred soon, fetch a new credentials and return it.
//
// Otherwise returns the credentials fetched last time.
//
//	Retry at most maxRetryTimes if failed to fetch.
func (p *EcsRamRoleCredentialsProvider) GetCredentials() (Credentials, error) {
	if p.cred != nil && !p.cred.ShouldRefresh() {
		return p.cred.Credentials, nil
	}
	level.Debug(Logger).Log("reason", "ecsRamRole start to fetch new credentials")

	cred, err := p.fetcher()

	if err != nil {
		if !p.cred.HasExpired() { // if credentials still valid, return it
			level.Warn(Logger).Log("ecsRamRole fetch credentials failed, credentials still valid, use it", err)
			return cred.Credentials, nil
		}
		return Credentials{}, fmt.Errorf("ecsRamRole fetch credentials, err: %w", err)
	}
	p.cred = cred
	level.Debug(Logger).Log("reason", "fetch new credentials succeed",
		"expirationTime", time.UnixMilli(cred.expirationInMills).Format(CRED_TIME_FORMAT),
		"updateTime", time.UnixMilli(cred.lastUpdatedInMills).Format(CRED_TIME_FORMAT),
	)
	return cred.Credentials, nil
}

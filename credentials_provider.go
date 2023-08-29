package sls

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
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
type StaticCredentialsProvider struct {
	Cred Credentials
}

// Create a static credential provider with AccessKeyID/AccessKeySecret/SecurityToken.
//
// Param accessKeyID and accessKeySecret must not be an empty string.
func NewStaticCredentialsProvider(accessKeyID, accessKeySecret, securityToken string) *StaticCredentialsProvider {
	return &StaticCredentialsProvider{
		Cred: Credentials{
			AccessKeyID:     accessKeyID,
			AccessKeySecret: accessKeySecret,
			SecurityToken:   securityToken,
		},
	}
}

func (p *StaticCredentialsProvider) GetCredentials() (Credentials, error) {
	return p.Cred, nil
}

type CredentialsRequestBuilder = func() (*http.Request, error)
type CredentialsRespParser = func(*http.Response) (*TempCredentials, error)
type CredentialsFetcher = func() (*TempCredentials, error)

// Combine RequestBuilder and RespParser, return a CredentialsFetcher
func NewCredentialsFetcher(builder CredentialsRequestBuilder, parser CredentialsRespParser, customClient *http.Client) CredentialsFetcher {
	return func() (*TempCredentials, error) {
		req, err := builder()
		if err != nil {
			return nil, fmt.Errorf("fail to build http request: %w", err)
		}

		var client *http.Client
		if customClient != nil {
			client = customClient
		} else {
			client = &http.Client{}
		}

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
		var errs []error
		for i := 0; i <= retryTimes; i++ {
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

	mutex             sync.RWMutex
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

		if !checkSTSTokenValid(id, secret, token, expireTime) {
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

	adp.mutex.Lock()
	defer adp.mutex.Unlock()
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
	adp.mutex.RLock()
	defer adp.mutex.RUnlock()

	if adp.cred == nil {
		return true
	}
	now := time.Now()
	return time.UnixMilli(adp.expirationInMills).Sub(now) <= adp.advanceDuration
}

func checkSTSTokenValid(accessKeyID, accessKeySecret, securityToken string, expirationTime time.Time) bool {
	return accessKeyID != "" && accessKeySecret != "" && expirationTime.UnixMilli() > 0
}

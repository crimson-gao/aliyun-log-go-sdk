package sls

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestDefaultHttpClient(t *testing.T) {
	project1, err := NewLogProject("test-project", "cn-hangzhou.log.aliyuncs.com", "", "")
	assert.NoError(t, err)
	assert.Equal(t, project1.httpClient, defaultHttpClient)
	assert.Equal(t, defaultHttpClient.Transport.(*http.Transport).DisableKeepAlives, defaultHttpClientDisableKeepAlives)
	assert.Equal(t, defaultHttpClient.Transport.(*http.Transport).IdleConnTimeout, defaultHttpClientIdleTimeout)
	assert.Equal(t, defaultHttpClient.Timeout, defaultRequestTimeout)

	// reset config
	ResetDefaultHttpClientIdleTimeout(time.Second * 60)
	ResetDefaultHttpClientDisableKeepAlives(true)
	assert.Equal(t, defaultHttpClientDisableKeepAlives, true)
	assert.Equal(t, defaultHttpClientIdleTimeout, time.Second*60)
	project2, err := NewLogProject("test-project", "cn-hangzhou.log.aliyuncs.com", "", "")
	assert.NoError(t, err)
	assert.Equal(t, project2.httpClient, defaultHttpClient)
	client := project2.httpClient
	assert.Equal(t, client.Transport.(*http.Transport).DisableKeepAlives, true)
	assert.Equal(t, client.Transport.(*http.Transport).IdleConnTimeout, time.Second*60)
	// with timeout
	project2 = project2.WithRequestTimeout(time.Second * 33)
	assert.NotEqual(t, project2.httpClient, defaultHttpClient) // changed
	assert.Equal(t, project2.httpClient.Transport.(*http.Transport).DisableKeepAlives, true)
	assert.NotEqual(t, defaultRequestTimeout, time.Second*33)
	assert.Equal(t, project2.httpClient.Timeout, time.Second*33)
	assert.NotEqual(t, defaultHttpClient.Timeout, project2.httpClient.Timeout)
	// with proxy
	project3, err := NewLogProject("test-project", "127.0.0.1", "", "")
	assert.NoError(t, err)
	assert.NotEqual(t, project3.httpClient, defaultHttpClient) // changed
	transport := project3.httpClient.Transport.(*http.Transport)
	assert.Equal(t, project3.httpClient.Timeout, defaultRequestTimeout)
	assert.Equal(t, transport.DisableKeepAlives, true)
	assert.Equal(t, transport.IdleConnTimeout, time.Second*60)
	assert.NotNil(t, transport.Proxy)

}

package sls

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestDNSCache(t *testing.T) {
	resolver := NewResolver()
	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				cHost, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				d := net.Dialer{
					Timeout: defaultRequestTimeout, // timeout 5s
				}

				if ips, err := resolver.Get(ctx, cHost); err != nil {
					return d.DialContext(ctx, network, addr)
				} else {
					for _, ip := range ips {
						if conn, err := d.DialContext(ctx, network, net.JoinHostPort(ip, port)); err == nil {
							return conn, nil
						}
					}
					return d.DialContext(ctx, network, addr)
				}

			},
		},
		Timeout: defaultRequestTimeout,
	}
	_, err := httpClient.Get("https://www.baidu.com/")
	assert.Nil(t, err)
	assert.Equal(t, 1, resolver.GetCacheNum())
	_, err = httpClient.Get("https://www.baidu.com/")
	assert.Nil(t, err)
	assert.Equal(t, 1, resolver.GetCacheNum())
	_, err = httpClient.Get("https://www.aliyun.com/")
	assert.Nil(t, err)
	assert.Equal(t, 2, resolver.GetCacheNum())
	_, err = httpClient.Get("https://www.aliyun.com/")
	assert.Nil(t, err)
	assert.Equal(t, 2, resolver.GetCacheNum())
	_, err = httpClient.Get("https://cn.bing.com/")
	assert.Nil(t, err)
	assert.Equal(t, 3, resolver.GetCacheNum())
	_, err = httpClient.Get("https://cn.bing.com/")
	assert.Nil(t, err)
	assert.Equal(t, 3, resolver.GetCacheNum())
}

func TestTimeout(t *testing.T) {
	t.Skip("this will cost at least 3 minutes")
	resolver := NewResolver()
	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				cHost, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				d := net.Dialer{
					Timeout: defaultRequestTimeout, // timeout 5s
				}

				if ips, err := resolver.Get(ctx, cHost); err != nil {
					return d.DialContext(ctx, network, addr)
				} else {
					for _, ip := range ips {
						if conn, err := d.DialContext(ctx, network, net.JoinHostPort(ip, port)); err == nil {
							return conn, nil
						}
					}
					return d.DialContext(ctx, network, addr)
				}

			},
		},
		Timeout: defaultRequestTimeout,
	}
	_, err := httpClient.Get("https://www.baidu.com/")
	assert.Nil(t, err)
	time.Sleep(1 * time.Minute)
	assert.Equal(t, 1, resolver.GetCacheNum())
	_, err = httpClient.Get("https://www.aliyun.com/")
	assert.Nil(t, err)
	time.Sleep(1 * time.Minute)
	assert.Equal(t, 2, resolver.GetCacheNum())
	resolver.deleteTimoutCachedIps(60)
	assert.Equal(t, 0, resolver.GetCacheNum())
	httpClient.Get("https://www.aliyun.com/")
	httpClient.Get("https://www.baidu.com/")
	assert.Equal(t, 2, resolver.GetCacheNum())
	time.Sleep(1 * time.Minute)
	_, err = httpClient.Get("https://cn.bing.com/")
	assert.Nil(t, err)
	assert.Equal(t, 3, resolver.GetCacheNum())
	resolver.deleteTimoutCachedIps(60)
	assert.Equal(t, 1, resolver.GetCacheNum())
}

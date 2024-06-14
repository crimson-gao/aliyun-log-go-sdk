package sls

import (
	"context"
	"net"
	"sync"
	"time"
)

var (
	dnsCacheTimeOut     = 2 * time.Minute
	maxAllowDnsCacheNum = 10000
)

type ipInfo struct {
	ips         []string
	refreshTime time.Time
}

type dnsCachedResolver struct {
	lock  sync.RWMutex
	cache map[string]ipInfo
}

func newDnsResolver() *dnsCachedResolver {
	newResolver := &dnsCachedResolver{
		cache: make(map[string]ipInfo, 0),
	}
	return newResolver
}

func (r *dnsCachedResolver) Get(ctx context.Context, host string) ([]string, error) {
	r.lock.RLock()
	ipInfo, exists := r.cache[host]
	r.lock.RUnlock()
	if exists && ipInfo.refreshTime.Add(dnsCacheTimeOut).After(time.Now()) {
		return ipInfo.ips, nil
	}
	return r.lookup(ctx, host)
}

func (r *dnsCachedResolver) GetCacheNum() int {
	r.lock.RLock()
	defer r.lock.RUnlock()
	return len(r.cache)
}

func (r *dnsCachedResolver) Clear() {
	r.lock.Lock()
	r.cache = make(map[string]ipInfo, 0)
	r.lock.Unlock()
}

func (r *dnsCachedResolver) deleteTimoutCachedIps(expireTimeSecond int) {
	expireTime := dnsCacheTimeOut
	if expireTimeSecond >= 60 {
		expireTime = time.Duration(expireTimeSecond) * time.Second
	}
	newCache := make(map[string]ipInfo, 0)
	r.lock.RLock()
	for k, v := range r.cache {
		if v.refreshTime.Add(expireTime).After(time.Now()) {
			newCache[k] = v
		}
	}
	r.lock.RUnlock()
	r.lock.Lock()
	r.cache = newCache
	r.lock.Unlock()
}

func (r *dnsCachedResolver) lookup(ctx context.Context, host string) ([]string, error) {
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, nil
	}
	strIPs := make([]string, len(ips))
	for index, ip := range ips {
		strIPs[index] = ip.String()
	}
	r.lock.Lock()
	r.cache[host] = ipInfo{ips: strIPs, refreshTime: time.Now()}
	l := len(r.cache)
	r.lock.Unlock()
	if l > maxAllowDnsCacheNum {
		r.deleteTimoutCachedIps(0)
	}
	return strIPs, nil
}

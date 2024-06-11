package sls

import (
	"context"
	"net"
	"sync"
	"time"
)

var (
	cacheTimeOut     = 15 * time.Minute
	maxAllowCacheNum = 10000
)

type IpInfo struct {
	ips         []string
	refreshTime time.Time
}

type DNSCachedResolver struct {
	lock  sync.RWMutex
	cache map[string]IpInfo
}

func NewResolver() *DNSCachedResolver {
	newResolver := &DNSCachedResolver{
		cache: make(map[string]IpInfo, 0),
	}
	return newResolver
}

func (r *DNSCachedResolver) Get(ctx context.Context, host string) ([]string, error) {
	r.lock.RLock()
	ipInfo, exists := r.cache[host]
	r.lock.RUnlock()
	if exists && ipInfo.refreshTime.Add(cacheTimeOut).After(time.Now()) {
		return ipInfo.ips, nil
	}
	return r.lookup(ctx, host)
}

func (r *DNSCachedResolver) GetCacheNum() int {
	return len(r.cache)
}

func (r *DNSCachedResolver) deleteTimoutCachedIps(expireTimeSecond int) {
	expireTime := cacheTimeOut
	if expireTimeSecond >= 60 {
		expireTime = time.Duration(expireTimeSecond) * time.Second
	}
	newCache := make(map[string]IpInfo, 0)
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

func (r *DNSCachedResolver) Clear() {
	r.lock.Lock()
	r.cache = make(map[string]IpInfo, 0)
	r.lock.Unlock()
}

func (r *DNSCachedResolver) lookup(ctx context.Context, host string) ([]string, error) {
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
	r.cache[host] = IpInfo{ips: strIPs, refreshTime: time.Now()}
	r.lock.Unlock()
	if len(r.cache) > maxAllowCacheNum {
		r.deleteTimoutCachedIps(0)
	}
	return strIPs, nil
}

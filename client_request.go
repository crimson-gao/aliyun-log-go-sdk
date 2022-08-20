package sls

// request sends a request to SLS.
import (
	"bytes"
	"encoding/json"
	"fmt"

	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"strings"

	"github.com/aliyun/aliyun-log-go-sdk/sign"
	"github.com/go-kit/kit/log/level"
	"github.com/pkg/errors"
)

// request sends a request to alibaba cloud Log Service.
// @note if error is nil, you must call http.Response.Body.Close() to finalize reader
func (c *Client) request(project, method, uri string, headers map[string]string, body []byte) (*http.Response, error) {
	// The caller should provide 'x-log-bodyrawsize' header
	if _, ok := headers["x-log-bodyrawsize"]; !ok {
		return nil, fmt.Errorf("Can't find 'x-log-bodyrawsize' header")
	}

	var endpoint string
	var usingHTTPS bool
	if strings.HasPrefix(c.Endpoint, "https://") {
		endpoint = c.Endpoint[8:]
		usingHTTPS = true
	} else if strings.HasPrefix(c.Endpoint, "http://") {
		endpoint = c.Endpoint[7:]
	} else {
		endpoint = c.Endpoint
	}

	// SLS public request headers
	var hostStr string
	if len(project) == 0 {
		hostStr = endpoint
	} else {
		hostStr = project + "." + endpoint
	}
	headers["Host"] = hostStr
	// headers["Date"] = nowRFC1123() // do in signature
	headers["x-log-apiversion"] = version
	headers["x-log-signaturemethod"] = signatureMethod

	if len(c.UserAgent) > 0 {
		headers["User-Agent"] = c.UserAgent
	} else {
		headers["User-Agent"] = DefaultLogUserAgent
	}

	c.accessKeyLock.RLock()
	stsToken := c.SecurityToken
	accessKeyID := c.AccessKeyID
	accessKeySecret := c.AccessKeySecret
	c.accessKeyLock.RUnlock()

	// Access with token
	if stsToken != "" {
		headers["x-acs-security-token"] = stsToken
	}

	if _, ok := headers["Content-Type"]; !ok && body != nil {
		return nil, fmt.Errorf("can't find 'Content-Type' header")
	}

	// Sign for request
	signer, err := sign.GetSigner(accessKeyID, accessKeySecret, c.SignVersion, c.Region)
	if err != nil {
		return nil, errors.Wrap(err, "getSigner")
	}
	err = signer.Sign(method, uri, headers, body)
	if err != nil {
		return nil, errors.Wrap(err, "sign")
	}

	// Initialize http request
	reader := bytes.NewReader(body)
	var urlStr string
	// using http as default
	if !GlobalForceUsingHTTP && usingHTTPS {
		urlStr = "https://"
	} else {
		urlStr = "http://"
	}
	urlStr += hostStr + uri
	req, err := http.NewRequest(method, urlStr, reader)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Add(k, v)
	}
	if IsDebugLevelMatched(5) {
		dump, e := httputil.DumpRequest(req, true)
		if e != nil {
			level.Info(Logger).Log("msg", e)
		}
		level.Info(Logger).Log("msg", "HTTP Request:\n%v", string(dump))
	}

	// Get ready to do request
	httpClient := c.HTTPClient
	if httpClient == nil {
		httpClient = defaultHttpClient
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	// Parse the sls error from body.
	if resp.StatusCode != http.StatusOK {
		err := &Error{}
		err.HTTPCode = (int32)(resp.StatusCode)
		defer resp.Body.Close()
		buf, _ := ioutil.ReadAll(resp.Body)
		json.Unmarshal(buf, err)
		err.RequestID = resp.Header.Get("x-log-requestid")
		return nil, err
	}
	if IsDebugLevelMatched(5) {
		dump, e := httputil.DumpResponse(resp, true)
		if e != nil {
			level.Info(Logger).Log("msg", e)
		}
		level.Info(Logger).Log("msg", "HTTP Response:\n%v", string(dump))
	}

	return resp, nil
}

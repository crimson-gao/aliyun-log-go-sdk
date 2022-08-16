package signer

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	EMPTY_STRING_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

// Key is lowercased
var DEFAULT_SIGNED_HEADERS = map[string]bool{
	"host":         true,
	"content-type": true,
}

// Sign version v4, a non-empty region is required
type SignerV4 struct {
	accessKeyID     string
	accessKeySecret string
	region          string
}

func NewSignerV4(accessKeyID, accessKeySecret, region string) *SignerV4 {
	return &SignerV4{
		accessKeyID:     accessKeyID,
		accessKeySecret: accessKeySecret,
		region:          region,
	}
}

func (s *SignerV4) Sign(method, uriWithQuery string, headers map[string]string, body []byte) error {
	if s.region == "" {
		return errors.New("SignType v4 require a valid region")
	}

	uri, urlParams, err := parseUri(uriWithQuery)
	if err != nil {
		return err
	}

	// If content-type value is empty string, server will ignore it.
	// So we add a default value here.
	if typ, ok := headers["Content-Type"]; ok && len(typ) == 0 {
		headers["Content-Type"] = "application/json"
	}
	// Date & dateTime
	date, dateTime := dateISO8601(), dateTimeISO8601()
	if d, ok := headers["x-log-date"]; ok { // for debuging
		dateTime = d
		date = dateTime[:len("20060102")]
	}

	sha256Payload := EMPTY_STRING_SHA256
	contentLength := len(body)
	if len(body) != 0 {
		sha256Payload = fmt.Sprintf("%x", sha256.Sum256(body))
	}

	// Set http header
	headers["x-log-content-sha256"] = sha256Payload
	headers["x-log-date"] = dateTime
	headers["Content-Length"] = strconv.Itoa(len(body))
	headers["Content-Length"] = strconv.Itoa(contentLength)

	// Caninocal header & signedHeaderStr
	canonHeaders := buildCanonicalHeader(headers)
	signedHeaderStr := buildSignedHeaderStr(canonHeaders)

	// CanonicalRequest
	canonReq := buildCanonicalRequest(method, uri, signedHeaderStr, sha256Payload, urlParams, canonHeaders)
	scope := buildScope(date, s.region)

	// SignKey + signMessage => signature
	msg := buildSignMessage(canonReq, dateTime, scope)
	key, err := buildSignKey(s.accessKeySecret, s.region, date)
	if err != nil {
		return fmt.Errorf("buildSignKey: %w", err)
	}
	hash, err := hmacSha256([]byte(msg), key)
	if err != nil {
		return fmt.Errorf("hmac-sha256 signMessgae: %w", err)
	}
	signature := fmt.Sprintf("%x", hash)
	// Auth
	auth := buildAuthorization(s.accessKeyID, signedHeaderStr, signature, scope)
	headers["Authorization"] = auth

	// For debuging
	// fmt.Println("sha256Payload: ", sha256Payload)
	// fmt.Println("dateTime: ", dateTime)
	// fmt.Println("canonReq: ", canonReq)
	// fmt.Println("signMessage: ", msg)
	// fmt.Printf("signKey: %x\n", key)
	// fmt.Println("signature: ", signature)
	// fmt.Println("authorization: ", auth)
	return nil
}

func parseUri(uriWithQuery string) (string, map[string]string, error) {
	u, err := url.Parse(uriWithQuery)
	if err != nil {
		return "", nil, fmt.Errorf("uriWithQuery: %w", err)
	}
	urlParams := make(map[string]string)
	for k, vals := range u.Query() {
		if len(vals) == 0 {
			urlParams[k] = ""
		} else {
			urlParams[k] = vals[0] // param val should has at most one value
		}
	}
	return u.Path, urlParams, nil
}

func dateISO8601() string {
	return time.Now().In(gmtLoc).Format("20060102")
}

func dateTimeISO8601() string {
	return time.Now().In(gmtLoc).Format("20060102T150405Z")
}

func buildCanonicalHeader(headers map[string]string) map[string]string {
	res := make(map[string]string)
	for k, v := range headers {
		lower := strings.ToLower(k)
		_, ok := DEFAULT_SIGNED_HEADERS[lower]
		if ok || strings.HasPrefix(lower, "x-log-") || strings.HasPrefix(lower, "x-acs-") {
			res[lower] = v
		}
	}
	return res
}

func buildSignedHeaderStr(canonicalHeaders map[string]string) string {
	res, sep := "", ""
	forEachSorted(canonicalHeaders, func(k, v string) {
		res += sep + k
		sep = ";"
	})
	return res
}

// Iterate over m in sorted order, and apply func f
func forEachSorted(m map[string]string, f func(k, v string)) {
	var ss sort.StringSlice
	for k := range m {
		ss = append(ss, k)
	}
	ss.Sort()
	for _, k := range ss {
		f(k, m[k])
	}
}

func buildCanonicalRequest(method, uri, signedHeaderStr, sha256Payload string, urlParams, canonicalHeaders map[string]string) string {
	res := ""

	res += method + "\n"
	res += urlEncode(uri, true) + "\n"

	// Url params
	canonParams := make(map[string]string)
	for k, v := range urlParams {
		ck := urlEncode(strings.TrimSpace(k), false)
		cv := urlEncode(strings.TrimSpace(v), false)
		canonParams[ck] = cv
	}

	sep := ""
	forEachSorted(canonParams, func(k, v string) {
		res += sep + k
		sep = "&"
		if len(v) != 0 {
			res += "=" + v
		}
	})
	res += "\n"

	// Canonical headers
	forEachSorted(canonicalHeaders, func(k, v string) {
		res += k + ":" + strings.TrimSpace(v) + "\n"
	})
	res += "\n"

	res += signedHeaderStr + "\n"
	res += sha256Payload
	return res
}

func urlEncode(uri string, ignoreSlash bool) string {
	u := url.QueryEscape(uri)
	u = strings.ReplaceAll(u, "+", "%20")
	u = strings.ReplaceAll(u, "*", "%2A")
	if ignoreSlash {
		u = strings.ReplaceAll(u, "%2F", "/")
	}
	return u
}

func buildScope(date, region string) string {

	return date + "/" + region + "/sls/aliyun_v4_request"
}

func buildSignMessage(canonReq, dateTime, scope string) string {
	return "SLS4-HMAC-SHA256" + "\n" + dateTime + "\n" + scope + "\n" + fmt.Sprintf("%x", sha256.Sum256([]byte(canonReq)))
}

func hmacSha256(message, key []byte) ([]byte, error) {
	hmac := hmac.New(sha256.New, key)
	_, err := hmac.Write(message)
	if err != nil {
		return nil, err
	}
	return hmac.Sum(nil), nil
}

func buildSignKey(accessKeySecret, region, date string) ([]byte, error) {
	signDate, err := hmacSha256([]byte(date), []byte("aliyun_v4"+accessKeySecret))
	if err != nil {
		return nil, fmt.Errorf("sign date: %w", err)
	}
	signRegion, err := hmacSha256([]byte(region), signDate)
	if err != nil {
		return nil, fmt.Errorf("sign region: %w", err)
	}
	signService, err := hmacSha256([]byte("sls"), signRegion)
	if err != nil {
		return nil, fmt.Errorf("sign product name: %w", err)
	}
	signAll, err := hmacSha256([]byte("aliyun_v4_request"), signService)
	if err != nil {
		return nil, fmt.Errorf("sign terminator: %w", err)
	}
	return signAll, nil
}

func buildAuthorization(accessKeyID, signedHeaderStr, signature, scope string) string {
	return fmt.Sprintf("SLS4-HMAC-SHA256 Credential=%s/%s,SignedHeaders=%s,Signature=%s",
		accessKeyID, scope, signedHeaderStr, signature)
}

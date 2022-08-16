package signer

import "errors"

const (
	SignVerionV1  = "v1"
	SignVersionV4 = "v4"
)

type Signer interface {
	// Sign modifies @param headers only, adds signature and other http headers
	// that log services authorization requires.
	Sign(method, uriWithQuery string, headers map[string]string, body []byte) error
}

// Param signVersion could be "v1" or "v4", if empty string is passed, "v1" is selected as default.
// If SignVersion is v4, a valid non-empty region is required.
func GetSigner(accessKeyID, accessKeySecret, signVersion, region string) (Signer, error) {
	switch signVersion {
	case "": // default sign version = v1
		return NewSignerV1(accessKeyID, accessKeySecret), nil
	case SignVerionV1:
		return NewSignerV1(accessKeyID, accessKeySecret), nil
	case SignVersionV4:
		return NewSignerV4(accessKeyID, accessKeySecret, region), nil

	default:
		return nil, errors.New("signVersion " + signVersion + " is invalid")
	}
}

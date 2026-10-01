package license

import "errors"

var (
	ErrMalformedLicense        = errors.New("license: malformed license envelope")
	ErrInvalidSignature        = errors.New("license: signature verification failed")
	ErrUnsupportedVersion      = errors.New("license: unsupported license format version")
	ErrUnknownIssuerKey        = errors.New("license: envelope references unknown issuer key")
	ErrDeviceMismatch          = errors.New("license: license is bound to a different device")
	ErrNotYetValid             = errors.New("license: license is not valid yet")
	ErrExpired                 = errors.New("license: license has expired")
	ErrRevocationDataInvalid   = errors.New("license: revocation data is present but invalid")
	ErrRevocationDataMissing   = errors.New("license: revocation data is missing, so revocation was not checked")
	ErrRevoked                 = errors.New("license: license has been revoked")
	ErrMalformedRevocationList = errors.New("license: malformed revocation list")
	ErrStaleRevocationData     = errors.New("license: revocation data is older than the state already known")
	ErrRevocationStore         = errors.New("license: local revocation store is unreadable or corrupt")
	ErrChainBroken             = errors.New("license: delegation chain is broken")
	ErrDelegationWidensScope   = errors.New("license: sublicense broadens the parent's scope")
	ErrParentInvalid           = errors.New("license: parent authorization is invalid, so the sublicense is invalid")
)

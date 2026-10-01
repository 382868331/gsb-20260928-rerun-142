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
	ErrStaleRevocationData     = errors.New("license: revocation data is older than the already applied state")
	ErrDelegationNotPermitted  = errors.New("license: parent license does not permit delegation")
	ErrDelegationExpandsScope  = errors.New("license: sub-license expands the parent scope")
	ErrDelegationSignature     = errors.New("license: sub-license delegation signature verification failed")
	ErrMalformedChain          = errors.New("license: malformed delegation chain")
	ErrDuplicateLicenseID      = errors.New("license: duplicate license id in delegation chain")
)

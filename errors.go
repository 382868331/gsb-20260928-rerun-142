package license

import "errors"

var (
	ErrMalformed         = errors.New("license: malformed license token")
	ErrUnknownIssuer     = errors.New("license: issuer key not found")
	ErrBadSignature      = errors.New("license: signature verification failed")
	ErrDeviceMismatch    = errors.New("license: device identity does not match")
	ErrExpired           = errors.New("license: license has expired")
	ErrNotYetValid       = errors.New("license: license is not valid yet")
	ErrRevoked           = errors.New("license: license has been revoked")
	ErrRevocationMissing = errors.New("license: revocation data is unavailable")
	ErrClockRolledBack   = errors.New("license: system clock rolled back beyond tolerance")
	ErrVersionChange     = errors.New("license: license format version is not supported")
)

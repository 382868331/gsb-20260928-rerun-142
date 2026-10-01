package license

import "encoding/json"

// CurrentFormatVersion is the only license envelope version understood by
// this build. A license carrying any other version is rejected outright.
const CurrentFormatVersion = 1

// License is the signed content of an authorization. Functional scope,
// validity period and device identity are represented as distinct fields so
// that no component can be implied from another.
type License struct {
	Version   int      `json:"version"`
	LicenseID string   `json:"license_id"`
	IssuerID  string   `json:"issuer_id"`
	KeyID     string   `json:"key_id"`
	DeviceID  string   `json:"device_id"`
	Features  []string `json:"features"`
	IssuedAt  string   `json:"issued_at"`
	NotBefore string   `json:"not_before"`
	NotAfter  string   `json:"not_after"`
	// DelegationKey is the ephemeral public key whose holder may issue
	// restricted sub-licenses under this one. Empty means the license may
	// not be delegated. It is covered by the signature, so the delegation
	// right cannot be added by tampering.
	DelegationKey []byte `json:"delegation_key,omitempty"`
}

// Envelope is the serialized, imported license form: claims plus the issuer
// signature over the canonical JSON encoding of the License.
type Envelope struct {
	License   License `json:"license"`
	Signature []byte  `json:"signature"`
}

// Encode renders the license to its stable on-disk/import representation.
func (e *Envelope) Encode() ([]byte, error) {
	return json.MarshalIndent(e, "", "  ")
}

// ParseEnvelope decodes an imported license without verifying it.
func ParseEnvelope(data []byte) (*Envelope, error) {
	var e Envelope
	if err := json.Unmarshal(data, &e); err != nil {
		return nil, ErrMalformedLicense
	}
	if len(e.Signature) == 0 {
		return nil, ErrMalformedLicense
	}
	return &e, nil
}

func signingBytes(l *License) ([]byte, error) {
	// Struct field order is fixed by declaration, making this encoding stable
	// and canonical across processes in the same module version.
	return json.Marshal(l)
}

package license

import "encoding/json"

// CurrentFormatVersion is the only license envelope version understood by
// this build. A license carrying any other version is rejected outright.
const CurrentFormatVersion = 1

// License is the signed content of an authorization. Functional scope,
// validity period and device identity are represented as distinct fields so
// that no component can be implied from another.
type License struct {
	Version   int    `json:"version"`
	LicenseID string `json:"license_id"`
	IssuerID  string `json:"issuer_id"`
	KeyID     string `json:"key_id"`
	// ParentID identifies the license this one was delegated from. It is
	// empty on issuer-signed root licenses. A child license can never
	// broaden the parent's features, device scope or validity window.
	ParentID string   `json:"parent_id,omitempty"`
	DeviceID string   `json:"device_id"`
	Features []string `json:"features"`
	// Grants name concrete resource/operation permissions. Restrictions can
	// suspend part of a grant for an interval without revoking the whole
	// license; features remain the coarser legacy scope.
	Grants []Grant `json:"grants,omitempty"`
	// Delegators are temporary ed25519 keys the holder may use to create
	// restricted sublicenses. They are covered by the envelope signature,
	// so nobody can smuggle in an unauthorized delegation key.
	Delegators []DelegationKey `json:"delegators,omitempty"`
	IssuedAt   string          `json:"issued_at"`
	NotBefore  string          `json:"not_before"`
	NotAfter   string          `json:"not_after"`
}

// DelegationKey authorizes creation of sublicenses under the license that
// carries it. The key material is generated locally for this project; it is
// never a real device identity or commercial-licensing key.
type DelegationKey struct {
	KeyID string `json:"key_id"`
	Key   []byte `json:"key"`
}

// Grant is one resource and the operations allowed on it. Wildcard "*"
// means every resource or every operation in the context where it appears.
type Grant struct {
	Resource string   `json:"resource"`
	Actions  []string `json:"actions"`
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

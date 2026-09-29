package license

import (
	"crypto/ed25519"
	"encoding/json"
)

func (s *SignedRevocationList) Encode() ([]byte, error) {
	return json.MarshalIndent(s, "", "  ")
}

// RevocationList is signed by the issuer and enumerates revoked license IDs.
// It is strictly local/offline data: a consumer without the list cannot claim
// revocation has been checked.
type RevocationList struct {
	IssuerID    string   `json:"issuer_id"`
	KeyID       string   `json:"key_id"`
	GeneratedAt string   `json:"generated_at"`
	RevokedIDs  []string `json:"revoked_ids"`
}

// SignedRevocationList pairs the list with its issuer signature.
type SignedRevocationList struct {
	List      RevocationList `json:"list"`
	Signature []byte         `json:"signature"`
}

// SignRevocationList signs a revocation list with an issuer key.
func SignRevocationList(k *IssuerSecret, rl RevocationList) (*SignedRevocationList, error) {
	rl.IssuerID = k.IssuerID
	rl.KeyID = k.KeyID
	body, err := json.Marshal(rl)
	if err != nil {
		return nil, err
	}
	return &SignedRevocationList{
		List:      rl,
		Signature: ed25519.Sign(ed25519.PrivateKey(k.Secret), body),
	}, nil
}

// Verify checks the signature against the ring. A structurally broken or
// badly signed list is never accepted.
func (s *SignedRevocationList) Verify(kr *KeyRing) error {
	if s == nil || len(s.Signature) == 0 {
		return ErrMalformedRevocationList
	}
	pub, ok := kr.lookup(s.List.IssuerID, s.List.KeyID)
	if !ok {
		return ErrUnknownIssuerKey
	}
	body, err := json.Marshal(s.List)
	if err != nil {
		return ErrMalformedRevocationList
	}
	if !ed25519.Verify(ed25519.PublicKey(pub.Key), body, s.Signature) {
		return ErrInvalidSignature
	}
	return nil
}

func (s *SignedRevocationList) contains(id string) bool {
	return containsID(s.List.RevokedIDs, id)
}

func containsID(ids []string, id string) bool {
	for _, candidate := range ids {
		if candidate == id {
			return true
		}
	}
	return false
}

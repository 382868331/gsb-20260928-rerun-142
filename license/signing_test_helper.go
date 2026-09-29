package license

import "crypto/ed25519"

func signRaw(k *IssuerSecret, body []byte) []byte {
	return ed25519.Sign(ed25519.PrivateKey(k.Secret), body)
}

package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
)

// EncryptRSAOAEP encrypts data with the given RSA public key using OAEP/SHA-256.
// Used by the init tool to produce recovery-encrypted backups of unseal keys.
func EncryptRSAOAEP(pub *rsa.PublicKey, data []byte) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, data, nil)
}

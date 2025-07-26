package privkey

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
)

type RSAPrivateKey struct {
	key *rsa.PrivateKey
}

func New(bits int) (*RSAPrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	return &RSAPrivateKey{key: key}, nil
}

func (r *RSAPrivateKey) Marshal() ([]byte, error) {
	return x509.MarshalPKCS1PrivateKey(r.key), nil
}

func (r *RSAPrivateKey) Public() *rsa.PublicKey {
	return &r.key.PublicKey
}

func (r *RSAPrivateKey) Sign(hashed []byte) ([]byte, error) {
	return rsa.SignPKCS1v15(nil, r.key, crypto.SHA256, hashed)
}

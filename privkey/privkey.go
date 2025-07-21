package privkey

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"os"
	"path/filepath"
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

func (r *RSAPrivateKey) Save(filename string) error {
	dir := filepath.Dir(filename)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}

	derBytes := x509.MarshalPKCS1PrivateKey(r.key)
	return os.WriteFile(filename, derBytes, 0600)
}

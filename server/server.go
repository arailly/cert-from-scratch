package server

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"time"
)

// Start starts an HTTPS server using the provided certificate and key files (DER format) on the given address.
// addr should be in the form ":8443" or "0.0.0.0:8443".
func Start(certFile, keyFile, addr string) error {
	certDER, err := os.ReadFile(certFile)
	if err != nil {
		return fmt.Errorf("read cert: %w", err)
	}
	keyDER, err := os.ReadFile(keyFile)
	if err != nil {
		return fmt.Errorf("read key: %w", err)
	}

	// Try common private key formats: PKCS#1, PKCS#8, EC
	var priv any
	if k, err := x509.ParsePKCS1PrivateKey(keyDER); err == nil {
		priv = k
	} else if k, err := x509.ParsePKCS8PrivateKey(keyDER); err == nil {
		priv = k
	} else if k, err := x509.ParseECPrivateKey(keyDER); err == nil {
		priv = k
	} else {
		return fmt.Errorf("unsupported private key format: %w", err)
	}

	tlsCert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}

	srv := &http.Server{
		Addr: addr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Hello World!\n"))
		}),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
		TLSConfig:    &tls.Config{Certificates: []tls.Certificate{tlsCert}},
	}

	// Passing empty certFile/keyFile makes ListenAndServeTLS use srv.TLSConfig
	return srv.ListenAndServeTLS("", "")
}

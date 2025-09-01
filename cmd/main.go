package main

import (
	"fmt"
	"os"

	"github.com/arailly/cert-from-scratch/basecert"
	"github.com/arailly/cert-from-scratch/certified"
	"github.com/arailly/cert-from-scratch/privkey"
	"github.com/arailly/cert-from-scratch/selfsigned"
	"github.com/arailly/cert-from-scratch/util"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "privkey":
		if len(os.Args) < 3 {
			fmt.Fprintf(os.Stderr, "Error: output path required\n")
			fmt.Fprintf(os.Stderr, "Usage: %s privkey <output-path>\n", os.Args[0])
			os.Exit(1)
		}
		key, err := privkey.New(2048)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating private key: %v\n", err)
			os.Exit(1)
		}
		if err := util.MarshalAndSaveKey(os.Args[2], key); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving private key: %v\n", err)
			os.Exit(1)
		}
	case "basecert":
		if len(os.Args) < 3 {
			fmt.Fprintf(os.Stderr, "Error: output path required\n")
			fmt.Fprintf(os.Stderr, "Usage: %s basecert <output-path>\n", os.Args[0])
			os.Exit(1)
		}
		cert := basecert.New()
		if err := util.MarshalAndSaveCert(os.Args[2], cert); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving base certificate: %v\n", err)
			os.Exit(1)
		}
	case "selfsigned":
		if len(os.Args) < 3 {
			fmt.Fprintf(os.Stderr, "Error: output path prefix required\n")
			fmt.Fprintf(os.Stderr, "Usage: %s selfsigned <output-path-prefix>\n", os.Args[0])
			os.Exit(1)
		}
		prefix := os.Args[2]
		priv, err := privkey.New(2048)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating private key: %v\n", err)
			os.Exit(1)
		}
		if err := util.MarshalAndSaveKey(prefix+"-key", priv); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving private key: %v\n", err)
			os.Exit(1)
		}
		cert := selfsigned.New(priv)
		if err := util.MarshalAndSaveCert(prefix+"-cert", cert); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving certificate: %v\n", err)
			os.Exit(1)
		}
	case "certified":
		if len(os.Args) < 3 {
			fmt.Fprintf(os.Stderr, "Error: output path prefix required\n")
			fmt.Fprintf(os.Stderr, "Usage: %s certified <output-path-prefix>\n", os.Args[0])
			os.Exit(1)
		}
		prefix := os.Args[2]

		// CA Certificate
		caKey, err := privkey.New(2048)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating private key: %v\n", err)
			os.Exit(1)
		}
		// Private key for CA is not necessary to verify server certificate
		caCert := certified.NewCACertificate(caKey)
		if err := util.MarshalAndSaveCert(prefix+"-cacert", caCert); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving CA certificate: %v\n", err)
			os.Exit(1)
		}

		// Server Certificate
		serverKey, err := privkey.New(2048)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating private key: %v\n", err)
			os.Exit(1)
		}
		if err := util.MarshalAndSaveKey(prefix+"-key", serverKey); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving private key: %v\n", err)
			os.Exit(1)
		}
		serverCert := certified.NewServerCertificate(serverKey, caKey, caCert)
		if err := util.MarshalAndSaveCert(prefix+"-cert", serverCert); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving server certificate: %v\n", err)
			os.Exit(1)
		}

	default:
		fmt.Fprintf(os.Stderr, "Error: unknown command '%s'\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, "Usage: %s <command> [args...]\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "\nCommands:\n")
	fmt.Fprintf(os.Stderr, "  privkey <output-path>  Generate RSA private key in DER format\n")
	fmt.Fprintf(os.Stderr, "  basecert <output-path>  Generate base certificate in DER format\n")
	fmt.Fprintf(os.Stderr, "  signedcert <output-path-prefix>  Generate signed certificate and private key in DER format\n")
	fmt.Fprintf(os.Stderr, "  https <prefix> <addr>  Start HTTPS server with <prefix>-cert.der and <prefix>-privkey.der (e.g. :8443)\n")
	fmt.Fprintf(os.Stderr, "  chainedcert <output-path-prefix>  Generate certificate and private key with CommonName=localhost in DER format\n")
	fmt.Fprintf(os.Stderr, "  cagen <output-path-prefix>  Generate CA certificate and private key (PEM)\n")
}

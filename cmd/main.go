package main

import (
	"fmt"
	"os"

	"github.com/arailly/cert-from-scratch/basecert"
	"github.com/arailly/cert-from-scratch/chainedcert"
	"github.com/arailly/cert-from-scratch/https"
	"github.com/arailly/cert-from-scratch/privkey"
	"github.com/arailly/cert-from-scratch/signedcert"
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
	case "signedcert":
		if len(os.Args) < 3 {
			fmt.Fprintf(os.Stderr, "Error: output path required\n")
			fmt.Fprintf(os.Stderr, "Usage: %s signedcert <output-path-prefix>\n", os.Args[0])
			os.Exit(1)
		}
		privkey, err := privkey.New(2048)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating private key: %v\n", err)
			os.Exit(1)
		}
		if err := util.MarshalAndSaveKey(os.Args[2]+"-privkey.der", privkey); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving private key: %v\n", err)
			os.Exit(1)
		}
		cert := signedcert.New(privkey)
		if err := util.MarshalAndSaveCert(os.Args[2]+"-cert.der", cert); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving signed certificate: %v\n", err)
			os.Exit(1)
		}
	case "https":
		if len(os.Args) < 4 {
			fmt.Fprintf(os.Stderr, "Error: prefix and address required\n")
			fmt.Fprintf(os.Stderr, "Usage: %s https <prefix> <addr>\n", os.Args[0])
			os.Exit(1)
		}
		prefix := os.Args[2]
		addr := os.Args[3]
		certPath := prefix + "-cert.der"
		keyPath := prefix + "-privkey.der"
		err := https.Start(certPath, keyPath, addr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "HTTPS server error: %v\n", err)
			os.Exit(1)
		}
	case "chainedcert":
		if len(os.Args) < 3 {
			fmt.Fprintf(os.Stderr, "Error: output path prefix required\n")
			fmt.Fprintf(os.Stderr, "Usage: %s chainedcert <output-path-prefix>\n", os.Args[0])
			os.Exit(1)
		}
		prefix := os.Args[2]
		priv, err := privkey.New(2048)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating private key: %v\n", err)
			os.Exit(1)
		}
		if err := util.MarshalAndSaveKey(prefix+"-privkey", priv); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving private key: %v\n", err)
			os.Exit(1)
		}
		cert := chainedcert.New(priv)
		if err := util.MarshalAndSaveCert(prefix+"-cert", cert); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving certificate: %v\n", err)
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
}

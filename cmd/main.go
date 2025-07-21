package main

import (
	"fmt"
	"os"

	"github.com/arailly/cert-from-scratch/privkey"
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
		if err := key.Save(os.Args[2]); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving private key: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Private key generated and saved to: %s\n", os.Args[2])
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
}

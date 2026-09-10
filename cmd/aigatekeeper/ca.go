package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/canngos/aigatekeeper/internal/ca"
	"github.com/canngos/aigatekeeper/internal/config"
)

func cmdCA(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: aigatekeeper ca <init|print> [flags]")
		return 2
	}
	switch args[0] {
	case "init":
		return cmdCAInit(args[1:], stdout, stderr)
	case "print":
		return cmdCAPrint(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown ca subcommand %q\n", args[0])
		return 2
	}
}

func cmdCAInit(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("ca init", flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("out", "./certs", "directory for ca.crt and ca.key")
	certPath := fs.String("cert", "", "certificate output path (overrides --out)")
	keyPath := fs.String("key", "", "private key output path (overrides --out)")
	cn := fs.String("cn", ca.DefaultCommonName, "certificate common name")
	org := fs.String("org", ca.DefaultOrganization, "certificate organization")
	validity := fs.String("validity", "3650d", "validity period (e.g. 3650d, 87600h)")
	force := fs.Bool("force", false, "overwrite existing files")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *certPath == "" {
		*certPath = filepath.Join(*out, "ca.crt")
	}
	if *keyPath == "" {
		*keyPath = filepath.Join(*out, "ca.key")
	}
	dur, err := config.ParseDuration(*validity)
	if err != nil {
		fmt.Fprintln(stderr, "invalid --validity:", err)
		return 2
	}

	c, err := ca.Generate(*cn, *org, dur)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	if err := c.Save(*certPath, *keyPath, *force); err != nil {
		if errors.Is(err, ca.ErrExists) {
			fmt.Fprintln(stderr, "error:", err)
			return 1
		}
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	fmt.Fprintf(stdout, "Root CA generated.\n  certificate: %s\n  private key: %s (keep this secret)\n", *certPath, *keyPath)
	printTrustInstructions(stdout, c, *certPath)
	return 0
}

func cmdCAPrint(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("ca print", flag.ContinueOnError)
	fs.SetOutput(stderr)
	certPath := fs.String("cert", "./certs/ca.crt", "certificate path")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	pemBytes, err := os.ReadFile(*certPath)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	c, err := ca.ParseCertificate(pemBytes)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	printTrustInstructions(stdout, c, *certPath)
	return 0
}

func printTrustInstructions(w io.Writer, c *ca.CA, certPath string) {
	abs, err := filepath.Abs(certPath)
	if err != nil {
		abs = certPath
	}
	fmt.Fprintf(w, "\nSubject:     %s\nNot after:   %s\nSHA-256:     %s\n",
		c.Cert.Subject.String(), c.Cert.NotAfter.Format(time.RFC3339), c.Fingerprint())
	fmt.Fprintf(w, `
Trust this CA on client machines:
  Windows (admin shell):   certutil -addstore -f Root "%s"
  macOS:                   sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "%s"
  Debian/Ubuntu:           sudo cp "%s" /usr/local/share/ca-certificates/aigatekeeper.crt && sudo update-ca-certificates
  Node-based tools:        set NODE_EXTRA_CA_CERTS=%s   (GitHub Copilot, VS Code extensions)
  Cursor / OpenSSL tools:  set SSL_CERT_FILE=%s
  Python requests:         set REQUESTS_CA_BUNDLE=%s
The certificate is also served by the admin listener at /ca.crt.
`, abs, abs, abs, abs, abs, abs)
}

func cmdHealthcheck(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("healthcheck", flag.ContinueOnError)
	fs.SetOutput(stderr)
	url := fs.String("url", "http://127.0.0.1:9090/healthz", "health endpoint URL")
	timeout := fs.Duration("timeout", 5*time.Second, "request timeout")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	client := &http.Client{Timeout: *timeout}
	resp, err := client.Get(*url)
	if err != nil {
		fmt.Fprintln(stderr, "unhealthy:", err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(stderr, "unhealthy: status %d\n", resp.StatusCode)
		return 1
	}
	fmt.Fprintln(stdout, "ok")
	return 0
}

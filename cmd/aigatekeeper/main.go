// Command aigatekeeper is the AIGatekeeper proxy binary.
//
// Subcommands:
//
//	serve        run the proxy (forward listener, reverse listeners, admin)
//	ca init      generate the root CA certificate and key
//	ca print     show the fingerprint and trust instructions for a CA
//	healthcheck  probe the admin health endpoint (used by container healthchecks)
//	version      print the build version
package main

import (
	"fmt"
	"io"
	"os"
)

// version is set at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	switch args[0] {
	case "serve":
		return cmdServe(args[1:], stdout, stderr)
	case "ca":
		return cmdCA(args[1:], stdout, stderr)
	case "healthcheck":
		return cmdHealthcheck(args[1:], stdout, stderr)
	case "version", "--version", "-v":
		fmt.Fprintf(stdout, "aigatekeeper %s\n", version)
		return 0
	case "help", "-h", "--help":
		usage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n", args[0])
		usage(stderr)
		return 2
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `AIGatekeeper - DLP proxy for GenAI traffic

Usage:
  aigatekeeper serve --config configs/aigatekeeper.yaml [--log-level info]
  aigatekeeper ca init [--out ./certs] [--cn NAME] [--org ORG] [--validity 3650d] [--force]
  aigatekeeper ca print [--cert ./certs/ca.crt]
  aigatekeeper healthcheck [--url http://127.0.0.1:9090/healthz]
  aigatekeeper version
`)
}

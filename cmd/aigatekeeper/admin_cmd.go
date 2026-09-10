package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/canngos/aigatekeeper/internal/admin"
)

func cmdAdmin(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: aigatekeeper admin hash-password [--stdin]")
		return 2
	}
	switch args[0] {
	case "hash-password":
		return cmdHashPassword(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown admin subcommand %q\n", args[0])
		return 2
	}
}

// cmdHashPassword prints a bcrypt hash for admin.auth.password_hash. The
// password is read from stdin (a line, or --stdin for the whole input) so it
// never appears in shell history or process listings.
func cmdHashPassword(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("admin hash-password", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	fmt.Fprint(stderr, "Password: ")
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		fmt.Fprintln(stderr, "\nerror: could not read password from stdin")
		return 1
	}
	password := strings.TrimRight(line, "\r\n")
	if len(password) < 8 {
		fmt.Fprintln(stderr, "\nerror: password must be at least 8 characters")
		return 1
	}
	hash, err := admin.HashPassword(password)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	fmt.Fprintln(stderr)
	fmt.Fprintln(stdout, hash)
	fmt.Fprintf(stderr, "\nPut this in the config as admin.auth.password_hash (quote it) or set AIGK_ADMIN_PASSWORD_HASH.\n")
	return 0
}

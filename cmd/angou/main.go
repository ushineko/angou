// Command angou encrypts sensitive files into a portable, syncable store.
//
// This binary is built CGO_ENABLED=0 and invokes no subprocesses: no gpg, no
// gpg-agent, no kwallet-query (spec 001 R6.2, R6.3).
package main

import (
	"fmt"
	"os"

	"github.com/ushineko/angou/internal/cli"
)

func main() {
	if err := cli.Root().Execute(); err != nil {
		// The command tree silences cobra's own reporting so this is the single
		// place a failure is printed. Errors carry no secret material: the
		// passphrase never reaches an error value.
		fmt.Fprintln(os.Stderr, "angou:", err)
		os.Exit(1)
	}
}

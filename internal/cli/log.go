package cli

import (
	"fmt"
	"os"

	"github.com/ushineko/angou/internal/core"
)

// verbose enables operational logging on stderr.
var verbose bool

// logf writes an operational note when --verbose is set.
//
// Nothing passed here may be a secret. That is a rule about call sites rather
// than something this function can enforce, so the rule is stated at every one:
// a passphrase, an unlock passphrase, a decrypted envelope, or the plaintext of
// a blob must never reach a log path at any verbosity. Logging is for what
// angou did — which blob it addressed, which route it opened the store by — not
// for what the blob contained.
//
// Blob identifiers are loggable. They are already the filenames in the store, so
// printing one discloses nothing the directory listing does not.
func logf(format string, args ...any) {
	if !verbose {
		return
	}
	_, _ = fmt.Fprintf(os.Stderr, "angou: "+format+"\n", args...)
}

// events wires core's reporting to this front end: --verbose logging on stderr
// and advisory notices printed verbatim.
//
// core decides the wording. That is deliberate — the words are part of what the
// tool promises, and letting each front end phrase them itself is how the CLI
// and the GUI start telling users different things about the same state.
func events() core.Events {
	return core.Events{
		Logf: func(format string, args ...any) { logf(format, args...) },
		Notice: func(msg string) {
			_, _ = fmt.Fprintln(os.Stderr, msg)
		},
	}
}

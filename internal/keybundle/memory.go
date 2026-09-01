package keybundle

import (
	"errors"
	"fmt"
)

// ErrInsufficientMemory reports that the machine cannot supply the memory the
// recorded Argon2id parameters demand.
var ErrInsufficientMemory = errors.New("not enough memory for the key derivation")

// derivationHeadroomKiB is what the process needs on top of the Argon2id block
// array: the Go runtime, the binary, the decrypted identity, and enough slack
// that the allocation does not merely succeed and then push the process over a
// limit on its next garbage collection.
//
// Measured peak RSS for a full `init` at the pinned floor is about 77 MiB
// against a 64 MiB block array, so the real overhead is roughly 13 MiB. This is
// set well above that but not so far above that it refuses a container the
// derivation would in fact have completed in.
const derivationHeadroomKiB uint64 = 32 << 10 // 32 MiB

// memoryReport describes what the platform could determine about available
// memory. A zero-valued report with known=false means the platform offers no
// answer, and the check is skipped rather than guessed at.
type memoryReport struct {
	availableKiB uint64
	known        bool
	// limitNote describes a container or cgroup limit when one is what
	// constrains the process, so the message points at the thing the user has
	// to change.
	limitNote string
}

// checkMemory refuses a derivation the machine cannot complete.
//
// This is a pre-flight check rather than error handling because there is no
// error to handle: argon2.IDKey allocates its block array in one go, and a
// failed allocation in Go is a runtime abort, not a returnable error. Without
// this the process is simply killed — exit 137, no output, nothing to diagnose.
func (p Params) checkMemory() error {
	return p.checkMemoryAgainst(availableMemory())
}

// checkMemoryAgainst is the decision, separated from the platform probe so it
// can be tested without a fake /proc.
func (p Params) checkMemoryAgainst(report memoryReport) error {
	if !report.known {
		// Better to attempt the derivation than to refuse on a platform whose
		// available memory this build cannot read.
		return nil
	}
	required := uint64(p.MemoryKiB) + derivationHeadroomKiB
	if report.availableKiB >= required {
		return nil
	}
	return fmt.Errorf("%w: this store's key bundle needs %d MiB for its key derivation, "+
		"but only %d MiB is available%s. Free memory or raise the limit",
		ErrInsufficientMemory,
		uint64(p.MemoryKiB)/1024,
		report.availableKiB/1024,
		report.limitNote)
}

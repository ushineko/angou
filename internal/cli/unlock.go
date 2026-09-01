package cli

import (
	"github.com/ushineko/angou/internal/core"
	"github.com/ushineko/angou/internal/prompt"
	"github.com/ushineko/angou/internal/store"
)

// This file is the CLI's half of unlocking: how a passphrase is asked for, and
// where core's notices are printed. The routes themselves — the agent, the
// machine-local key, the recovery passphrase, and the order they are tried in —
// live in internal/core, so the GUI takes exactly the same ones.

// cliSecrets prompts on the terminal, or reads the passphrase from the file
// descriptor the caller passed with --passphrase-fd.
type cliSecrets struct{}

func (cliSecrets) Recovery(p string) ([]byte, error) {
	return prompt.Passphrase(global.passphraseFD, p)
}

// unlock opens the store by whichever route this machine supports.
func unlock() (*store.Store, error) {
	dir, err := storeDir()
	if err != nil {
		return nil, err
	}
	return core.Open(dir, cliSecrets{}, events())
}

// unlockLocal takes the keyring route only. bootstrap --force uses it to reach
// a superseded local key it is about to replace.
func unlockLocal(dir string) (*store.Store, error) {
	return core.OpenLocal(dir, events())
}

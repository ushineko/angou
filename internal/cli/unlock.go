package cli

import (
	"github.com/ushineko/angou/internal/core"
	"github.com/ushineko/angou/internal/prompt"
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
func unlock() (*core.Session, error) {
	dir, err := storeDir()
	if err != nil {
		return nil, err
	}
	return core.Open(dir, cliSecrets{}, events())
}

// cliDecider answers core's mid-operation questions on the terminal.
//
// With no terminal to ask, it takes the question's default rather than reading
// from a stdin that may be a file, a pipe, or nothing. That keeps the safe
// answer safe: the destructive questions default to no, so a non-interactive
// run declines them unless a flag said otherwise.
type cliDecider struct{}

func (cliDecider) Ask(d core.Decision) bool {
	return confirm(d.Question, d.Default)
}

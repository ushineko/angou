// Package core holds angou's operations, with no front end attached.
//
// Both front ends run on this package: `internal/cli` renders its results as
// text, the desktop GUI renders the same results as widgets. Neither may
// reimplement an operation, and neither may reach past this package into
// internal/store and friends to assemble one itself. That rule is what keeps
// the two in step; the project policy in .claude/CLAUDE.md states it, and a
// parity test enforces it once the GUI is wired.
//
// Three constraints shape everything here:
//
//   - Nothing in this package writes to stdout or stderr, and nothing prompts.
//     A caller that needs to say something to the user is given the words
//     through Events; a caller that needs a secret supplies one through Secrets.
//     This is what lets the CLI keep its exact output while the GUI shows the
//     same facts in a dialog.
//
//   - Results are data, not prose. A report is a list of findings with a
//     severity attached, not a formatted block. The CLI's rendering is
//     byte-for-byte what it was before this package existed — that is asserted
//     by the e2e suite, which was not changed when the operations moved here.
//
//   - Secrets are borrowed, never retained. A Secrets implementation hands over
//     a buffer, this package uses it and zeroes it. Nothing here keeps a
//     passphrase past the operation that needed it.
package core

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ushineko/angou/internal/keyring"
	"github.com/ushineko/angou/internal/passphrase"
)

// ErrNoSecret reports that no secret can be supplied without interaction.
//
// It exists for diagnostics: `doctor` is what someone runs when a command is
// already failing in a way they do not understand, and a diagnostic that stops
// to ask for a passphrase is a worse diagnostic. A Secrets implementation
// returns this rather than prompting, and the operation reports what it can.
var ErrNoSecret = errors.New("no secret available without prompting")

// Secrets supplies passphrases on demand.
//
// The prompt string is the question to put to the user; it is never a secret
// itself. The returned buffer belongs to the caller of this package only until
// the operation returns — core zeroes it.
type Secrets interface {
	Recovery(prompt string) ([]byte, error)
}

// SecretFunc adapts a function to Secrets.
type SecretFunc func(prompt string) ([]byte, error)

// Recovery implements Secrets.
func (f SecretFunc) Recovery(prompt string) ([]byte, error) { return f(prompt) }

// NoSecrets refuses every request. It is what a non-interactive diagnostic
// passes when it wants whatever can be learned without asking.
type NoSecrets struct{}

// Recovery implements Secrets by refusing.
func (NoSecrets) Recovery(string) ([]byte, error) { return nil, ErrNoSecret }

// Events carries what an operation wants to tell the user while it works.
//
// The strings are complete and final: core decides the wording, because the
// wording is part of what the tool promises and must not drift between the two
// front ends. The CLI writes them to stderr verbatim; the GUI shows them as
// banners. Either field may be nil.
type Events struct {
	// Logf reports what angou is doing, for --verbose. Nothing passed here may
	// be a secret: not a passphrase, not an unlock passphrase, not a decrypted
	// envelope, not the plaintext of a blob. That is a rule about call sites,
	// restated here because this is now the boundary they cross.
	Logf func(format string, args ...any)

	// Notice reports something the user should see without --verbose: a
	// degraded index, a drifted bootstrap script, a faster route not taken.
	// Never a failure — a failure is an error return.
	Notice func(msg string)
}

func (e Events) logf(format string, args ...any) {
	if e.Logf != nil {
		e.Logf(format, args...)
	}
}

func (e Events) notice(msg string) {
	if e.Notice != nil {
		e.Notice(msg)
	}
}

func (e Events) noticef(format string, args ...any) {
	e.notice(fmt.Sprintf(format, args...))
}

// ExpandPath resolves a leading ~ to the user's home directory.
//
// A shell does this before angou sees the argument, but only when the tilde is
// unquoted — `--store '~/store'` reaches us literally and creates a directory
// actually named "~". The GUI has no shell at all, so a path typed into a field
// always arrives this way, and a store called ~/Dropbox/angou would be created
// inside whatever directory the window happened to be launched from.
//
// "~user" is left alone. Resolving another user's home means consulting the
// password database, and a path that silently resolves to someone else's home
// directory is a worse outcome than one that does not resolve at all.
func ExpandPath(p string) string {
	if p != "~" && !strings.HasPrefix(p, "~/") {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return p
	}
	if p == "~" {
		return home
	}
	return filepath.Join(home, p[2:])
}

// ErrTildeComponent reports a path with a component that is literally "~".
var ErrTildeComponent = errors.New("path component is a bare tilde")

// CheckCreatablePath refuses to create anything under a path component that is
// literally "~".
//
// Not tidiness. A directory named "~" is a trap: from inside its parent, the
// obvious way to remove it is `rm -rf ~`, and the shell expands that to the
// user's home directory before rm ever runs. angou created one of these — a
// store at ./~/Dropbox/angou, from a quoted tilde — and cleaning it up by hand
// meant reaching for a command that would have deleted a home directory. It was
// removed from a file manager instead, which is the correct instinct and not one
// a tool should require.
//
// ExpandPath already resolves a leading tilde, so nothing reaching here is an
// accident of quoting. This covers what is left: a tilde deeper in the path,
// where expansion does not apply and never will, because there the shell treats
// it as an ordinary filename.
//
// Only creation is refused. An existing store at such a path still opens, or the
// fix for having made one would be to be unable to reach it.
func CheckCreatablePath(p string) error {
	for _, part := range strings.Split(filepath.Clean(p), string(filepath.Separator)) {
		if part != "~" {
			continue
		}
		return fmt.Errorf("%w: %s\n"+
			"Refusing to create anything under a directory named \"~\". From its parent, the "+
			"obvious way to remove it is `rm -rf ~`, which the shell expands to your home "+
			"directory before rm runs.\n"+
			"If you meant your home directory, write it as ~/ at the start of the path, or "+
			"give the full path", ErrTildeComponent, p)
	}
	return nil
}

// ValidateKeyringBackend checks the configured keyring backend name before any
// command does work, so a misspelt one is reported rather than discovered
// halfway through.
func ValidateKeyringBackend() error { return keyring.ValidateBackend() }

// GeneratePassphrase returns a recovery passphrase and its entropy in bits.
//
// It is shown to the user exactly once, after the store it opens exists: telling
// someone to write down a phrase before the thing it unlocks has been created
// hands them a phrase that opens nothing when creation fails.
func GeneratePassphrase() (string, float64, error) { return passphrase.Generate() }

// CheckPassphrase reports the entropy of a user-chosen passphrase, or an error
// if it is too weak to protect the store.
func CheckPassphrase(p string) (float64, error) { return passphrase.Check(p) }

// Severity ranks a finding so a front end can present it by importance.
//
// The CLI ignores it: its output is a flat list and stays that way. The GUI
// uses it to make "this machine still needs the recovery passphrase" look
// different from "the store directory is here", which reading a wall of
// key-value lines does not.
type Severity int

const (
	// SeverityInfo is a plain fact with no judgement attached.
	SeverityInfo Severity = iota
	// SeverityGood is a state the user wants to be in.
	SeverityGood
	// SeverityWarn is a state that needs an action but has broken nothing yet.
	SeverityWarn
	// SeverityBad is a state that is already costing the user something.
	SeverityBad
)

// Finding is one line of a report.
//
// Indent reproduces the sub-lines the CLI has always printed — "  to change
// that", "  consequence" — as structure rather than as leading spaces baked
// into the label, so the GUI can nest them and the CLI can re-add the spaces
// and produce exactly what it produced before.
type Finding struct {
	Label    string
	Value    string
	Indent   int
	Severity Severity
}

// Section groups findings by subject. The CLI prints the findings in order and
// ignores the titles, which is why its output is unchanged.
type Section struct {
	Title    string
	Findings []Finding
}

// Report is the result of a diagnostic operation.
type Report struct {
	Sections []Section
}

// Findings flattens the report in order, for a front end that presents a list.
func (r Report) Findings() []Finding {
	var out []Finding
	for _, s := range r.Sections {
		out = append(out, s.Findings...)
	}
	return out
}

// add appends a finding to the last section, opening one if needed.
func (r *Report) add(title string, f Finding) {
	if len(r.Sections) == 0 || r.Sections[len(r.Sections)-1].Title != title {
		r.Sections = append(r.Sections, Section{Title: title})
	}
	s := &r.Sections[len(r.Sections)-1]
	s.Findings = append(s.Findings, f)
}

package core

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ushineko/angou/internal/envelope"
	"github.com/ushineko/angou/internal/store"
)

// Session is an open store, and the only handle a front end gets to one.
//
// Operations are methods here rather than functions taking a *store.Store, so a
// front end cannot assemble an operation out of store internals — the project's
// parity rule turns on both front ends going through the same door. The GUI
// opens one session and acts on it many times; the CLI opens one per command.
type Session struct {
	st *store.Store
	ev Events
}

// Store exposes the underlying store.
//
// MIGRATION SCAFFOLDING (spec 002 pass 2). The commands that have not yet moved
// onto this type still drive the store directly, and this is how they reach it
// during the move. It must be gone before pass 2 is called finished: while it
// exists, the rule that neither front end reaches past internal/core is a
// convention rather than something the compiler holds.
func (s *Session) Store() *store.Store { return s.st }

// Fingerprint is the store's identity key.
func (s *Session) Fingerprint() string { return s.st.Fingerprint() }

// Root is the store directory.
func (s *Session) Root() string { return s.st.Root() }

// IndexTrusted reports whether the index loaded and verified. When it did not,
// the listing is empty and retrieval by path still works: the index is a cache,
// never the authority (R3.7).
func (s *Session) IndexTrusted() bool { return s.st.IndexTrusted }

// List returns what the store holds, as recorded in the index.
func (s *Session) List() []store.IndexEntry { return s.st.List() }

// Remove deletes one blob. The deletion propagates to every machine the store
// syncs to, and angou keeps no copy of its own.
func (s *Session) Remove(path string) error {
	s.ev.logf("removing %s", path)
	return s.st.Remove(path)
}

// Move re-addresses a blob under a new logical path. The path is part of the
// signed envelope and is bound to the blob's filename, so the two change
// together rather than by renaming a file.
func (s *Session) Move(from, to string) error {
	s.ev.logf("re-addressing %s to %s", from, to)
	return s.st.Move(from, to)
}

// ReindexResult reports what a rebuild found. The two lists are things the
// rebuild stepped over, each of which means something different to the user and
// so is kept separate rather than merged into a count.
type ReindexResult struct {
	Entries int
	// Unreadable did not decrypt with this store's key — usually a leftover
	// from an interrupted rekey.
	Unreadable []string
	// Skipped were not blob names at all — usually a sync service's conflicted
	// copies.
	Skipped []string
}

// Reindex discards the index and reconstructs it from the blobs themselves,
// which are the authoritative record.
func (s *Session) Reindex() (ReindexResult, error) {
	if err := s.st.Reindex(); err != nil {
		return ReindexResult{}, err
	}
	return ReindexResult{
		Entries:    len(s.st.List()),
		Unreadable: s.st.UnreadableOnReindex,
		Skipped:    s.st.SkippedOnReindex,
	}, nil
}

// Get reads one blob. The signature is verified before anything is returned: a
// blob that decrypts but does not verify yields nothing.
func (s *Session) Get(path string) (envelope.Envelope, error) {
	env, err := s.st.Get(path)
	if err != nil {
		return envelope.Envelope{}, err
	}
	// The size is metadata; the digest is not logged. For a low-entropy secret
	// a digest is a reusable oracle.
	s.ev.logf("decrypted %s: %d bytes", env.Path, env.Size)
	return env, nil
}

// Extract writes a stored file beneath dest, recreating its directories and
// restoring its mode and modification time. Writes are confined to dest and
// will not traverse a symlink to leave it: a stored path is untrusted input,
// because anyone who can write to the store chooses it.
func (s *Session) Extract(path, dest string) (string, error) {
	if dest == "" {
		return "", errors.New("--dest is required: extraction needs an explicit root to confine writes to")
	}
	env, err := s.Get(path)
	if err != nil {
		return "", err
	}
	return store.Extract(dest, env.Path, env.Content, env.Mode, env.MTime)
}

// WriteTo writes plaintext to a chosen path with the stored permissions.
func WriteTo(path string, env envelope.Envelope) error {
	perm := os.FileMode(env.Mode).Perm()
	if err := os.WriteFile(path, env.Content, perm); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	// WriteFile applies the mode only when it creates the file, so replacing an
	// existing one would keep whatever permissions that one had. Restoring a
	// 0600 private key over a 0644 file and leaving it world-readable is not a
	// restore, and the umask can widen it on creation too.
	if err := os.Chmod(path, perm); err != nil {
		return fmt.Errorf("set permissions on %s: %w", path, err)
	}
	return nil
}

// Decision is a question an operation has to ask while it runs.
//
// This is the shared mechanism behind the CLI's --overwrite / --auto flags and
// the GUI's dialogs and checkboxes (spec 002 R3.3): one operation, two ways of
// answering. A front end that cannot ask -- a script with no terminal -- returns
// the default, which is why the destructive questions default to no.
type Decision struct {
	// Question is the whole question, phrased by core so the two front ends
	// cannot drift into asking differently about the same thing.
	Question string
	// Default is the answer to take when nobody can be asked.
	Default bool
	// Destructive marks a question whose yes replaces or removes something.
	Destructive bool
}

// Decider answers decisions. Returning Default for everything is a valid
// implementation and is what a non-interactive run does.
type Decider interface {
	Ask(d Decision) bool
}

// DeciderFunc adapts a function to Decider.
type DeciderFunc func(Decision) bool

// Ask implements Decider.
func (f DeciderFunc) Ask(d Decision) bool { return f(d) }

// AlwaysDefault answers every decision with its default.
type AlwaysDefault struct{}

// Ask implements Decider.
func (AlwaysDefault) Ask(d Decision) bool { return d.Default }

// ErrDeclined reports that the user answered no. It is not a failure of the
// operation; the caller reports it as a decision, not an error condition.
var ErrDeclined = errors.New("declined")

// RestoreToOrigin puts a file back where it was encrypted from.
//
// Acting on a path that came out of the store is only defensible because the
// envelope is signed (spec 001 R1.7): forging this destination means forging the
// signature, so write access to the store does not buy an attacker a write
// anywhere on this machine. The user is still asked, because a store is carried
// between machines and "where it came from" may not be somewhere it belongs
// here.
//
// overwrite skips the second question, never the first.
func RestoreToOrigin(env envelope.Envelope, overwrite bool, d Decider) (string, error) {
	target := env.Origin
	if !filepath.IsAbs(target) {
		return "", fmt.Errorf("the recorded location %q is not absolute; use -o to choose a destination", target)
	}

	existing, err := os.Lstat(target)
	switch {
	case err == nil && existing.Mode()&os.ModeSymlink != 0:
		return "", fmt.Errorf("%s is a symlink; refusing to write through it. Use -o to choose a destination", target)
	case err == nil && !existing.Mode().IsRegular():
		return "", fmt.Errorf("%s is not a regular file; refusing to replace it", target)
	}
	exists := err == nil

	if !d.Ask(Decision{
		Question: fmt.Sprintf("Restore %s to %s?", env.Path, target),
		Default:  true,
	}) {
		return "", ErrDeclined
	}
	if exists && !overwrite {
		if !d.Ask(Decision{
			Question:    fmt.Sprintf("%s already exists. Replace it?", target),
			Default:     false,
			Destructive: true,
		}) {
			return "", ErrDeclined
		}
	}

	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return "", fmt.Errorf("create %s: %w", filepath.Dir(target), err)
	}
	if err := WriteTo(target, env); err != nil {
		return "", err
	}
	return target, nil
}

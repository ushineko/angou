//go:build e2e

package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A machine that has been set up should not need to be told where its store is
// on every command. init records it, and the record is what `ls` finds with no
// --store and no $ANGOU_STORE.
//
// Driven with the variable removed from the child's environment, because with it
// set there is nothing for the remembered store to decide.
func TestInitRemembersTheStore(t *testing.T) {
	e := newEnv(t)
	e.initStore()
	e.noStoreEnv = true

	r := e.mustRun("ls")
	if strings.Contains(r.stderr, "no store directory") {
		t.Fatalf("ls could not find the store init had just made:\n%s", r.stderr)
	}

	// The record is a file holding a path, and nothing else. A config file that
	// grew a fingerprint or anything out of the store would be a leak in a place
	// nobody looks.
	cfg := filepath.Join(e.home, ".config", "angou", "config.json")
	b, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatalf("init recorded no config at %s: %v", cfg, err)
	}
	if !strings.Contains(string(b), e.store) {
		t.Fatalf("the config does not name the store:\n%s", b)
	}
	if strings.Contains(string(b), e.recovery) || strings.Contains(string(b), e.fingerprint) {
		t.Fatalf("the config holds more than a path:\n%s", b)
	}
	if fi, err := os.Stat(cfg); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("config mode is %v (err %v), want 0600", fi.Mode().Perm(), err)
	}
}

// --store on one command is a one-off. If it became the new default, a single
// command run against a backup copy would quietly repoint every later one.
func TestAOneOffStoreFlagDoesNotBecomeTheDefault(t *testing.T) {
	e := newEnv(t)
	e.initStore()
	e.noStoreEnv = true

	other := filepath.Join(e.work, "other-store")
	e.mustRun("init", "--no-bootstrap", other)

	// Whatever that init remembered, point the machine back at the first store
	// and then use the second one once.
	e.mustRun("use", e.store)
	e.mustRun("ls", "--store", other)

	r := e.mustRun("use")
	if !strings.Contains(r.stdout, e.store) {
		t.Fatalf("a --store on one command changed the remembered store:\n%s", r.stdout)
	}
	if strings.Contains(r.stdout, other) {
		t.Fatalf("the remembered store is the one used for a single command:\n%s", r.stdout)
	}
}

// use --forget puts the machine back to needing a path, and the error says how
// to fix it. An error that names no remedy is how someone ends up reading the
// source.
func TestUseForgetsAndTheErrorSaysHow(t *testing.T) {
	e := newEnv(t)
	e.initStore()
	e.noStoreEnv = true

	e.mustRun("use", "--forget")

	r := e.run("ls")
	if r.code == 0 {
		t.Fatalf("ls succeeded after the store was forgotten:\n%s", r.stdout)
	}
	if !strings.Contains(r.stderr, "angou use") {
		t.Fatalf("the error does not name the remedy:\n%s", r.stderr)
	}

	e.mustRun("use", e.store)
	e.mustRun("ls")
}

// A path that holds no store is refused rather than remembered. Remembering it
// would only move the failure to the next command, which is further from the
// mistake.
func TestUseRefusesADirectoryWithNoStore(t *testing.T) {
	e := newEnv(t)
	e.initStore()

	empty := filepath.Join(e.work, "not-a-store")
	mkdirAll(t, empty)

	r := e.run("use", empty)
	if r.code == 0 {
		t.Fatalf("use accepted a directory holding no store:\n%s", r.stdout)
	}
	if !strings.Contains(r.stderr, "does not hold a store") {
		t.Fatalf("the error does not say what is wrong:\n%s", r.stderr)
	}
}

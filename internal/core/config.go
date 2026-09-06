package core

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// The remembered store directory, shared by both front ends.
//
// Before this existed the GUI remembered a store in Fyne's preferences and the
// CLI remembered nothing, so a machine could be set up in the window and still
// need --store on every command. The two front ends are one tool over one store
// and should not disagree about which store that is.
//
// What is written here is a path and nothing else. A store path is not a secret:
// it is already in $ANGOU_STORE, in the shell history of anyone using the CLI,
// and in doctor's output. No fingerprint, no passphrase, and nothing out of the
// store itself goes in this file, and nothing should be added to it that does.

// configFile is the JSON document at ConfigPath.
type configFile struct {
	StoreDir string `json:"store_dir,omitempty"`
}

// ConfigPath is where the remembered settings live, following XDG.
//
// Empty when there is no home directory to put it in — a rare case, but one
// where the answer is to carry on without remembering anything rather than to
// fail an operation that had nothing to do with configuration.
func ConfigPath() string {
	if dir := os.Getenv("XDG_CONFIG_HOME"); dir != "" {
		return filepath.Join(dir, "angou", "config.json")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "angou", "config.json")
}

// RememberedStore is the store directory this machine last chose, or empty.
//
// Errors are answers here, not failures: a missing file is the ordinary state
// on a machine that has never chosen one, and a file that will not parse is a
// remembered choice that has been lost rather than a reason to refuse to run.
// The caller's fallbacks — --store, $ANGOU_STORE, first-run setup — cover both.
func RememberedStore() string {
	path := ConfigPath()
	if path == "" {
		return ""
	}
	b, err := os.ReadFile(path) //nolint:gosec // a path this program chose, not user input
	if err != nil {
		return ""
	}
	var c configFile
	if err := json.Unmarshal(b, &c); err != nil {
		return ""
	}
	return ExpandPath(c.StoreDir)
}

// RememberStore records a store directory as this machine's default.
//
// The write is atomic: a temporary file beside the target, then a rename. A
// half-written config is a machine that has forgotten its store, and the moment
// this is called — straight after init or bootstrap — is exactly when losing
// it would be most confusing.
func RememberStore(dir string) error {
	path := ConfigPath()
	if path == "" {
		return nil // nowhere to remember it; not worth failing the operation over
	}
	dir = ExpandPath(dir)

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create %s: %w", filepath.Dir(path), err)
	}
	b, err := json.MarshalIndent(configFile{StoreDir: dir}, "", "  ")
	if err != nil {
		return fmt.Errorf("encode the configuration: %w", err)
	}
	b = append(b, '\n')

	tmp, err := os.CreateTemp(filepath.Dir(path), ".config-*.json")
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }() // no-op once the rename has happened

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// ForgetStore removes the remembered choice, leaving the file itself in place if
// it holds anything else later.
func ForgetStore() error { return RememberStore("") }

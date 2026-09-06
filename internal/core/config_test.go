package core

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRememberedStoreRoundTrips(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	require.Empty(t, RememberedStore(), "a machine that has chosen nothing remembers nothing")

	require.NoError(t, RememberStore("/srv/angou"))
	require.Equal(t, "/srv/angou", RememberedStore())

	require.NoError(t, RememberStore("/srv/other"))
	require.Equal(t, "/srv/other", RememberedStore(), "a later choice replaces the earlier one")

	require.NoError(t, ForgetStore())
	require.Empty(t, RememberedStore())
}

// A tilde typed into a GUI field or quoted on a command line arrives literally.
// Expanding it on the way out means a remembered "~/store" resolves rather than
// sending every later command to a directory named "~".
func TestRememberedStoreExpandsATilde(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	home, err := os.UserHomeDir()
	require.NoError(t, err)

	require.NoError(t, RememberStore("~/angou-store"))
	require.Equal(t, filepath.Join(home, "angou-store"), RememberedStore())
}

// A config that will not parse is a remembered choice that has been lost, not a
// reason to refuse to run: --store, $ANGOU_STORE and first-run setup all still
// work, and failing here would break commands that never needed the file.
func TestRememberedStoreToleratesARuinedFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "angou"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "angou", "config.json"),
		[]byte("{not json"), 0o600))

	require.NotPanics(t, func() { require.Empty(t, RememberedStore()) })
}

// The file holds a path and is written for the user alone. It is not secret, but
// it says where the user keeps their credentials, which is not something to
// widen by default.
func TestRememberStoreWritesAPrivateFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	require.NoError(t, RememberStore("/srv/angou"))

	fi, err := os.Stat(filepath.Join(dir, "angou", "config.json"))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), fi.Mode().Perm())
}

//go:build e2e

package e2e

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestDecryptOnAnotherMachine covers what the store is for.
//
// Everything else in the design serves this: one keypair per store, carried in
// the key bundle, so that a blob written anywhere opens everywhere. The test
// gives the second machine a different home directory, a different store path,
// no local key, and no keyring — the state a machine is in when a sync service
// has just put the store there and nothing else has happened.
func TestDecryptOnAnotherMachine(t *testing.T) {
	machineA := newEnv(t)
	machineB := newEnv(t)

	machineA.initStore()
	secrets := map[string]string{
		"work/.secrets.env":   "DB_PASSWORD=from-machine-A\n",
		"work/ssh/id_ed25519": "not-really-a-key\n",
		"personal/notes.txt":  "written on the first machine\n",
	}
	for path, content := range secrets {
		src := machineA.writePlaintext("staged", []byte(content), 0o600)
		machineA.mustRun("enc", "--as", path, src)
	}

	// The sync service copies the directory. Nothing else travels: machine B
	// has its own home, its own data directory, and no keyring.
	syncStore(t, machineA.store, machineB.store)

	// Machine B needs the recovery passphrase, because it has not been set up.
	// That is the one thing it needs.
	pass := machineA.recovery

	listing := machineB.runWithPassphrase(pass, "ls").stdout
	for path := range secrets {
		require.Contains(t, listing, path, "machine B should see %s", path)
	}
	for path, content := range secrets {
		require.Equal(t, content, machineB.runWithPassphrase(pass, "dec", path).stdout,
			"machine B must decrypt %s", path)
	}

	// And extraction works there too, restoring mode and time.
	dest := filepath.Join(machineB.work, "restored")
	machineB.runWithPassphrase(pass, "get", "--dest", dest, "work/ssh/id_ed25519")
	require.Equal(t, "not-really-a-key\n",
		string(readFile(t, filepath.Join(dest, "work", "ssh", "id_ed25519"))))
}

// TestWriteOnOneMachineReadOnTheOther covers the return direction, which is what
// makes the store shared rather than merely copied.
func TestWriteOnOneMachineReadOnTheOther(t *testing.T) {
	machineA := newEnv(t)
	machineB := newEnv(t)

	machineA.initStore()
	src := machineA.writePlaintext("a.env", []byte("FIELD=from-A\n"), 0o600)
	machineA.mustRun("enc", "--as", "shared/a.env", src)

	syncStore(t, machineA.store, machineB.store)
	pass := machineA.recovery

	// Machine B adds something of its own.
	srcB := machineB.writePlaintext("b.env", []byte("FIELD=from-B\n"), 0o600)
	machineB.runWithPassphrase(pass, "enc", "--as", "shared/b.env", srcB)

	// It syncs back, and machine A reads it.
	syncStore(t, machineB.store, machineA.store)
	require.Equal(t, "FIELD=from-B\n", machineA.mustRun("dec", "shared/b.env").stdout)
	require.Equal(t, "FIELD=from-A\n", machineA.mustRun("dec", "shared/a.env").stdout)

	// The index on machine A predates B's write, so it is stale rather than
	// wrong. Retrieval by name never consulted it; reindex brings it level.
	machineA.mustRun("reindex")
	listing := machineA.mustRun("ls").stdout
	require.Contains(t, listing, "shared/a.env")
	require.Contains(t, listing, "shared/b.env")
}

// TestAnotherMachineIsRefusedWithoutThePassphrase states the other half: the
// store travelling somewhere does not make it readable there.
func TestAnotherMachineIsRefusedWithoutThePassphrase(t *testing.T) {
	machineA := newEnv(t)
	machineB := newEnv(t)

	machineA.initStore()
	src := machineA.writePlaintext("s.env", []byte("FIELD=secret\n"), 0o600)
	machineA.mustRun("enc", "--as", "s.env", src)
	syncStore(t, machineA.store, machineB.store)

	// machineB.recovery is its own, freshly drawn, and unrelated.
	r := machineB.run("dec", "s.env")
	require.NotZero(t, r.code, "a different passphrase must not open the store")
	require.Empty(t, r.stdout)
	require.NotContains(t, r.stdout, "secret")
}

// syncStore copies a store directory the way a sync service would, leaving
// everything else about the destination machine alone.
func syncStore(t *testing.T, from, to string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(to, 0o700))
	require.NoError(t, filepath.Walk(from, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(from, path)
		if err != nil {
			return err
		}
		target := filepath.Join(to, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, raw, info.Mode().Perm())
	}))
}

//go:build e2e

package e2e

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// releasedStore builds a store that holds signed platform binaries, a signed
// installer, and a release key, which is what a bare machine bootstraps from.
func releasedStore(t *testing.T) (*env, string) {
	t.Helper()
	requireGPG(t)

	e := newEnv(t)
	e.initStore()

	key := filepath.Join(e.work, "signing.asc")
	out := e.mustRunNoPassphrase("release", "--new-signing-key", key)
	fingerprint := fieldAfter(t, out.stdout, "Fingerprint: ")

	// Two platforms, so the "unsupported platform" path has something to list.
	dist := filepath.Join(e.work, "dist")
	mkdirAll(t, dist)
	writeFakeBinary(t, filepath.Join(dist, "angou-linux-amd64"))
	writeFakeBinary(t, filepath.Join(dist, "angou-darwin-arm64"))

	e.mustRun("release", "--dist", dist, "--signing-key", key)
	return e, fingerprint
}

// writeFakeBinary stands in for a built angou. The bootstrap chain verifies and
// installs bytes; what those bytes do is not what these tests are about, and a
// real 7 MB binary per case would make the suite slow for no added confidence.
func writeFakeBinary(t *testing.T, path string) {
	t.Helper()
	script := "#!/bin/sh\necho 'angou version 0.1.0-dev (fake)'\n"
	require.NoError(t, os.WriteFile(path, []byte(script), 0o755)) //nolint:gosec // it must be executable
}

func requireGPG(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg is not installed; the bootstrap chain needs it")
	}
}

// runInstaller drives bootstrap.sh the way a bare machine would: an empty
// environment, a throwaway HOME, and nothing of angou's on PATH.
func (e *env) runInstaller(t *testing.T, extraPath string) result {
	t.Helper()
	home := filepath.Join(e.work, "baremachine")
	mkdirAll(t, home)

	path := "/usr/bin:/bin"
	if extraPath != "" {
		path = extraPath
	}
	cmd := exec.Command("/bin/sh", e.storePath("bootstrap.sh"))
	cmd.Env = []string{
		"PATH=" + path,
		"HOME=" + home,
		"ANGOU_INSTALL_DIR=" + filepath.Join(home, "bin"),
	}
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	code := 0
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if ok := asExitError(err, &exitErr); !ok {
			t.Fatalf("running the installer: %v\n%s", err, stderr.String())
		}
		code = exitErr.ExitCode()
	}
	return result{stdout: stdout.String(), stderr: stderr.String(), code: code}
}

func (e *env) installedBinary() string {
	return filepath.Join(e.work, "baremachine", "bin", "angou")
}

// TestReleaseStashesSignedBinariesWithMetadata covers R5.3: the record has to
// describe the artifact it sits beside, or it means nothing.
func TestReleaseStashesSignedBinariesWithMetadata(t *testing.T) {
	e, fingerprint := releasedStore(t)

	for _, platform := range []string{"linux-amd64", "darwin-arm64"} {
		name := "angou-" + platform + "-0.1.0-dev"
		binary := e.storePath("bootstrap", name)
		require.FileExists(t, binary)
		require.FileExists(t, binary+".sig")

		var meta map[string]any
		require.NoError(t, json.Unmarshal(readFile(t, binary+".json"), &meta))

		sum := sha256.Sum256(readFile(t, binary))
		require.Equal(t, hex.EncodeToString(sum[:]), meta["sha256"],
			"the recorded digest must match the artifact it describes")
		require.NotEmpty(t, meta["commit"])
		require.NotEmpty(t, meta["toolchain"])
		require.NotEmpty(t, meta["build_flags"])
	}

	// The installer and the release key travel with them, and the installer
	// carries the fingerprint rather than looking it up in the store.
	require.FileExists(t, e.storePath("bootstrap", "release-key.asc"))
	require.FileExists(t, e.storePath("bootstrap.sh"))
	require.FileExists(t, e.storePath("bootstrap.sh.sig"))
	require.Contains(t, string(readFile(t, e.storePath("bootstrap.sh"))), fingerprint)
}

// TestBareMachineInstallsFromTheStore is the R5.6 path: no angou, no keyring, no
// Go toolchain, nothing but the store and the system gpg.
func TestBareMachineInstallsFromTheStore(t *testing.T) {
	e, _ := releasedStore(t)

	r := e.runInstaller(t, "")
	require.Zero(t, r.code, "the installer should succeed:\n%s", r.stderr)
	require.FileExists(t, e.installedBinary())
	require.Contains(t, r.stderr, "matches its signature")

	// No passphrase was asked for at the binary step: the binary is not
	// encrypted, only signed.
	require.NotContains(t, strings.ToLower(r.stderr), "passphrase:")

	info, err := os.Stat(e.installedBinary())
	require.NoError(t, err)
	require.NotZero(t, info.Mode()&0o111, "the installed binary must be executable")
}

// TestInstallerRefusesATamperedBinary covers R5.4.
func TestInstallerRefusesATamperedBinary(t *testing.T) {
	e, fingerprint := releasedStore(t)

	binary := e.storePath("bootstrap", "angou-linux-amd64-0.1.0-dev")
	require.NoError(t, os.WriteFile(binary, append(readFile(t, binary), []byte("\n# added\n")...), 0o755)) //nolint:gosec // it must stay executable

	r := e.runInstaller(t, "")
	require.NotZero(t, r.code, "a tampered binary must be refused")
	require.Contains(t, r.stderr, fingerprint)
	require.NoFileExists(t, e.installedBinary(), "nothing may be installed")
}

// TestInstallerRefusesAnotherKeysSignature covers R5.4.1, which is the finding
// that makes the release key worth keeping separate at all.
//
// The attacker here holds write access to the store: they re-sign the binary
// with a key of their own and replace release-key.asc to match. Every signature
// in the store then verifies against every key in the store. What refuses them
// is the fingerprint written into the installer, which does not come from the
// store.
func TestInstallerRefusesAnotherKeysSignature(t *testing.T) {
	e, fingerprint := releasedStore(t)

	// Build a second store, signed by a different key, and lift its artifacts.
	attacker, attackerFingerprint := releasedStore(t)
	require.NotEqual(t, fingerprint, attackerFingerprint)

	name := "angou-linux-amd64-0.1.0-dev"
	copyOver(t, attacker.storePath("bootstrap", name), e.storePath("bootstrap", name))
	copyOver(t, attacker.storePath("bootstrap", name+".sig"), e.storePath("bootstrap", name+".sig"))
	copyOver(t, attacker.storePath("bootstrap", "release-key.asc"), e.storePath("bootstrap", "release-key.asc"))

	r := e.runInstaller(t, "")
	require.NotZero(t, r.code, "a binary signed by another key must be refused")
	require.Contains(t, r.stderr, fingerprint,
		"the refusal should name the key the installer actually trusts")
	require.NoFileExists(t, e.installedBinary())
}

// TestInstallerReportsMissingGPG covers R5.6: it names the install command for
// the platform and installs nothing.
func TestInstallerReportsMissingGPG(t *testing.T) {
	e, _ := releasedStore(t)

	// A PATH with the ordinary tools but no gpg.
	stub := filepath.Join(e.work, "nogpg")
	mkdirAll(t, stub)
	for _, tool := range []string{"uname", "ls", "sed", "sort", "tail", "grep", "mktemp", "rm", "chmod", "mkdir", "install", "basename", "dirname", "printf", "tr", "cat"} {
		if p, err := exec.LookPath(tool); err == nil {
			require.NoError(t, os.Symlink(p, filepath.Join(stub, tool)))
		}
	}

	r := e.runInstaller(t, stub)
	require.NotZero(t, r.code, "the installer must not proceed without gpg")
	require.Contains(t, r.stderr, "gpg is not installed")
	require.Regexp(t, `pacman -S gnupg|apt install gnupg|dnf install gnupg2|brew install gnupg|install gnupg with`,
		r.stderr, "the message should name a command the user can actually run")
	require.NoFileExists(t, e.installedBinary())
}

// TestInstallerListsAvailablePlatforms covers the R5.6 failure path.
func TestInstallerListsAvailablePlatforms(t *testing.T) {
	e, _ := releasedStore(t)

	// Remove everything for the host platform, leaving only the other one.
	for _, suffix := range []string{"", ".sig", ".json"} {
		require.NoError(t, os.Remove(e.storePath("bootstrap", "angou-linux-amd64-0.1.0-dev"+suffix)))
	}

	r := e.runInstaller(t, "")
	require.NotZero(t, r.code)
	require.Contains(t, r.stderr, "holds no binary for")
	require.Contains(t, r.stderr, "darwin/arm64", "the message should list what is available")
}

// TestInstallerSelfCheckReportsDriftHonestly covers R5.8.2 and R5.8.3. The
// wording matters as much as the check: presenting this as proof the script was
// genuine would be a claim the design cannot support.
func TestInstallerSelfCheckReportsDriftHonestly(t *testing.T) {
	e, _ := releasedStore(t)

	script := e.storePath("bootstrap.sh")
	require.NoError(t, os.WriteFile(script,
		append(readFile(t, script), []byte("\n# a local edit\n")...), 0o755)) //nolint:gosec // it must stay executable

	r := e.runInstaller(t, "")
	require.NotZero(t, r.code, "a drifted installer must exit non-zero")
	require.Contains(t, r.stderr, "does not match its signature")
	require.Contains(t, r.stderr, "ran after the installer did",
		"the warning must describe detection after execution")
	require.NotContains(t, strings.ToLower(r.stderr), "guarantee")
}

// TestVerifyBootstrapDetectsASingleByte covers R5.8, the out-of-band check.
func TestVerifyBootstrapDetectsASingleByte(t *testing.T) {
	e, _ := releasedStore(t)

	require.Contains(t, e.mustRun("verify-bootstrap").stdout, "matches the digest")

	script := e.storePath("bootstrap.sh")
	raw := readFile(t, script)
	raw[len(raw)/2] ^= 0x20
	require.NoError(t, os.WriteFile(script, raw, 0o755)) //nolint:gosec // it must stay executable

	r := e.run("verify-bootstrap")
	require.NotZero(t, r.code, "a single altered byte must be reported")
	require.Contains(t, r.stderr, "MISMATCH")
}

// TestUnlockWarnsOnBootstrapDrift covers R5.8.1: the check also runs
// opportunistically, so an operator notices without having asked.
func TestUnlockWarnsOnBootstrapDrift(t *testing.T) {
	e, _ := releasedStore(t)

	script := e.storePath("bootstrap.sh")
	require.NoError(t, os.WriteFile(script, append(readFile(t, script), '\n'), 0o755)) //nolint:gosec // it must stay executable

	r := e.mustRun("ls")
	require.Contains(t, r.stderr, "WARNING")
	require.Contains(t, r.stderr, "bootstrap.sh")
	require.Zero(t, r.code, "a drifted installer must not make the store unreadable")
}

// TestRetentionPrunesPerPlatform covers R5.10.
func TestRetentionPrunesPerPlatform(t *testing.T) {
	e, _ := releasedStore(t)

	// Stand in extra versions for one platform, as successive releases would.
	dir := e.storePath("bootstrap")
	base := "angou-linux-amd64-0.1.0-dev"
	for _, version := range []string{"0.0.7", "0.0.8", "0.0.9"} {
		for _, suffix := range []string{"", ".sig", ".json"} {
			copyOver(t, filepath.Join(dir, base+suffix),
				filepath.Join(dir, "angou-linux-amd64-"+version+suffix))
		}
	}

	e.mustRun("prune", "--bootstrap", "--keep", "2")

	remaining := 0
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, de := range entries {
		if strings.HasPrefix(de.Name(), "angou-linux-amd64-") &&
			!strings.HasSuffix(de.Name(), ".sig") && !strings.HasSuffix(de.Name(), ".json") {
			remaining++
		}
	}
	require.Equal(t, 2, remaining, "retention must keep exactly --keep per platform")

	// The other platform is untouched, because retention is per platform.
	require.FileExists(t, filepath.Join(dir, "angou-darwin-arm64-0.1.0-dev"))
}

// TestCloneWithoutBinaries covers R5.10's second half.
func TestCloneWithoutBinaries(t *testing.T) {
	e, _ := releasedStore(t)
	src := e.writePlaintext("c.env", []byte("FIELD=value\n"), 0o600)
	e.mustRun("enc", "--as", "c.env", src)

	dest := filepath.Join(e.work, "clone")
	e.mustRun("clone", "--to", dest, "--no-binaries")

	require.NoFileExists(t, filepath.Join(dest, "bootstrap", "angou-linux-amd64-0.1.0-dev"),
		"the binaries must be omitted")
	require.FileExists(t, filepath.Join(dest, "bootstrap", "keybundle.json"),
		"the key bundle must not be")

	// The clone still holds every secret and still opens.
	require.Equal(t, "FIELD=value\n",
		e.runWithLines([]string{e.recovery}, "dec", "c.env", "--store", dest).stdout)
}

func copyOver(t *testing.T, src, dst string) {
	t.Helper()
	info, err := os.Stat(src)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(dst, readFile(t, src), info.Mode().Perm()))
}

func fieldAfter(t *testing.T, text, prefix string) string {
	t.Helper()
	for _, line := range strings.Split(text, "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), prefix); ok {
			return strings.TrimSpace(rest)
		}
	}
	t.Fatalf("no line starting %q in:\n%s", prefix, text)
	return ""
}

// TestInstallerPrefersAReleaseOverAPrerelease covers the ordering the installer
// has to share with the tool. `sort -V` ranks 0.1.0-dev above 0.1.0, which is
// backwards, and BSD sort has no -V at all — so the installer does the
// comparison itself and this pins the result.
func TestInstallerPrefersAReleaseOverAPrerelease(t *testing.T) {
	e, _ := releasedStore(t)
	dir := e.storePath("bootstrap")

	// A newer, non-prerelease build retained alongside the 0.1.0-dev one.
	for _, suffix := range []string{"", ".sig", ".json"} {
		copyOver(t, filepath.Join(dir, "angou-linux-amd64-0.1.0-dev"+suffix),
			filepath.Join(dir, "angou-linux-amd64-0.1.0"+suffix))
	}

	r := e.runInstaller(t, "")
	require.Zero(t, r.code, "the installer should succeed:\n%s", r.stderr)
	require.Contains(t, r.stderr, "installed angou-linux-amd64-0.1.0 to",
		"the release must be preferred over the pre-release it leads to")
	require.NotContains(t, r.stderr, "installed angou-linux-amd64-0.1.0-dev to")
}

// TestOlderBinaryIsRefusedByEveryCommand covers R5.4.2 where it matters. A
// replayed binary that could still read and write every blob would leave the
// rollback the floor exists to stop entirely usable; refusing only at bootstrap
// would close the door after the room had been emptied.
func TestOlderBinaryIsRefusedByEveryCommand(t *testing.T) {
	e := newEnv(t)
	e.initStore()
	src := e.writePlaintext("f.env", []byte("FIELD=value\n"), 0o600)
	e.mustRun("enc", "--as", "f.env", src)

	newer := buildVersioned(t, e, "9.9.9")
	key := filepath.Join(e.work, "signing.asc")
	e.mustRunNoPassphrase("release", "--new-signing-key", key)
	dist := filepath.Join(e.work, "dist")
	mkdirAll(t, dist)
	writeFakeBinary(t, filepath.Join(dist, "angou-linux-amd64"))
	runBinary(t, e, newer, []string{e.recovery}, "release", "--dist", dist, "--signing-key", key)

	for _, args := range [][]string{{"ls"}, {"dec", "f.env"}, {"enc", "--as", "g.env", src}, {"reindex"}} {
		r := e.run(args...)
		require.NotZero(t, r.code, "angou %v must refuse to run below the version floor", args)
		require.Contains(t, r.stderr, "9.9.9")
		require.Empty(t, r.stdout, "no store content may be produced")
	}
}

// TestCloneRefusesADestinationInsideTheStore covers the recursion: the walk
// creates the destination and then descends into it.
func TestCloneRefusesADestinationInsideTheStore(t *testing.T) {
	e := newEnv(t)
	e.initStore()
	seedStore(t, e, 2)

	r := e.run("clone", "--to", e.storePath("backup"))
	require.NotZero(t, r.code, "cloning a store into itself must be refused")
	require.Contains(t, r.stderr, "into itself")
	require.NoDirExists(t, e.storePath("backup"))
}

// TestCloneRefusesToFollowSymlinks covers the exfiltration path. Anyone who can
// write to a synced store could otherwise name a local file and have its
// contents copied into the clone.
func TestCloneRefusesToFollowSymlinks(t *testing.T) {
	e := newEnv(t)
	e.initStore()
	seedStore(t, e, 1)

	bait := filepath.Join(e.work, "private-key")
	require.NoError(t, os.WriteFile(bait, []byte("PRIVATE MATERIAL\n"), 0o600))
	require.NoError(t, os.Symlink(bait, e.storePath("aaaaaaaaaaaaaaaaaaaaaaaaab.angou")))

	dest := filepath.Join(e.work, "clone")
	r := e.run("clone", "--to", dest)
	require.NotZero(t, r.code, "a symlink in the store must be refused")
	require.Contains(t, r.stderr, "symlink")

	// And nothing outside the store was read into the copy.
	if entries, err := os.ReadDir(dest); err == nil {
		for _, de := range entries {
			if de.IsDir() {
				continue
			}
			require.NotContains(t, string(readFile(t, filepath.Join(dest, de.Name()))),
				"PRIVATE MATERIAL")
		}
	}
}

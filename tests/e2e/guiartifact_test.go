//go:build e2e

package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// The store may carry the desktop GUI, and recovery must never depend on it
// (spec 002 R2.2).
//
// The two names overlap — angou-gui-linux-amd64 also begins "angou-" — so every
// place that parses them has to test the longer prefix first. Get it wrong and a
// GUI build reads as a CLI build for a platform called "gui", which is not a
// parse error anywhere: it is a plausible-looking wrong answer that reaches the
// installer as a platform it offers to install from.

// releasedStoreWithGUI stashes a GUI artifact alongside the CLI ones, the way a
// release from a machine that can build the GUI would.
func releasedStoreWithGUI(t *testing.T) *env {
	t.Helper()
	requireGPG(t)

	e := newEnv(t)
	e.initStore()

	key := filepath.Join(e.work, "signing.asc")
	e.mustRunNoPassphrase("release", "--new-signing-key", key)

	dist := filepath.Join(e.work, "dist")
	mkdirAll(t, dist)
	writeFakeBinary(t, filepath.Join(dist, "angou-linux-amd64"))
	writeFakeBinary(t, filepath.Join(dist, "angou-darwin-arm64"))
	// The GUI cannot be cross-compiled, so a real release carries it for one
	// platform while the CLI covers every platform. That asymmetry is the case
	// worth testing, not a matching pair.
	// Distinguishable content, so a test can tell which artifact was installed
	// rather than only that something was.
	writeMarkedBinary(t, filepath.Join(dist, "angou-gui-linux-amd64"), guiMarker)

	e.mustRun("release", "--dist", dist, "--signing-key", key)
	return e
}

// guiMarker identifies the stand-in GUI binary in a test's output.
const guiMarker = "STAND-IN-FOR-THE-DESKTOP-GUI"

// writeMarkedBinary is a stand-in a test can recognise afterwards.
//
// The marker is appended rather than substituted: the bytes have to stay a
// readable Go binary, because release refuses to stash anything whose build it
// cannot identify. Trailing data does not disturb that — the build information
// lives in a section, not at the end of the file.
func writeMarkedBinary(t *testing.T, path, marker string) {
	t.Helper()
	writeFakeBinary(t, path)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o755)
	require.NoError(t, err)
	_, err = f.WriteString("\n" + marker + "\n")
	require.NoError(t, err)
	require.NoError(t, f.Close())
}

func TestReleaseStashesTheGUIAlongsideTheCLI(t *testing.T) {
	e := releasedStoreWithGUI(t)
	version := e.version(t)
	dir := e.storePath("bootstrap")

	gui := filepath.Join(dir, "angou-gui-linux-amd64-"+version)
	require.FileExists(t, gui, "the GUI should be stashed under its own name")
	require.FileExists(t, gui+".sig", "and signed like any other artifact")
	require.FileExists(t, gui+".json")

	// The CLI is still there for both platforms, including the one the GUI
	// shares. The two must not collide.
	require.FileExists(t, filepath.Join(dir, "angou-linux-amd64-"+version))
	require.FileExists(t, filepath.Join(dir, "angou-darwin-arm64-"+version))
}

// TestInstallerIgnoresTheGUI is the one that matters. bootstrap.sh globs
// angou-* and derives a platform from the name; without an explicit exclusion it
// would offer "gui/linux" as somewhere to install from, and a machine answering
// to it would be handed a binary needing OpenGL and a display server.
func TestInstallerIgnoresTheGUI(t *testing.T) {
	e := releasedStoreWithGUI(t)

	// Remove the CLI for the host platform, which is what drives the installer
	// down the "no binary for this platform" path where it lists what it does
	// have. Without that it simply installs and never says which platforms it
	// considers available — and the listing is where a misparsed GUI name would
	// surface.
	for _, suffix := range []string{"", ".sig", ".json"} {
		require.NoError(t, os.Remove(e.storePath("bootstrap", e.binaryName(t, "linux-amd64")+suffix)))
	}

	r := e.runInstaller(t, "")
	require.NotZero(t, r.code, "with no CLI for this platform the installer must refuse")
	listed := r.stdout + r.stderr

	require.Contains(t, listed, "darwin/arm64", "it should still list the platform it has")
	require.NotContains(t, listed, "gui/",
		"the installer must not read a GUI build as a platform:\n%s", listed)
	require.NotContains(t, listed, "gui-linux",
		"nor offer the GUI artifact itself:\n%s", listed)
}

// TestBareMachineStillInstallsTheCLIWithAGUIPresent: the GUI sharing a platform
// with the CLI must not change which binary a bare machine ends up with.
func TestBareMachineStillInstallsTheCLIWithAGUIPresent(t *testing.T) {
	e := releasedStoreWithGUI(t)

	r := e.runInstaller(t, "")
	if r.code != 0 {
		// This machine's platform may not be one the fixture stashed, which is
		// the unsupported-platform path and is covered elsewhere.
		t.Skipf("installer exited %d on this platform:\n%s", r.code, r.stderr)
	}
	installed := readFile(t, e.installedBinary())
	require.NotContains(t, string(installed), guiMarker,
		"a bare machine must be installed the CLI, never the GUI")
}

// TestRetentionKeepsTheCLIWhenGUIsAccumulate covers the counting rule: retention
// is per kind as well as per platform. Counted together, a run of GUI builds
// would evict the CLI for the same platform — the one artifact a bare machine
// cannot do without.
func TestRetentionKeepsTheCLIWhenGUIsAccumulate(t *testing.T) {
	e := releasedStoreWithGUI(t)
	dir := e.storePath("bootstrap")
	version := e.version(t)

	base := filepath.Join(dir, "angou-gui-linux-amd64-"+version)
	for _, v := range []string{"0.0.7", "0.0.8", "0.0.9"} {
		for _, suffix := range []string{"", ".sig", ".json"} {
			copyOver(t, base+suffix, filepath.Join(dir, "angou-gui-linux-amd64-"+v+suffix))
		}
	}

	e.mustRun("prune", "--bootstrap", "--keep", "2")

	require.FileExists(t, filepath.Join(dir, "angou-linux-amd64-"+version),
		"pruning GUI builds must not remove the CLI for the same platform")

	guis := 0
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, de := range entries {
		name := de.Name()
		if strings.HasPrefix(name, "angou-gui-linux-amd64-") &&
			!strings.HasSuffix(name, ".sig") && !strings.HasSuffix(name, ".json") {
			guis++
		}
	}
	require.Equal(t, 2, guis, "retention must keep exactly --keep GUI builds per platform")
}

// TestBareMachineAlsoInstallsTheGUIWhenPresent: the GUI is a bonus the
// installer picks up, never something recovery waits for. When the store has one
// for this platform it arrives with a desktop entry and an icon, the same three
// files install.sh places.
func TestBareMachineAlsoInstallsTheGUIWhenPresent(t *testing.T) {
	e := releasedStoreWithGUI(t)

	r := e.runInstaller(t, "")
	if r.code != 0 {
		t.Skipf("installer exited %d on this platform:\n%s", r.code, r.stderr)
	}

	home := filepath.Join(e.work, "baremachine")
	gui := filepath.Join(home, "bin", "angou-gui")
	require.FileExists(t, gui, "the GUI should be installed when the store carries one")
	require.Contains(t, string(readFile(t, gui)), guiMarker)

	// The basename has to match the Wayland app_id the GUI sets, or the taskbar
	// shows a generic icon and no name.
	desktop := filepath.Join(home, ".local", "share", "applications", "io.ushineko.angou.desktop")
	require.FileExists(t, desktop)
	entry := string(readFile(t, desktop))
	require.Contains(t, entry, "StartupWMClass=io.ushineko.angou")
	require.Contains(t, entry, filepath.Join(home, "bin", "angou-gui"),
		"the entry must point at the binary it just installed, not a name on PATH")

	icon := filepath.Join(home, ".local", "share", "icons", "hicolor", "scalable", "apps", "angou.svg")
	require.FileExists(t, icon, "the entry's Icon= key must resolve to something")
	require.Contains(t, string(readFile(t, icon)), "<svg",
		"the icon should be the drawing, not an unsubstituted placeholder")
	require.NotContains(t, string(readFile(t, icon)), "__ANGOU_ICON_SVG__")
}

// TestBareMachineWithoutAGUISaysSoAndCarriesOn: a store with no GUI for this
// platform is the normal case. Recovery must not treat it as a failure.
func TestBareMachineWithoutAGUISaysSoAndCarriesOn(t *testing.T) {
	e, _ := releasedStore(t) // CLI only

	r := e.runInstaller(t, "")
	if r.code != 0 {
		t.Skipf("installer exited %d on this platform:\n%s", r.code, r.stderr)
	}
	require.FileExists(t, e.installedBinary(), "the CLI must install regardless")
	require.Contains(t, r.stderr+r.stdout, "carries no desktop GUI",
		"it should say why there is no GUI rather than staying silent")
	require.NoFileExists(t, filepath.Join(e.work, "baremachine", "bin", "angou-gui"))
}

// TestReleaseRefusesAStaleBuild is the guard behind the mislabelling bug.
//
// The metadata beside a stashed artifact records the version and commit of the
// tool doing the stashing, not of the artifact. A dist/ directory left over from
// an earlier build was therefore stashed under the current version, signed, and
// served to another machine — which reported the older version and was refused
// by the store's own version floor. The signature was valid throughout: it signs
// the bytes, and cannot notice that the description beside them is wrong.
func TestReleaseRefusesAStaleBuild(t *testing.T) {
	requireGPG(t)

	e := newEnv(t)
	e.initStore()
	key := filepath.Join(e.work, "signing.asc")
	e.mustRunNoPassphrase("release", "--new-signing-key", key)

	dist := filepath.Join(e.work, "dist")
	mkdirAll(t, dist)
	// A Go binary from some other build: any binary not built from this commit
	// will do, and the Go toolchain is one that is certainly present.
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go binary to stand in for a foreign build")
	}
	copyOver(t, goBin, filepath.Join(dist, "angou-linux-amd64"))
	require.NoError(t, os.Chmod(filepath.Join(dist, "angou-linux-amd64"), 0o755))

	r := e.run("release", "--dist", dist, "--signing-key", key)
	require.NotZero(t, r.code, "a binary from another build must not be stashed")

	// Either refusal is the guard working. A binary from a different commit
	// says so; one built outside a repository — which the Go toolchain's own
	// binary is — carries no revision at all, and an artifact that cannot say
	// which build it is cannot be described by metadata claiming to know.
	require.Truef(t,
		strings.Contains(r.stderr, "was built from commit") ||
			strings.Contains(r.stderr, "carries no VCS revision"),
		"the refusal should say the build could not be confirmed:\n%s", r.stderr)

	// Nothing was stashed under a version it does not have.
	entries, err := os.ReadDir(e.storePath("bootstrap"))
	require.NoError(t, err)
	for _, de := range entries {
		require.NotContains(t, de.Name(), "angou-linux-amd64-",
			"the refused artifact must not be in the store")
	}
}

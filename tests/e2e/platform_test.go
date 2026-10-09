//go:build e2e

package e2e

import (
	"debug/pe"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// requirePerm asserts a file's permission bits where the platform has them.
// Windows has none: Go reports 0666 or 0444 for every file and the ACL is what
// guards it, so there is nothing for this assertion to check there. What angou
// records for a Windows file is checked separately, through ls.
func requirePerm(t *testing.T, info os.FileInfo, want os.FileMode, msgAndArgs ...any) {
	t.Helper()
	if runtime.GOOS == "windows" {
		return
	}
	require.Equal(t, want, info.Mode().Perm(), msgAndArgs...)
}

// logicalOf is the logical path angou derives for an absolute path outside the
// home directory: the path with its root removed, so /srv/x is srv/x and, on
// Windows, C:\srv\x is srv/x.
func logicalOf(abs string) string {
	trimmed := strings.TrimPrefix(filepath.ToSlash(abs), filepath.ToSlash(filepath.VolumeName(abs)))
	return strings.TrimPrefix(trimmed, "/")
}

// exeName is name with the platform's executable suffix, for test builds that
// have to be runnable by name.
func exeName(name string) string {
	if runtime.GOOS == "windows" {
		return name + ".exe"
	}
	return name
}

// gpgHomePath renders a directory the way the gpg on PATH reads GNUPGHOME.
//
// A native gpg.exe (Gpg4win) takes the Windows path as it is. Git for Windows
// ships an MSYS build that only treats a path starting with "/" as absolute,
// so C:\x has to reach it as /c/x or it looks for its keyring under the
// working directory.
func gpgHomePath(dir string) string {
	if runtime.GOOS != "windows" {
		return dir
	}
	gpg, err := exec.LookPath("gpg")
	if err != nil || !strings.Contains(strings.ToLower(gpg), `\usr\bin\`) {
		return dir
	}
	volume := filepath.VolumeName(dir)
	if len(volume) != 2 || volume[1] != ':' {
		return filepath.ToSlash(dir)
	}
	return "/" + strings.ToLower(volume[:1]) + filepath.ToSlash(dir[2:])
}

// requireOnlySystemImports is the Windows form of the static-binary check.
//
// No Windows program is static in the ELF sense: everything reaches the kernel
// through kernel32.dll. What R6.2 protects is that a bare machine needs nothing
// installed, so the check is that every DLL the PE import table names ships
// with Windows itself. A CGO build would name the MinGW runtime here, and that
// is the regression this catches. DLLs loaded lazily at run time (advapi32 for
// the Credential Manager) are Windows components too and do not appear.
func requireOnlySystemImports(t *testing.T, bin string) {
	t.Helper()
	f, err := pe.Open(bin)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	// debug/pe leaves ImportedLibraries unimplemented; ImportedSymbols reports
	// each import as "symbol:library", which carries the same information.
	symbols, err := f.ImportedSymbols()
	require.NoError(t, err)
	seen := map[string]bool{}
	var libs []string
	for _, sym := range symbols {
		if _, lib, ok := strings.Cut(sym, ":"); ok && !seen[strings.ToLower(lib)] {
			seen[strings.ToLower(lib)] = true
			libs = append(libs, lib)
		}
	}
	require.NotEmpty(t, libs, "a PE binary imports at least kernel32.dll")

	system := filepath.Join(os.Getenv("SystemRoot"), "System32")
	for _, lib := range libs {
		_, err := os.Stat(filepath.Join(system, lib))
		require.NoError(t, err, "%s imports %s, which is not a Windows system DLL", filepath.Base(bin), lib)
		require.NotContains(t, strings.ToLower(lib), "libgcc")
		require.NotContains(t, strings.ToLower(lib), "libwinpthread")
	}
}

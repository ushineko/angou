package release

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestCompareVersions pins the ordering the version floor depends on. A string
// comparison gets 0.10.0 against 0.9.0 backwards, and the floor is what stops an
// older signed binary from being replayed, so the ordering is load-bearing.
func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.0", 0},
		{"1.0.1", "1.0.0", 1},
		{"1.0.0", "1.0.1", -1},
		{"0.10.0", "0.9.0", 1},
		{"0.9.0", "0.10.0", -1},
		{"2.0.0", "1.99.99", 1},
		{"1.0", "1.0.0", 0},
		{"v1.2.3", "1.2.3", 0},
		// A pre-release precedes the release it leads to.
		{"1.0.0-dev", "1.0.0", -1},
		{"1.0.0", "1.0.0-dev", 1},
		{"0.1.0-dev", "0.1.0-dev", 0},
		{"0.2.0-dev", "0.1.0", 1},
	}
	for _, tc := range cases {
		t.Run(tc.a+" vs "+tc.b, func(t *testing.T) {
			require.Equal(t, tc.want, CompareVersions(tc.a, tc.b))
			require.Equal(t, -tc.want, CompareVersions(tc.b, tc.a), "the comparison must be symmetric")
		})
	}
}

func TestParseBinaryName(t *testing.T) {
	kind, goos, goarch, version, ok := ParseBinaryName("angou-linux-amd64-0.1.0-dev")
	require.Equal(t, KindCLI, kind)
	require.True(t, ok)
	require.Equal(t, "linux", goos)
	require.Equal(t, "amd64", goarch)
	require.Equal(t, "0.1.0-dev", version, "a version may contain the separator itself")

	require.Equal(t, "angou-darwin-arm64-1.2.3", BinaryName(KindCLI, "darwin", "arm64", "1.2.3"))
	require.Equal(t, "angou-gui-darwin-arm64-1.2.3", BinaryName(KindGUI, "darwin", "arm64", "1.2.3"))

	// The two prefixes overlap, so the GUI name must not be read as a CLI build
	// for the platform "gui". This is the case the longest-prefix-first rule in
	// ParseBinaryName exists for.
	kind, goos, goarch, version, ok = ParseBinaryName("angou-gui-linux-amd64-0.1.4")
	require.True(t, ok)
	require.Equal(t, KindGUI, kind)
	require.Equal(t, "linux", goos)
	require.Equal(t, "amd64", goarch)
	require.Equal(t, "0.1.4", version)

	for _, bad := range []string{"angou", "angou-linux", "notangou-linux-amd64-1.0.0", "keybundle.json"} {
		_, _, _, _, ok := ParseBinaryName(bad)
		require.False(t, ok, "%q should not parse as a binary name", bad)
	}
}

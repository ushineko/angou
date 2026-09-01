package keybundle

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestCheckMemoryDecision pins the arithmetic rather than the platform probe.
// The probe is exercised end-to-end against a real cgroup limit; what matters
// here is that the comparison includes headroom and that an unreadable platform
// does not turn into a refusal.
func TestCheckMemoryDecision(t *testing.T) {
	const oneGiB = 1 << 20 // KiB

	cases := []struct {
		name      string
		params    Params
		report    memoryReport
		wantError bool
	}{
		{
			name:      "plenty available",
			params:    Params{MemoryKiB: oneGiB},
			report:    memoryReport{availableKiB: 8 << 20, known: true},
			wantError: false,
		},
		{
			name:      "exactly enough including headroom",
			params:    Params{MemoryKiB: oneGiB},
			report:    memoryReport{availableKiB: oneGiB + derivationHeadroomKiB, known: true},
			wantError: false,
		},
		{
			name:      "enough for the blocks but not the headroom",
			params:    Params{MemoryKiB: oneGiB},
			report:    memoryReport{availableKiB: oneGiB, known: true},
			wantError: true,
		},
		{
			// The floor plus headroom must clear a small container, or the
			// check refuses work the machine could actually have done.
			name:      "128 MiB container clears the pinned floor",
			params:    Params{MemoryKiB: FloorMemoryKiB},
			report:    memoryReport{availableKiB: 122 << 10, known: true},
			wantError: false,
		},
		{
			name:      "far too little",
			params:    Params{MemoryKiB: oneGiB},
			report:    memoryReport{availableKiB: 180 << 10, known: true},
			wantError: true,
		},
		{
			name:      "platform cannot say",
			params:    Params{MemoryKiB: oneGiB},
			report:    memoryReport{known: false},
			wantError: false,
		},
		{
			// The pinned floor is chosen so that a small container clears it.
			name:      "the pinned floor fits a small container",
			params:    Params{MemoryKiB: FloorMemoryKiB},
			report:    memoryReport{availableKiB: 197 << 10, known: true},
			wantError: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.params.checkMemoryAgainst(tc.report)
			if !tc.wantError {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, ErrInsufficientMemory)
			require.Contains(t, err.Error(), "Free memory or raise the limit")
		})
	}
}

// TestCheckMemoryNamesTheLimit checks that a cgroup-constrained process is told
// what to change, rather than being told the host has plenty.
func TestCheckMemoryNamesTheLimit(t *testing.T) {
	p := Params{MemoryKiB: 1 << 20}
	err := p.checkMemoryAgainst(memoryReport{
		availableKiB: 180 << 10,
		known:        true,
		limitNote:    " (this process is capped at 200 MiB by its cgroup)",
	})
	require.ErrorIs(t, err, ErrInsufficientMemory)
	require.Contains(t, err.Error(), "capped at 200 MiB by its cgroup")
	require.Contains(t, err.Error(), "needs 1024 MiB")
	require.Contains(t, err.Error(), "only 180 MiB")
}

// TestAvailableMemoryProbe records what this machine reports. It asserts only
// internal consistency, because the values are properties of the host.
func TestAvailableMemoryProbe(t *testing.T) {
	report := availableMemory()
	t.Logf("available=%d KiB known=%v note=%q", report.availableKiB, report.known, report.limitNote)
	if report.known {
		require.NotZero(t, report.availableKiB, "a known report should carry a figure")
	}
}

package keybundle

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSealOpenRoundTrip(t *testing.T) {

	identity := []byte("stand-in for an exported identity")
	passphrase := []byte("unit-test-unlock-input")

	bundle, err := Seal(identity, passphrase)
	require.NoError(t, err)
	raw, err := Marshal(bundle)
	require.NoError(t, err)
	// The parameters must be readable without the passphrase: a reader has to
	// check them against the floor before spending a derivation on them.
	require.Contains(t, string(raw), "argon2id")
	require.Contains(t, string(raw), "memory_kib")
	// The identity must not be.
	require.NotContains(t, string(raw), "stand-in for an exported")

	parsed, err := Unmarshal(raw)
	require.NoError(t, err)
	got, err := parsed.Open(passphrase)
	require.NoError(t, err)
	require.Equal(t, identity, got)
}

func TestOpenRefusesWrongPassphrase(t *testing.T) {

	bundle, err := Seal([]byte("identity"), []byte("opens-it"))
	require.NoError(t, err)

	_, err = bundle.Open([]byte("does-not-open-it"))
	require.ErrorIs(t, err, ErrBadPassphrase)
}

// TestOpenRefusesDowngradedParameters is the control of R2.2.1: an attacker who
// can write to the store must not be able to edit the recorded parameters and
// make the offline target cheap.
func TestOpenRefusesDowngradedParameters(t *testing.T) {

	bundle, err := Seal([]byte("identity"), []byte("unit-test-unlock-input"))
	require.NoError(t, err)

	for name, mutate := range map[string]func(*Params){
		"memory below the floor":      func(p *Params) { p.MemoryKiB = 1 },
		"time below the floor":        func(p *Params) { p.Time = 0 },
		"parallelism below the floor": func(p *Params) { p.Parallelism = 0 },
		"salt truncated":              func(p *Params) { p.Salt = p.Salt[:8] },
		"algorithm swapped":           func(p *Params) { p.Algorithm = "pbkdf2" },
	} {
		t.Run(name, func(t *testing.T) {
			tampered := *bundle
			tampered.KDF = bundle.KDF
			mutate(&tampered.KDF)

			_, err := tampered.Open([]byte("unit-test-unlock-input"))
			require.ErrorIs(t, err, ErrWeakKDF)
		})
	}
}

// TestFloorIsEnforced checks that parameters below the pinned floor are refused
// and that the floor itself is accepted.
func TestFloorIsEnforced(t *testing.T) {
	weak := Params{
		Algorithm:   "argon2id",
		MemoryKiB:   8 << 10,
		Time:        1,
		Parallelism: 1,
		Salt:        make([]byte, FloorSaltLen),
	}
	require.ErrorIs(t, weak.Validate(), ErrWeakKDF)

	strong := Params{
		Algorithm:   "argon2id",
		MemoryKiB:   FloorMemoryKiB,
		Time:        FloorTime,
		Parallelism: FloorParallelism,
		Salt:        make([]byte, FloorSaltLen),
	}
	require.NoError(t, strong.Validate())
}

func TestDefaultParamsMeetTheFloor(t *testing.T) {
	p, err := DefaultParams()
	require.NoError(t, err)
	require.Equal(t, FloorMemoryKiB, p.MemoryKiB)
	require.Equal(t, FloorTime, p.Time)
	require.Equal(t, FloorParallelism, p.Parallelism)
	require.Len(t, p.Salt, FloorSaltLen)
	require.NoError(t, p.Validate())
}

func TestSaltIsFreshPerBundle(t *testing.T) {
	a, err := Seal([]byte("x"), []byte("unit-test-unlock-input"))
	require.NoError(t, err)
	b, err := Seal([]byte("x"), []byte("unit-test-unlock-input"))
	require.NoError(t, err)
	require.NotEqual(t, a.KDF.Salt, b.KDF.Salt)
	require.NotEqual(t, a.WrappedKey, b.WrappedKey)
	require.NotEqual(t, a.Payload, b.Payload)
}

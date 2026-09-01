package gui

import "time"

// The types in this file are the view models of spec 002 R8.2: the shapes the
// widgets render, converted from what internal/core returns. They are separate
// from core's own types on purpose — core's describe the store, these describe
// what to draw, and collapsing the two would put presentation decisions in the
// package both front ends share.

// UnlockRoute names how this machine currently opens the store. It drives the
// status bar and nothing else; it is not a capability check.
type UnlockRoute int

// The routes unlock() tries, in the order it prefers them in reverse: the agent
// is the fastest and the recovery passphrase is the fallback for a machine with
// no keyring backend.
const (
	// UnlockNone means no store is configured on this machine yet.
	UnlockNone UnlockRoute = iota
	// UnlockPassphrase means every command asks for the recovery passphrase.
	UnlockPassphrase
	// UnlockLocalKey means this machine holds a local key, unwrapped by the keyring.
	UnlockLocalKey
	// UnlockAgent means a running agent is holding the key.
	UnlockAgent
)

func (u UnlockRoute) String() string {
	switch u {
	case UnlockPassphrase:
		return "recovery passphrase"
	case UnlockLocalKey:
		return "this machine's key"
	case UnlockAgent:
		return "agent session"
	}
	return "no store"
}

// StoreEntry is one row of the Store table — the `ls` listing.
type StoreEntry struct {
	LogicalPath string // as you named it
	RawName     string // as it sits on disk, for the --raw toggle
	Size        int64
	// Mode is the POSIX mode the file had when it was stored. The index does
	// not record the container encoding, so this is shown instead -- it is also
	// what `ls` shows, and it is the field that matters when deciding whether a
	// restore would widen a private key's permissions.
	Mode     uint32
	Modified time.Time
	Origin   string // recorded origin, or empty when there is none
}

// ScanCandidate is one row of the Encrypt scan — what `enc --all --dry-run`
// found, with the reason the scanner flagged it.
type ScanCandidate struct {
	Path     string
	Reason   string
	Size     int64
	Selected bool
	Stored   bool // already in the store; shown but not selectable
}

// Status ranks a doctor row so the report can be read at a glance rather than
// parsed line by line (R5.5).
type Status int

const (
	// StatusInfo is a plain fact with no judgement attached.
	StatusInfo Status = iota
	// StatusGood is a state the user wants to be in.
	StatusGood
	// StatusWarn is a state that needs an action but has broken nothing yet.
	StatusWarn
	// StatusBad is a state that is already costing the user something.
	StatusBad
)

// DoctorRow is one finding. DoctorGroup is the subject it belongs to.
type DoctorRow struct {
	Label  string
	Value  string
	Status Status
	Note   string // shown under the row when the value alone does not explain itself
}

// DoctorGroup is a set of findings sharing a subject.
type DoctorGroup struct {
	Title string
	Rows  []DoctorRow
}

// ReleaseEntry is one stashed binary in the bootstrap namespace.
type ReleaseEntry struct {
	Platform string
	Version  string
	Size     int64
	Signed   bool
}

// AgentState is what the Agent section reports.
type AgentState struct {
	Running   bool
	Remaining time.Duration
	Socket    string
}

// Session is everything the window knows. A passphrase is deliberately not a
// field here: R7.2 forbids holding one beyond the operation that needed it.
type Session struct {
	StoreDir string
	Route    UnlockRoute
	Agent    AgentState
}

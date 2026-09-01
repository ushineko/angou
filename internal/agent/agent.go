// Package agent implements the session cache (spec 001 R6.5).
//
// Without gpg-agent there is nothing holding unlocked key material between
// commands, so every command pays for a key derivation or a keyring round trip.
// This daemon holds the unlocked identity behind a unix socket for a bounded
// time.
//
// What it is not: a security boundary against anything running as you. The
// socket's 0600 mode excludes other users and nothing else. Any process running
// under your uid after unlock can connect within the TTL and ask for the key,
// and peer-credential checks, buffer zeroing, and mlockall do not change that —
// they raise the cost of accidents and of other users, not of malware already
// running as you. R-10 says this plainly and so does the command's help text.
// Same-uid compromise after unlock is out of scope, and the honest mitigations
// are a small API and a short TTL, both of which this has.
package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// DefaultTTL is how long the cache holds key material. It is short on purpose:
// the window in which a same-uid process can ask for the key is the main thing
// the design can actually control.
const DefaultTTL = 10 * time.Minute

// Protocol operations. The API is deliberately tiny — every operation is
// something a same-uid attacker gets for free, so there is no reason to offer
// more of them than the tool needs.
const (
	// OpIdentity returns the unlocked identity to an authenticated peer.
	OpIdentity = "identity"
	// OpStatus reports the remaining lifetime.
	OpStatus = "status"
	// OpStop terminates the agent, releasing cached material before the TTL
	// expires (R6.4.1).
	OpStop = "stop"
)

var (
	// ErrNoAgent reports that no agent is listening for this store.
	ErrNoAgent = errors.New("no agent is running for this store")
	// ErrExpired reports that the cache has passed its TTL.
	ErrExpired = errors.New("the agent's cached key material has expired")
	// ErrDenied reports a peer this agent will not serve.
	ErrDenied = errors.New("the connecting process is not permitted")
)

// Request is one command to the agent.
type Request struct {
	Op string `json:"op"`
}

// Response is the agent's reply.
type Response struct {
	Error string `json:"error,omitempty"`
	// Identity is the serialized store identity, base64-encoded by encoding/json.
	Identity []byte `json:"identity,omitempty"`
	// ExpiresIn is the remaining lifetime in seconds.
	ExpiresIn int64 `json:"expires_in,omitempty"`
	// Fingerprint identifies which store the agent holds.
	Fingerprint string `json:"fingerprint,omitempty"`
}

func encode(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("encode agent message: %w", err)
	}
	return append(raw, '\n'), nil
}

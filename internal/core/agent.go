package core

import (
	"errors"
	"time"

	"github.com/ushineko/angou/internal/agent"
	"github.com/ushineko/angou/internal/prompt"
)

// The session cache.
//
// Worth being clear about what this is for, because it is easy to reach for and
// mostly unnecessary. On a machine that has been bootstrapped it earns almost
// nothing: the local key carries no stretching at all, so the keyring route is
// already about as fast, and a session gives up something real in exchange --
// the keyring's copy stops being available when the wallet locks and the
// agent's does not. Where it earns its place is a machine with no keyring
// backend, which today includes every Mac, and where the alternative is an
// Argon2id derivation and a passphrase prompt on every command.

// AgentStatus is what an agent reports about itself.
type AgentStatus struct {
	// Running is false when no agent is holding this store.
	Running bool
	// Expired reports an agent past its lifetime and shutting down. Its key
	// material is already released.
	Expired     bool
	Remaining   time.Duration
	Fingerprint string
	Socket      string
}

// AgentState reports whether an agent is holding this store, and for how much
// longer.
func AgentState(dir string) (AgentStatus, error) {
	client, err := agent.Dial(dir)
	if err != nil {
		if errors.Is(err, agent.ErrNoAgent) {
			return AgentStatus{}, nil
		}
		return AgentStatus{}, err
	}
	remaining, fingerprint, err := client.Status()
	if err != nil {
		if errors.Is(err, agent.ErrExpired) {
			return AgentStatus{Running: true, Expired: true, Socket: client.Socket()}, nil
		}
		return AgentStatus{}, err
	}
	return AgentStatus{
		Running:     true,
		Remaining:   remaining,
		Fingerprint: fingerprint,
		Socket:      client.Socket(),
	}, nil
}

// StopAgent releases the cached key material now, without waiting for the
// lifetime to run out. It reports false when no agent was running, which is not
// an error.
func StopAgent(dir string) (bool, error) {
	client, err := agent.Dial(dir)
	if err != nil {
		if errors.Is(err, agent.ErrNoAgent) {
			return false, nil
		}
		return false, err
	}
	if err := client.Stop(); err != nil {
		return false, err
	}
	return true, nil
}

// AgentSocket is where the agent for a store listens.
func AgentSocket(dir string) (string, error) { return agent.SocketPath(dir) }

// StartAgent unlocks the store and holds the key behind a socket until ttl runs
// out. It blocks until the agent stops.
//
// The lifetime is the point. While the agent is up, anything running under the
// same account can ask it for the key, so how long it runs is how long that is
// true. Checking peer credentials and wiping buffers does not change that, and
// neither does locking memory: if something is already running as the user,
// this tool cannot defend against it, and the short lifetime is the real
// mitigation rather than any of the machinery.
func StartAgent(s *Session, socket string, ttl time.Duration, ev Events) error {
	identity, err := s.ExportLocalIdentity()
	if err != nil {
		return err
	}
	defer prompt.Zero(identity)

	// NewServer takes its own copy, so this one is wiped straight away rather
	// than at return: the agent then runs for the whole TTL with one copy of
	// the key in memory instead of two.
	server := agent.NewServer(socket, s.Fingerprint(), identity, ttl)
	prompt.Zero(identity)
	if err := server.Listen(); err != nil {
		return err
	}
	// Best-effort, and reported as such. Failing to lock memory is not a reason
	// to refuse to run, and claiming success would be worse than saying it did
	// not happen.
	if err := agent.LockMemory(); err != nil {
		ev.logf("could not lock memory (%v); key material may reach swap", err)
	}
	return server.Serve()
}

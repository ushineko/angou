package agent

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

// Server holds unlocked key material for a bounded time.
type Server struct {
	socket      string
	fingerprint string

	mu       sync.Mutex
	identity []byte
	expires  time.Time

	listener net.Listener
	done     chan struct{}
	stopOnce sync.Once
}

// NewServer prepares an agent. It copies the identity, because the caller is
// expected to zero its own copy.
func NewServer(socket, fingerprint string, identity []byte, ttl time.Duration) *Server {
	held := make([]byte, len(identity))
	copy(held, identity)
	return &Server{
		socket:      socket,
		fingerprint: fingerprint,
		identity:    held,
		expires:     time.Now().Add(ttl),
		done:        make(chan struct{}),
	}
}

// Listen binds the socket at 0600.
//
// The mode excludes other users. It is not a boundary against other processes
// running as this user, and nothing here should be read as claiming otherwise.
func (s *Server) Listen() error {
	// A stale socket from a killed agent would block the bind. Removing it is
	// safe because the path is per-user and per-store.
	if err := os.Remove(s.socket); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove stale socket: %w", err)
	}
	// Bind under a restrictive umask so there is no window in which the socket
	// exists with wider permissions than intended.
	old := setUmask(0o177)
	var config net.ListenConfig
	listener, err := config.Listen(context.Background(), "unix", s.socket)
	setUmask(old)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", s.socket, err)
	}
	if err := os.Chmod(s.socket, 0o600); err != nil {
		_ = listener.Close()
		return fmt.Errorf("restrict %s: %w", s.socket, err)
	}
	s.listener = listener
	return nil
}

// Serve accepts connections until the TTL expires or Stop is called.
func (s *Server) Serve() error {
	defer s.cleanup()

	go func() {
		select {
		case <-time.After(time.Until(s.expires)):
			s.Stop()
		case <-s.done:
		}
	}()

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.done:
				return nil
			default:
				return fmt.Errorf("accept: %w", err)
			}
		}
		s.handle(conn)
	}
}

// Stop terminates the agent and releases what it holds.
func (s *Server) Stop() {
	s.stopOnce.Do(func() {
		close(s.done)
		if s.listener != nil {
			_ = s.listener.Close()
		}
	})
}

// cleanup zeroes the cached material and removes the socket.
//
// Zeroing is best-effort and is documented as such rather than claimed: Go's
// garbage collector may have copied the buffer before this runs, and the copy is
// not reachable to be wiped (R-2).
func (s *Server) cleanup() {
	s.mu.Lock()
	for i := range s.identity {
		s.identity[i] = 0
	}
	s.identity = nil
	s.mu.Unlock()
	_ = os.Remove(s.socket)
}

func (s *Server) handle(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Peer credentials are checked before anything is served. This keeps out
	// other users even if the socket's mode were somehow wrong; it does not and
	// cannot keep out another process of this user's own.
	if err := checkPeer(conn); err != nil {
		_ = writeResponse(conn, Response{Error: err.Error()})
		return
	}

	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		return
	}
	var req Request
	if err := decodeRequest(line, &req); err != nil {
		_ = writeResponse(conn, Response{Error: err.Error()})
		return
	}

	s.mu.Lock()
	expired := time.Now().After(s.expires) || s.identity == nil
	remaining := int64(time.Until(s.expires).Seconds())
	identity := s.identity
	s.mu.Unlock()

	if expired {
		_ = writeResponse(conn, Response{Error: ErrExpired.Error()})
		s.Stop()
		return
	}

	switch req.Op {
	case OpIdentity:
		_ = writeResponse(conn, Response{Identity: identity, ExpiresIn: remaining, Fingerprint: s.fingerprint})
	case OpStatus:
		_ = writeResponse(conn, Response{ExpiresIn: remaining, Fingerprint: s.fingerprint})
	case OpStop:
		_ = writeResponse(conn, Response{ExpiresIn: 0, Fingerprint: s.fingerprint})
		s.Stop()
	default:
		_ = writeResponse(conn, Response{Error: fmt.Sprintf("unknown operation %q", req.Op)})
	}
}

func writeResponse(conn net.Conn, resp Response) error {
	raw, err := encode(resp)
	if err != nil {
		return err
	}
	if _, err := conn.Write(raw); err != nil {
		return fmt.Errorf("write response: %w", err)
	}
	return nil
}

func decodeRequest(line []byte, req *Request) error {
	if err := unmarshal(line, req); err != nil {
		return errors.New("malformed request")
	}
	return nil
}

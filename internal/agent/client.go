package agent

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"time"
)

// Client talks to a running agent.
type Client struct{ socket string }

// Dial connects to the agent for a store, or reports ErrNoAgent.
//
// Being unable to work out where a socket would live — an unwritable runtime
// directory, a path over the length limit — is reported as ErrNoAgent rather
// than as a distinct failure. There is no agent either way, and the caller's
// only reasonable response is the same: carry on without one. Reporting it
// separately produced a warning about an agent refusing to serve a key on
// machines that had never run one.
func Dial(storeDir string) (*Client, error) {
	socket, err := SocketPath(storeDir)
	if err != nil {
		return nil, ErrNoAgent
	}
	if _, err := os.Stat(socket); err != nil {
		return nil, ErrNoAgent
	}
	return &Client{socket: socket}, nil
}

// Socket returns the path this client talks to.
func (c *Client) Socket() string { return c.socket }

func (c *Client) call(op string) (Response, error) {
	var resp Response

	var dialer net.Dialer
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	conn, err := dialer.DialContext(ctx, "unix", c.socket)
	if err != nil {
		// A socket file with nothing behind it is a killed agent, not an error
		// the user did anything about.
		return resp, ErrNoAgent
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	raw, err := encode(Request{Op: op})
	if err != nil {
		return resp, err
	}
	if _, err := conn.Write(raw); err != nil {
		return resp, fmt.Errorf("write to agent: %w", err)
	}
	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		return resp, fmt.Errorf("read from agent: %w", err)
	}
	if err := unmarshal(line, &resp); err != nil {
		return resp, err
	}
	if resp.Error != "" {
		if resp.Error == ErrExpired.Error() {
			return resp, ErrExpired
		}
		return resp, errors.New(resp.Error)
	}
	return resp, nil
}

// Identity fetches the cached identity.
func (c *Client) Identity() ([]byte, error) {
	resp, err := c.call(OpIdentity)
	if err != nil {
		return nil, err
	}
	if len(resp.Identity) == 0 {
		return nil, errors.New("the agent returned no identity")
	}
	return resp.Identity, nil
}

// Status reports the remaining lifetime and which store is held.
func (c *Client) Status() (time.Duration, string, error) {
	resp, err := c.call(OpStatus)
	if err != nil {
		return 0, "", err
	}
	return time.Duration(resp.ExpiresIn) * time.Second, resp.Fingerprint, nil
}

// Stop asks the agent to terminate.
func (c *Client) Stop() error {
	_, err := c.call(OpStop)
	if err != nil && !errors.Is(err, ErrNoAgent) {
		return err
	}
	return nil
}

// Package prompt reads secrets from the user or from an explicitly-passed file
// descriptor.
//
// Nothing here writes a secret to any log path, and terminal input is never
// echoed (project security policy; spec 001 R6.5).
package prompt

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// ErrNoInput reports that no passphrase source was available.
var ErrNoInput = errors.New("no passphrase source available")

// Passphrase reads a passphrase. When fd is non-negative it is read from that
// already-open file descriptor, which is how the end-to-end suite supplies one
// without putting it in an environment variable or on a command line, both of
// which are readable by any process running as the same user.
func Passphrase(fd int, promptText string) ([]byte, error) {
	if fd >= 0 {
		return readFD(fd)
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil, fmt.Errorf("%w: stdin is not a terminal and no --passphrase-fd was given", ErrNoInput)
	}
	fmt.Fprint(os.Stderr, promptText)
	secret, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, fmt.Errorf("read passphrase: %w", err)
	}
	return secret, nil
}

// Confirm reads a passphrase twice and requires the two to agree.
func Confirm(fd int, first, second string) ([]byte, error) {
	a, err := Passphrase(fd, first)
	if err != nil {
		return nil, err
	}
	if fd >= 0 {
		// A file descriptor carries one value; asking for it twice is
		// meaningless and would block.
		return a, nil
	}
	b, err := Passphrase(fd, second)
	if err != nil {
		Zero(a)
		return nil, err
	}
	defer Zero(b)
	if string(a) != string(b) {
		Zero(a)
		return nil, errors.New("passphrases do not match")
	}
	return a, nil
}

func readFD(fd int) ([]byte, error) {
	f := os.NewFile(uintptr(fd), fmt.Sprintf("passphrase-fd-%d", fd))
	if f == nil {
		return nil, fmt.Errorf("%w: file descriptor %d is not open", ErrNoInput, fd)
	}
	defer func() { _ = f.Close() }()
	line, err := bufio.NewReader(f).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("read passphrase from fd %d: %w", fd, err)
	}
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return nil, fmt.Errorf("%w: file descriptor %d yielded an empty passphrase", ErrNoInput, fd)
	}
	return []byte(line), nil
}

// Zero overwrites a secret buffer. Go's garbage collector may have relocated
// the backing array before this runs, so this reduces exposure rather than
// eliminating it; it is best-effort and is documented as such (spec 001 R-2).
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

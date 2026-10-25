// Package execx wraps command execution behind an interface so the rest of
// the code can be tested without root, nftables or a real WireGuard device.
package execx

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

func newCommand(ctx context.Context, name string, args ...string) *exec.Cmd {
	return exec.CommandContext(ctx, name, args...)
}

// Runner runs external commands.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
	RunInput(ctx context.Context, input []byte, name string, args ...string) ([]byte, error)
}

// Real executes commands on the host.
type Real struct {
	// Timeout is the maximum time a command may run. Zero means 10s.
	Timeout time.Duration
}

func (r Real) timeout() time.Duration {
	if r.Timeout > 0 {
		return r.Timeout
	}
	return 10 * time.Second
}

func (r Real) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return r.run(ctx, nil, name, args...)
}

func (r Real) RunInput(ctx context.Context, input []byte, name string, args ...string) ([]byte, error) {
	return r.run(ctx, input, name, args...)
}

func (r Real) run(ctx context.Context, input []byte, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout())
	defer cancel()

	cmd := newCommand(ctx, name, args...)
	if input != nil {
		cmd.Stdin = bytes.NewReader(input)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return stdout.Bytes(), fmt.Errorf("%s: timeout after %s", name, r.timeout())
		}
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return stdout.Bytes(), fmt.Errorf("%s: %s", name, msg)
	}
	return stdout.Bytes(), nil
}

// Call is a recorded invocation for the fake runner.
type Call struct {
	Name  string
	Args  []string
	Input []byte
}

// Fake is an in-memory Runner for tests.
type Fake struct {
	Calls   []Call
	Outputs map[string][]byte
	Errors  map[string]error
}

func key(name string, args []string) string {
	return strings.TrimSpace(name + " " + strings.Join(args, " "))
}

func (f *Fake) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.Calls = append(f.Calls, Call{Name: name, Args: append([]string(nil), args...)})
	k := key(name, args)
	if err, ok := f.Errors[k]; ok {
		return f.Outputs[k], err
	}
	return f.Outputs[k], nil
}

func (f *Fake) RunInput(_ context.Context, input []byte, name string, args ...string) ([]byte, error) {
	f.Calls = append(f.Calls, Call{Name: name, Args: append([]string(nil), args...), Input: append([]byte(nil), input...)})
	k := key(name, args)
	if err, ok := f.Errors[k]; ok {
		return f.Outputs[k], err
	}
	return f.Outputs[k], nil
}

// Called reports whether a command was invoked.
func (f *Fake) Called(name string, args ...string) bool {
	k := key(name, args)
	for _, c := range f.Calls {
		if key(c.Name, c.Args) == k {
			return true
		}
	}
	return false
}

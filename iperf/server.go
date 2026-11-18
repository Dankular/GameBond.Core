package iperf

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"strconv"
	"time"
)

// ServerOptions configures a conventional iperf3 listener. Bind must be an
// explicitly selected private or loopback address; public listeners are rejected.
type ServerOptions struct {
	Executable string
	Bind       netip.Addr
	Port       int
}

// StartServer starts an iperf3-compatible server and returns a process handle
// that should be closed when its owning client, exit or gateway stops.
func StartServer(ctx context.Context, options ServerOptions) (*Server, error) {
	if options.Executable == "" {
		options.Executable = "iperf3"
	}
	if !options.Bind.IsValid() || (!options.Bind.IsPrivate() && !options.Bind.IsLoopback()) {
		return nil, errors.New("iperf server bind must be an explicit private or loopback IP")
	}
	if options.Port == 0 {
		options.Port = 5201
	}
	if options.Port < 1 || options.Port > 65535 {
		return nil, errors.New("iperf port must be 1..65535")
	}
	cmd := exec.CommandContext(ctx, options.Executable, "-s", "-B", options.Bind.String(), "-p", strconv.Itoa(options.Port))
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start iperf server: %w", err)
	}
	s := &Server{cmd: cmd, done: make(chan error, 1)}
	go func() { s.done <- cmd.Wait(); close(s.done) }()
	return s, nil
}

type Server struct {
	cmd  *exec.Cmd
	done chan error
}

// Wait returns when the process exits. Call Close to stop it.
func (s *Server) Wait() error { return <-s.done }

// Close stops the listener and waits briefly for the child process to exit.
func (s *Server) Close() error {
	if s == nil || s.cmd == nil || s.cmd.Process == nil {
		return nil
	}
	_ = s.cmd.Process.Kill()
	select {
	case err, ok := <-s.done:
		if ok && err != nil {
			return err
		}
		return nil
	case <-time.After(3 * time.Second):
		return errors.New("iperf server did not stop")
	}
}

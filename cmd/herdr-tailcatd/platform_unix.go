//go:build !windows

package main

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

func defaultSocketPath() string {
	return filepath.Join(os.Getenv("HOME"), ".config", "herdr", "herdr.sock")
}

// localSocketExists reports whether path is a unix socket.
func localSocketExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.Mode()&os.ModeSocket != 0
}

func dialLocal(path string) (net.Conn, error) {
	return net.Dial("unix", path)
}

// detach starts the daemon in its own session, like nohup + &.
func detach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}

func processAlive(pid int) bool {
	return syscall.Kill(pid, 0) == nil
}

// terminateProcess asks the daemon to shut down; it closes the tunnel and
// removes its pidfile on SIGTERM.
func terminateProcess(pid int) error {
	return syscall.Kill(pid, syscall.SIGTERM)
}

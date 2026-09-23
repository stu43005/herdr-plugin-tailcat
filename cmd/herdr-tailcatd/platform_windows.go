package main

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"time"

	winio "github.com/tailscale/go-winio"
	"golang.org/x/sys/windows"
)

// herdr for Windows stores its config under %APPDATA%\herdr.
func defaultSocketPath() string {
	return filepath.Join(os.Getenv("APPDATA"), "herdr", "herdr.sock")
}

// On Windows herdr serves each "socket" as a named pipe named after the
// full socket path; the file at that path only holds a pid:timestamp
// marker.
func pipeName(socketPath string) string {
	return `\\.\pipe\` + socketPath
}

func localSocketExists(path string) bool {
	_, err := os.Stat(pipeName(path))
	return err == nil
}

func dialLocal(path string) (net.Conn, error) {
	c, err := winio.DialPipe(pipeName(path), nil)
	if err != nil {
		return nil, err
	}
	return &halfClosePipe{Conn: c}, nil
}

// pipeDrainIdle is how long a half-closed pipe keeps relaying herdr's
// output after it goes quiet.
const pipeDrainIdle = 5 * time.Second

// halfClosePipe emulates a write shutdown on a byte-mode named pipe,
// which has none: without CloseWrite, tailcat.ProxyConns closes the whole
// pipe as soon as the tunnel client finishes sending (e.g.
// `printf ... | tailcat <token> 6464`), dropping herdr's reply. Instead,
// keep reading until herdr has been idle for pipeDrainIdle.
type halfClosePipe struct {
	net.Conn
	writeClosed atomic.Bool
}

func (c *halfClosePipe) CloseWrite() error {
	c.writeClosed.Store(true)
	return c.SetReadDeadline(time.Now().Add(pipeDrainIdle))
}

func (c *halfClosePipe) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 && c.writeClosed.Load() {
		c.SetReadDeadline(time.Now().Add(pipeDrainIdle))
	}
	return n, err
}

// detach starts the daemon without a console, outside the caller's
// console process group, so it outlives the startup hook.
func detach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP,
		HideWindow:    true,
	}
}

// stillActive is STILL_ACTIVE, the exit code GetExitCodeProcess reports
// for a running process.
const stillActive = 259

func processAlive(pid int) bool {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	var code uint32
	return windows.GetExitCodeProcess(h, &code) == nil && code == stillActive
}

// terminateProcess kills the daemon outright: Windows has no SIGTERM to
// deliver to a detached process. The tunnel dies with it.
func terminateProcess(pid int) error {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	defer proc.Release()
	return proc.Kill()
}

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// start launches `serve` as a detached background process unless one is
// already running. It runs once per server start via the plugin's
// [[startup]] hook, and is safe to re-run (herdr re-runs startup hooks
// after a live handoff).
func start(p paths) error {
	if pid, ok := runningPID(p); ok {
		fmt.Printf("herdr-tailcatd already running (pid %d)\n", pid)
		return nil
	}
	if err := os.MkdirAll(p.state, 0700); err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	logPath := filepath.Join(p.state, "daemon.log")
	logFile, err := os.OpenFile(logPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	defer logFile.Close()

	cmd := exec.Command(exe, "serve")
	// Pin the resolved paths so the daemon agrees with this process even
	// when they came from fallbacks rather than the environment.
	cmd.Env = append(os.Environ(),
		"HERDR_SOCKET_PATH="+p.socket,
		"HERDR_PLUGIN_STATE_DIR="+p.state,
		"HERDR_PLUGIN_CONFIG_DIR="+p.config,
	)
	// The log file, not herdr's hook output pipes, is the daemon's stdio:
	// herdr waits for the hook's output to close before recording it.
	cmd.Stdout, cmd.Stderr = logFile, logFile
	// Don't hold the plugin checkout as the working directory (on Windows
	// that would block deleting it).
	cmd.Dir = p.state
	detach(cmd)
	if err := cmd.Start(); err != nil {
		return err
	}
	pid := cmd.Process.Pid
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()

	// Wait briefly for the daemon to come up (it writes its pidfile after
	// the tunnel starts), so the startup log line shows something useful.
	deadline := time.After(10 * time.Second)
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case err := <-exited:
			return fmt.Errorf("daemon exited during startup (%v); see %s", err, logPath)
		case <-deadline:
			fmt.Printf("herdr-tailcatd started (pid %d); token not ready yet, see %s\n", pid, logPath)
			return nil
		case <-tick.C:
			if readPID(p.pidFile) != pid {
				continue
			}
			tok, _ := os.ReadFile(filepath.Join(p.state, "token"))
			fmt.Printf("herdr socket exposed via tailcat, token: %s\n", strings.TrimSpace(string(tok)))
			fmt.Println("run 'herdr plugin action invoke herdr.tailcat.token' for client instructions")
			return nil
		}
	}
}

// stop terminates the background daemon, if any, and waits for it to exit
// so a following start cannot race it.
func stop(p paths) error {
	pid, ok := runningPID(p)
	if !ok {
		os.Remove(p.pidFile) // stale
		fmt.Println("herdr-tailcatd is not running")
		return nil
	}
	if err := terminateProcess(pid); err != nil {
		return fmt.Errorf("stop pid %d: %w", pid, err)
	}
	for i := 0; i < 50 && processAlive(pid); i++ {
		time.Sleep(100 * time.Millisecond)
	}
	if processAlive(pid) {
		return fmt.Errorf("pid %d did not exit", pid)
	}
	os.Remove(p.pidFile)
	fmt.Println("herdr-tailcatd stopped; the token no longer accepts connections")
	return nil
}

// token prints the current connection token and how a client uses it.
func token(p paths) error {
	if _, ok := runningPID(p); !ok {
		fmt.Println("herdr-tailcatd is not running.")
		fmt.Println("start it with: herdr plugin action invoke herdr.tailcat.restart")
		return errors.New("not running")
	}
	short, err := os.ReadFile(filepath.Join(p.state, "token"))
	if err != nil {
		return err
	}
	full, err := os.ReadFile(filepath.Join(p.state, "token.full"))
	if err != nil {
		return err
	}
	tok := strings.TrimSpace(string(short))

	fmt.Println("herdr socket is exposed over tailcat (WireGuard, end-to-end encrypted).")
	fmt.Println()
	fmt.Printf("token:        %s\n", tok)
	fmt.Printf("full token:   %s\n", strings.TrimSpace(string(full)))
	fmt.Println("  (the full token embeds the DERP relay info so clients skip the")
	fmt.Println("   DERP map fetch; either form works)")
	fmt.Println()
	fmt.Println("── client side ───────────────────────────────────────────────")
	fmt.Println("one-off session (stdio = herdr socket):")
	fmt.Printf("    tailcat %s 6464\n", tok)
	fmt.Println()
	fmt.Println("persistent local bridge for herdr clients (e.g. herdrm):")
	fmt.Println("    socat UNIX-LISTEN:/tmp/herdr-remote.sock,fork \\")
	fmt.Printf("        EXEC:'tailcat %s 6464'\n", tok)
	fmt.Println("then point the client at /tmp/herdr-remote.sock.")
	fmt.Println()
	allowPath := filepath.Join(p.config, "allow.list")
	if data, err := os.ReadFile(allowPath); err == nil {
		n := 0
		for line := range strings.Lines(string(data)) {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				n++
			}
		}
		fmt.Printf("client allow-list: active (%d key(s))\n", n)
	} else {
		fmt.Println("client allow-list: OFF — anyone holding the token can connect.")
		fmt.Printf("  create %s with client nodekey:... lines\n", allowPath)
		fmt.Println("  to restrict access, then restart.")
	}
	return nil
}

// runningPID returns the pid recorded in the pidfile if that process is
// still alive.
func runningPID(p paths) (int, bool) {
	pid := readPID(p.pidFile)
	return pid, pid > 0 && processAlive(pid)
}

func readPID(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(data)))
	return pid
}

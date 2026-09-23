// Command herdr-tailcatd exposes the local herdr API socket through a
// tailcat tunnel: WireGuard-encrypted, NAT-traversing, with no control
// plane. The herdr.tailcat plugin runs it directly from its manifest, on
// every platform:
//
//	herdr-tailcatd [serve]   run the tunnel in the foreground
//	herdr-tailcatd start     launch `serve` as a detached background process
//	                         unless one is already running (startup hook)
//	herdr-tailcatd stop      stop the background process
//	herdr-tailcatd restart   stop, then start
//	herdr-tailcatd token     print the token and client instructions
//
// Environment (all injected by herdr when run as a plugin):
//
//	HERDR_SOCKET_PATH        herdr API socket (a unix socket, or on Windows
//	                         the marker file of a named pipe)
//	HERDR_PLUGIN_ROOT        plugin checkout; default: parent of bin/
//	HERDR_PLUGIN_STATE_DIR   key, token, pidfile, and log live here
//	HERDR_PLUGIN_CONFIG_DIR  optional allow.list of client node keys,
//	                         optional pinned server.private.json
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/tailscale/tailcat"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/wgengine/filter"
)

// servePort is the TCP port inside the tunnel on which the herdr API socket
// is served. clientPort serves the herdr client-protocol socket, which
// terminal attach (`herdr agent attach`) connects to. The packet filter is
// tightened to just these two ports, so the tunnel cannot reach anything else
// on this machine.
const servePort = 6464
const clientPort = 6465

func main() {
	log.SetPrefix("[herdr-tailcatd] ")
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)

	cmd := "serve"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	p := loadPaths()
	var err error
	switch cmd {
	case "serve":
		serve(p)
	case "start":
		err = start(p)
	case "stop":
		err = stop(p)
	case "restart":
		if err = stop(p); err == nil {
			err = start(p)
		}
	case "token":
		err = token(p)
	default:
		fmt.Fprintf(os.Stderr, "usage: herdr-tailcatd [serve|start|stop|restart|token]\n")
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "herdr-tailcatd %s: %v\n", cmd, err)
		os.Exit(1)
	}
}

// paths are the locations shared by the daemon and its control commands.
type paths struct {
	socket  string // herdr API socket
	state   string // key, token, pidfile, log
	config  string // optional allow.list, pinned key
	pidFile string
}

// loadPaths resolves paths from the herdr-injected environment, falling
// back to the plugin checkout so manual runs work from a plain shell too.
func loadPaths() paths {
	root := os.Getenv("HERDR_PLUGIN_ROOT")
	if root == "" {
		// The binary lives in <root>/bin.
		if exe, err := os.Executable(); err == nil {
			root = filepath.Dir(filepath.Dir(exe))
		}
	}
	p := paths{
		socket: os.Getenv("HERDR_SOCKET_PATH"),
		state:  os.Getenv("HERDR_PLUGIN_STATE_DIR"),
		config: os.Getenv("HERDR_PLUGIN_CONFIG_DIR"),
	}
	if p.socket == "" {
		p.socket = defaultSocketPath()
	}
	if p.state == "" {
		p.state = filepath.Join(root, ".state")
	}
	if p.config == "" {
		p.config = filepath.Join(root, ".config")
	}
	p.pidFile = filepath.Join(p.state, "daemon.pid")
	return p
}

// serve runs the tunnel in the foreground until interrupted or terminated.
func serve(p paths) {
	socketPath, stateDir, configDir := p.socket, p.state, p.config
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		log.Fatalf("state dir: %v", err)
	}

	if !localSocketExists(socketPath) {
		log.Fatalf("herdr socket %s not found; is the herdr server running?", socketPath)
	}

	// Terminal attach speaks herdr's client protocol on a second socket derived
	// from the API socket path (herdr.sock -> herdr-client.sock). Serve it too;
	// without it attach has nothing to connect to.
	clientSocketPath := deriveClientSocket(socketPath)
	if !localSocketExists(clientSocketPath) {
		log.Printf("warning: client socket %s not found; terminal attach will fail (control RPC still works)", clientSocketPath)
	}

	// The identity key is looked up in the config dir first: a key the
	// user placed there (e.g. `tailcat genkey` output, or a copy of the
	// auto-generated one) wins and is never overwritten. Otherwise the
	// key auto-generated on first run lives in the state dir. Either
	// way the key — and therefore the token — survives restarts.
	keyPath := filepath.Join(configDir, "server.private.json")
	if _, err := os.Stat(keyPath); err != nil {
		keyPath = filepath.Join(stateDir, "server.private.json")
	}
	priv, pub, err := loadOrCreateKey(keyPath)
	if err != nil {
		log.Fatalf("server key: %v", err)
	}
	if pub.ServerPublic.NodePublic.IsZero() || pub.ServerPublic.NodePublic != priv.Public() {
		log.Fatalf("server key file %s is corrupt (public key mismatch); delete it to regenerate", keyPath)
	}
	region := pub.Region[0]
	log.Printf("key %s: bootstrap relay region %d (%s)", keyPath, region.RegionID, region.RegionName)

	s := &tailcat.Server{
		Key:    priv,
		Logf:   log.Printf,
		Region: region,
		// The pre-shared key is part of the saved identity (and of the
		// token); a legacy key without one keeps the psk layer off.
		PresharedKey:        pub.PresharedKey,
		DisablePresharedKey: pub.PresharedKey.IsZero(),
		ServedTCPPorts: []filter.PortRange{
			{First: servePort, Last: servePort},
			{First: clientPort, Last: clientPort},
		},
		OnTCP: func(port uint16) func(net.Conn) {
			var target string
			switch port {
			case servePort:
				target = socketPath
			case clientPort:
				target = clientSocketPath
			default:
				return nil
			}
			return func(c net.Conn) {
				defer c.Close()
				local, err := dialLocal(target)
				if err != nil {
					log.Printf("dial %s: %v", target, err)
					return
				}
				log.Printf("client connected on port %d, proxying to %s", port, target)
				tailcat.ProxyConns(c, local)
			}
		},
	}
	applyAllowList(s, filepath.Join(configDir, "allow.list"))

	if err := s.Start(); err != nil {
		log.Fatalf("start tailcat server: %v", err)
	}

	// The token is the whole saved public identity (node key, disco key,
	// preshared key) plus the DERP region, so it is a pure function of
	// the key file and stable across restarts.
	shortCI := tailcat.ConnInfo{
		ServerPublic:      pub.ServerPublic,
		ServerDiscoPublic: pub.ServerDiscoPublic,
		PresharedKey:      pub.PresharedKey,
		RegionID:          region.RegionID,
	}
	fullCI := tailcat.ConnInfo{
		ServerPublic:      pub.ServerPublic,
		ServerDiscoPublic: pub.ServerDiscoPublic,
		PresharedKey:      pub.PresharedKey,
		Region:            []*tailcfg.DERPRegion{region},
	}
	writeFile(filepath.Join(stateDir, "token"), string(shortCI.Addr()))
	writeFile(filepath.Join(stateDir, "token.full"), string(fullCI.Addr()))
	pidPath := p.pidFile
	writeFile(pidPath, strconv.Itoa(os.Getpid()))

	log.Printf("serving herdr socket %s on tunnel port %d", socketPath, servePort)
	log.Printf("serving herdr client socket %s on tunnel port %d", clientSocketPath, clientPort)
	log.Printf("connection token: %s", shortCI.Addr())

	sig := make(chan os.Signal, 1)
	// On Windows `stop` terminates the process outright, so this only
	// covers Ctrl+C there; `stop` removes the pidfile itself.
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	s.Close()
	os.Remove(pidPath)
}

// deriveClientSocket mirrors herdr's derive_client_socket_from_api_socket:
// insert "-client" before the ".sock" extension (herdr.sock -> herdr-client.sock).
func deriveClientSocket(apiSocket string) string {
	dir := filepath.Dir(apiSocket)
	base := filepath.Base(apiSocket)
	stem := strings.TrimSuffix(base, filepath.Ext(base))
	return filepath.Join(dir, stem+"-client.sock")
}

// loadOrCreateKey returns the saved server key, generating one on first
// run. The nearest DERP region is discovered once and baked into the
// saved key, so the connection token stays stable across restarts
// (mirrors `tailcat genkey --fixed-region`). Keys saved by older
// tailcat versions are upgraded in place: the disco key (derived
// deterministically from the node key) is backfilled, and a missing
// region is resolved and re-saved.
func loadOrCreateKey(path string) (key.NodePrivate, tailcat.ConnInfo, error) {
	if j, err := os.ReadFile(path); err == nil {
		var k tailcat.PrivateKey
		if err := json.Unmarshal(j, &k); err != nil {
			return key.NodePrivate{}, tailcat.ConnInfo{}, fmt.Errorf("parse %s: %w", path, err)
		}
		dirty := false
		if k.Public.ServerDiscoPublic.IsZero() {
			k.Public.ServerDiscoPublic = tailcat.DiscoPublicForNode(k.Private)
			dirty = true
		}
		if len(k.Public.Region) == 0 {
			// A key without a baked region (e.g. plain `tailcat genkey`
			// output): resolve its region now and re-save, so the token
			// is stable from here on.
			if k.Public.RegionID == 0 {
				k.Public.RegionID = -1 // auto-detect nearest
			}
			if err := k.Public.Expand(context.Background(), tailcat.ExpandForServer); err != nil {
				return key.NodePrivate{}, tailcat.ConnInfo{}, fmt.Errorf("pick DERP region: %w", err)
			}
			dirty = true
		}
		if dirty {
			if j, err := json.MarshalIndent(k, "", "  "); err == nil {
				os.WriteFile(path, j, 0600)
			}
		}
		return k.Private, k.Public, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return key.NodePrivate{}, tailcat.ConnInfo{}, err
	}

	k := tailcat.NewPrivateKey()
	k.Public.RegionID = -1 // -1 = auto-detect nearest region
	// Expand populates Public.Region (and zeroes RegionID) while
	// keeping the ServerPublic/ServerDiscoPublic/PresharedKey that
	// NewPrivateKey set.
	if err := k.Public.Expand(context.Background(), tailcat.ExpandForServer); err != nil {
		return key.NodePrivate{}, tailcat.ConnInfo{}, fmt.Errorf("pick DERP region: %w", err)
	}
	j, err := json.MarshalIndent(k, "", "  ")
	if err != nil {
		return key.NodePrivate{}, tailcat.ConnInfo{}, err
	}
	if err := os.WriteFile(path, j, 0600); err != nil {
		return key.NodePrivate{}, tailcat.ConnInfo{}, err
	}
	return k.Private, k.Public, nil
}

// applyAllowList restricts which client node keys may connect if
// allow.list exists (one "nodekey:..." per line, '#' comments allowed).
// Without the file, possession of the connection token is the only
// credential — still WireGuard-authenticated and encrypted end to end.
func applyAllowList(s *tailcat.Server, path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Printf("no allow.list — anyone holding the token can connect")
		return
	}
	for line := range strings.Lines(string(data)) {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var k key.NodePublic
		if err := k.UnmarshalText([]byte(line)); err != nil {
			log.Printf("ignoring invalid key %q in %s: %v", line, path, err)
			continue
		}
		s.AllowedClients = append(s.AllowedClients, k)
	}
	log.Printf("allow.list: %d client key(s) may connect", len(s.AllowedClients))
	if len(s.AllowedClients) == 0 {
		log.Printf("WARNING: allow.list is empty — no client will be able to connect")
	}
}

func writeFile(path, contents string) {
	if err := os.WriteFile(path, []byte(contents+"\n"), 0600); err != nil {
		log.Printf("write %s: %v", path, err)
	}
}

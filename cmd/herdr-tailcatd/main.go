// Command herdr-tailcatd exposes the local herdr API socket through a
// tailcat tunnel: WireGuard-encrypted, NAT-traversing, with no control
// plane. It is launched by the herdr.tailcat plugin (see
// scripts/start.sh) and runs as a detached background process.
//
// Environment (all injected by herdr when run as a plugin):
//
//	HERDR_SOCKET_PATH        unix socket of the running herdr server
//	HERDR_PLUGIN_STATE_DIR   key, token, pidfile, and log live here
//	HERDR_PLUGIN_CONFIG_DIR  optional allow.list of client node keys
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

// servePort is the TCP port inside the tunnel on which the herdr socket
// is served. The packet filter is tightened to just this port, so the
// tunnel cannot reach anything else on this machine.
const servePort = 6464

func main() {
	log.SetPrefix("[herdr-tailcatd] ")
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)

	socketPath := os.Getenv("HERDR_SOCKET_PATH")
	if socketPath == "" {
		socketPath = filepath.Join(os.Getenv("HOME"), ".config", "herdr", "herdr.sock")
	}
	stateDir := os.Getenv("HERDR_PLUGIN_STATE_DIR")
	if stateDir == "" {
		stateDir = ".state" // manual runs from the plugin root
	}
	configDir := os.Getenv("HERDR_PLUGIN_CONFIG_DIR")
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		log.Fatalf("state dir: %v", err)
	}

	if st, err := os.Stat(socketPath); err != nil || st.Mode()&os.ModeSocket == 0 {
		log.Fatalf("herdr socket %s not found; is the herdr server running?", socketPath)
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
		ServedTCPPorts: []filter.PortRange{
			{First: servePort, Last: servePort},
		},
		OnTCP: func(port uint16) func(net.Conn) {
			if port != servePort {
				return nil
			}
			return func(c net.Conn) {
				defer c.Close()
				local, err := net.Dial("unix", socketPath)
				if err != nil {
					log.Printf("dial %s: %v", socketPath, err)
					return
				}
				log.Printf("client connected, proxying to %s", socketPath)
				tailcat.ProxyConns(c, local)
			}
		},
	}
	applyAllowList(s, filepath.Join(configDir, "allow.list"))

	if err := s.Start(); err != nil {
		log.Fatalf("start tailcat server: %v", err)
	}

	shortCI := tailcat.ConnInfo{ServerPublic: pub.ServerPublic, RegionID: region.RegionID}
	fullCI := tailcat.ConnInfo{ServerPublic: pub.ServerPublic, Region: []*tailcfg.DERPRegion{region}}
	short, full := shortCI.ConnBlob(), fullCI.ConnBlob()
	writeFile(filepath.Join(stateDir, "token"), string(short))
	writeFile(filepath.Join(stateDir, "token.full"), string(full))
	pidPath := filepath.Join(stateDir, "daemon.pid")
	writeFile(pidPath, strconv.Itoa(os.Getpid()))

	log.Printf("serving herdr socket %s on tunnel port %d", socketPath, servePort)
	log.Printf("connection token: %s", short)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	s.Close()
	os.Remove(pidPath)
}

// loadOrCreateKey returns the saved server key, generating one on first
// run. The nearest DERP region is discovered once and baked into the
// saved key, so the connection token stays stable across restarts
// (mirrors `tailcat genkey --fixed-region`).
func loadOrCreateKey(path string) (key.NodePrivate, tailcat.ConnInfo, error) {
	if j, err := os.ReadFile(path); err == nil {
		var k tailcat.PrivateKey
		if err := json.Unmarshal(j, &k); err != nil {
			return key.NodePrivate{}, tailcat.ConnInfo{}, fmt.Errorf("parse %s: %w", path, err)
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
	// keeping the ServerPublic that NewPrivateKey set.
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

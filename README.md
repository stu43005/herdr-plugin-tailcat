# herdr.tailcat — expose your local herdr socket over a tailcat tunnel

A [herdr](https://herdr.dev) plugin that exposes the local herdr API socket
(`~/.config/herdr/herdr.sock`; on Windows the named pipe behind
`%APPDATA%\herdr\herdr.sock`) through a [tailcat](https://github.com/tailscale/tailcat)
tunnel — WireGuard end-to-end encryption, DERP-relay NAT traversal, no control
plane, no root, and **no listening ports on your machine**. Runs on Linux,
macOS, and Windows.

Use case: drive this machine's herdr from another device — with
[herdrm](https://github.com/missuo/herdrm), `herdr api`, or your own scripts —
without SSH port forwarding.

## How it works

```
┌─ remote client ─┐  WireGuard/DERP  ┌─ herdr-tailcatd (this plugin) ─┐
│ tailcat CLI     │ ═══════════════▶ │ tailcat.Server                 │
│ or socat bridge │ ◂═══════════════ │   OnTCP :6464 ──dial──▶ herdr.sock │
└─────────────────┘  encrypted, NAT  └────────────────────────────────┘
                     traversal
```

- The `herdr-tailcatd` daemon (Go, built on the tailcat library) serves
  virtual port **6464** inside the tunnel and byte-forwards every connection
  to the local herdr API socket (the herdr protocol is newline-delimited
  JSON-RPC, so plain byte proxying is all it takes). Port **6465** forwards
  to herdr's client-protocol socket (`herdr-client.sock`) for terminal
  attach.
- On Windows herdr serves each "socket" as a named pipe called
  `\\.\pipe\<full socket path>` (the `.sock` file only holds a `pid:timestamp`
  marker); the daemon dials that pipe instead of a unix socket. Named pipes
  have no half-close, so when a tunnel client finishes sending, the daemon
  keeps relaying herdr's output until the pipe has been idle for 5 seconds.
- tailcat's packet filter is tightened to ports 6464 and 6465 only — the
  tunnel cannot reach anything else on the machine.
- The token carries a WireGuard pre-shared key (post-quantum confidentiality,
  and a DERP relay operator can't join the tunnel even if it observes the
  handshake).

## Install

```sh
# local development
herdr plugin link /path/to/herdr_tc
go build -o bin/ ./cmd/herdr-tailcatd   # `link` does not run build commands
                                        # (or: sh scripts/build.sh)

# or from GitHub once published
herdr plugin install <owner>/<repo>
```

Installing needs Go on `PATH` (the `[[build]]` step compiles the daemon).

Once enabled, herdr runs the `[[startup]]` hook on every server start (and
after a live handoff), which launches the daemon; it is idempotent when an
instance is already running.

Every manifest command runs the daemon binary directly
(`bin/herdr-tailcatd <start|stop|restart|token>`), so no shell is needed and
the same manifest works on all three platforms. The binary must be built
before the hook or any action runs.

## Usage

```sh
herdr plugin action invoke herdr.tailcat.token     # show token + client instructions
herdr plugin action invoke herdr.tailcat.restart   # restart the exposure
herdr plugin action invoke herdr.tailcat.stop      # stop; the token dies immediately
herdr plugin log list --plugin herdr.tailcat       # hook execution logs
```

### Client side

One-off session (stdin/stdout is the herdr socket byte stream):

```sh
printf '{"id":"1","method":"plugin.list","params":{}}\n' | tailcat <token> 6464
```

Persistent local bridge for clients that expect a unix socket (e.g. herdrm):

```sh
socat UNIX-LISTEN:/tmp/herdr-remote.sock,fork EXEC:'tailcat <token> 6464'
# then point the client at /tmp/herdr-remote.sock
```

Clients need tailcat v0.6.0 or newer (the address format gained a disco key
and pre-shared key in v0.6.0).

## Key & token stability

The token is derived from the server identity: same key, same token. The
daemon guarantees this:

- The key is generated exactly once, stored as `server.private.json` (mode
  0600) in the plugin state dir, and loaded on every subsequent start —
  herdr restarts, live handoffs, and daemon crashes all keep the token.
- The DERP region is probed once at first run and baked into the key file;
  restarts never re-probe (re-probing could change the region, which would
  change the token).
- **To pin the identity permanently** (surviving even a plugin reinstall or
  a wiped state dir): copy `server.private.json` into the plugin config dir
  (`herdr plugin config-dir herdr.tailcat`). A key in the config dir takes
  precedence over the state dir and is never overwritten. A key file from
  `tailcat genkey` works too (a missing region is resolved and written back).
  So does one made with `tailcat genkey --region=<derp-host>` for your own
  DERP relay; since such a relay has no ID in the public DERP map, both
  `token` and `token.full` then embed the relay info.
- To rotate: delete the key file(s) in both dirs and restart — a fresh
  identity and token are generated.
- The short token references a region ID in tailcat's public DERP map; if an
  upstream map change ever breaks it, use `token.full` (embeds the relay
  info, immune to map changes) or regenerate the key.

## Security (read this)

herdr's plugin model has **no sandbox**, and the socket this plugin exposes
grants **full control** of the herdr server (send keystrokes to any pane,
start agents, call every API). Treat this like putting a shell on the
network:

- **The token is a credential.** Anyone holding it can connect. Token files
  are stored mode 0600 in the plugin state dir; never paste them in public.
- **Use the client allow-list.** Create `allow.list` in the plugin config
  dir (`herdr plugin config-dir herdr.tailcat`) with one client `nodekey:...`
  per line (clients generate one with `tailcat genkey --client`), then
  restart. Non-matching clients are silently dropped at the WireGuard
  handshake — they can't even learn the service exists.
- `stop` the exposure when you don't need it; after
  `herdr plugin unlink herdr.tailcat`, make sure the daemon is stopped.
  On Windows `stop` terminates the process outright, since there is no
  SIGTERM to deliver to a detached process.
- Transport is always WireGuard end-to-end encrypted with a pre-shared key;
  DERP relays only ever see ciphertext.

## Files

```
herdr-plugin.toml                    manifest (build, startup hook, token/stop/restart actions)
cmd/herdr-tailcatd/main.go           tunnel daemon (`serve`) and subcommand dispatch
cmd/herdr-tailcatd/control.go        start (detached, idempotent) / stop / token
cmd/herdr-tailcatd/platform_*.go     unix socket vs. Windows named pipe, process control
scripts/build.sh                     go build → bin/herdr-tailcatd[.exe]
```

## Development

```sh
go build -o bin/ ./cmd/herdr-tailcatd                # build
./bin/herdr-tailcatd                                 # run in foreground for debugging
./bin/herdr-tailcatd start|stop|restart|token        # what the manifest runs
```

Without herdr's environment the daemon defaults to `.state/` and `.config/`
in the plugin checkout, and to herdr's default socket
(`~/.config/herdr/herdr.sock`, or `%APPDATA%\herdr\herdr.sock` on Windows);
set `HERDR_SOCKET_PATH`, `HERDR_PLUGIN_STATE_DIR`, or
`HERDR_PLUGIN_CONFIG_DIR` to override.

Requires Go ≥ 1.27.1 (inherited from tailcat v0.6.0); older Go toolchains
with toolchain auto-download enabled work too.

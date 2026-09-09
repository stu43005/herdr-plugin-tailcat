#!/bin/sh
# Print the current connection token and how a client uses it.
set -eu

. "$(dirname -- "$0")/env.sh"

if [ ! -f "$PIDFILE" ] || ! kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
	echo "herdr-tailcatd is not running."
	echo "start it with: herdr plugin action invoke herdr.tailcat.restart"
	exit 1
fi

TOKEN=$(cat "$STATE/token")
FULL=$(cat "$STATE/token.full")

echo "herdr socket is exposed over tailcat (WireGuard, end-to-end encrypted)."
echo
echo "token:        $TOKEN"
echo "full token:   $FULL"
echo "  (the full token embeds the DERP relay info so clients skip the"
echo "   DERP map fetch; either form works)"
echo
echo "── client side ───────────────────────────────────────────────"
echo "one-off session (stdio = herdr socket):"
echo "    tailcat $TOKEN 6464"
echo
echo "persistent local bridge for herdr clients (e.g. herdrm):"
echo "    socat UNIX-LISTEN:/tmp/herdr-remote.sock,fork \\"
echo "        EXEC:'tailcat $TOKEN 6464'"
echo "then point the client at /tmp/herdr-remote.sock."
echo
if [ -f "$CONFIG/allow.list" ]; then
	echo "client allow-list: active ($(grep -cv '^\s*\(#\|$\)' "$CONFIG/allow.list" || echo 0) key(s))"
else
	echo "client allow-list: OFF — anyone holding the token can connect."
	echo "  create $CONFIG/allow.list with client nodekey:... lines"
	echo "  to restrict access, then restart."
fi

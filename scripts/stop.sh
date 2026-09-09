#!/bin/sh
# Stop the tailcat exposure daemon.
set -eu

. "$(dirname -- "$0")/env.sh"

if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
	kill "$(cat "$PIDFILE")"
	rm -f "$PIDFILE"
	echo "herdr-tailcatd stopped; the token no longer accepts connections"
else
	echo "herdr-tailcatd is not running"
fi

#!/bin/sh
# Start the tailcat exposure daemon unless it is already running.
# Runs once per server start via the plugin's [[startup]] hook, and is
# safe to re-run (herdr re-runs startup hooks after a live handoff).
set -eu

. "$(dirname -- "$0")/env.sh"

if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
	echo "herdr-tailcatd already running (pid $(cat "$PIDFILE"))"
	exit 0
fi

if [ ! -x "$BIN" ]; then
	sh "$ROOT/scripts/build.sh"
fi

mkdir -p "$STATE"
nohup "$BIN" >>"$STATE/daemon.log" 2>&1 &

# Wait briefly for the daemon to write its token, so the startup log
# line shows something useful.
i=0
while [ ! -f "$STATE/token" ] && [ $i -lt 100 ]; do
	i=$((i + 1))
	sleep 0.1 2>/dev/null || sleep 1
done

if [ -f "$STATE/token" ]; then
	echo "herdr socket exposed via tailcat, token: $(cat "$STATE/token")"
	echo "run 'herdr plugin action invoke herdr.tailcat.token' for client instructions"
else
	echo "herdr-tailcatd started; token not ready yet, see $STATE/daemon.log"
fi

#!/bin/sh
# Restart the tailcat exposure daemon.
set -eu

DIR=$(dirname -- "$0")
sh "$DIR/stop.sh" || true
sh "$DIR/start.sh"

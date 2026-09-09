#!/bin/sh
# Common paths shared by the plugin scripts. Sourced, not executed.
# herdr injects HERDR_PLUGIN_ROOT / HERDR_PLUGIN_STATE_DIR /
# HERDR_PLUGIN_CONFIG_DIR / HERDR_SOCKET_PATH; the fallbacks make the
# scripts usable from a plain shell too.

ROOT="${HERDR_PLUGIN_ROOT:-$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)}"
STATE="${HERDR_PLUGIN_STATE_DIR:-$ROOT/.state}"
CONFIG="${HERDR_PLUGIN_CONFIG_DIR:-$ROOT/.config}"
SOCKET="${HERDR_SOCKET_PATH:-$HOME/.config/herdr/herdr.sock}"

BIN="$ROOT/bin/herdr-tailcatd"
PIDFILE="$STATE/daemon.pid"

export HERDR_SOCKET_PATH="$SOCKET"
export HERDR_PLUGIN_STATE_DIR="$STATE"
export HERDR_PLUGIN_CONFIG_DIR="$CONFIG"

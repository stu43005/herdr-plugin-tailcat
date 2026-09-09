#!/bin/sh
# Build the herdr-tailcatd daemon into bin/. Runs at plugin install time
# (and lazily from start.sh if the binary is missing).
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

mkdir -p bin
go build -o bin/herdr-tailcatd ./cmd/herdr-tailcatd
echo "built $ROOT/bin/herdr-tailcatd"

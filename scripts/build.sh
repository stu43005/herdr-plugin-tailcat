#!/bin/sh
# Build the herdr-tailcatd daemon into bin/ (bin/herdr-tailcatd.exe on
# Windows). Same as the manifest's [[build]] step; handy after
# `herdr plugin link`, which does not run build commands.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

go build -o bin/ ./cmd/herdr-tailcatd
echo "built $ROOT/bin/herdr-tailcatd"

#!/bin/sh
set -eu
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
exec python3 "$SCRIPT_DIR/check-repository-secrets.py" --root "$ROOT_DIR"

#!/bin/sh
set -eu

root="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
cd "$root"

help_output="$(make --no-print-directory help)"

for target in setup doctor up up-fcm health logs db-shell db-backup db-restore db-reset run migrate-json check; do
  printf '%s\n' "$help_output" | grep -Eq "^[[:space:]]+$target[[:space:]]" || {
    printf 'Make target is missing from help output: %s\n' "$target" >&2
    exit 1
  }
done

make --no-print-directory -n setup >/dev/null
make --no-print-directory -n up >/dev/null
make --no-print-directory -n up-fcm >/dev/null
make --no-print-directory -n fcm-setup FCM_CREDENTIALS=/tmp/firebase-service-account.json >/dev/null
make --no-print-directory -n db-restore BACKUP=/tmp/database.dump CONFIRM=restore >/dev/null
make --no-print-directory -n db-reset CONFIRM=reset >/dev/null
make --no-print-directory -n migrate-json LEGACY_DATA_DIR=/tmp/legacy-data >/dev/null

printf '%s\n' 'Makefile command interface: OK'

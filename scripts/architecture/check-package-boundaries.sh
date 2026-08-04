#!/bin/sh
set -eu

root="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
cd "$root"

failed=0
fail() {
  printf 'architecture error: %s\n' "$1" >&2
  failed=1
}

for package in domain config push security storage; do
  path="internal/$package"
  [ -d "$path" ] || continue
  if grep -R --include='*.go' -n 'github.com/0xDive/ferventio-backend/internal/application' "$path" >/dev/null 2>&1; then
    fail "$path imports internal/application; adapters and domain must not depend on orchestration"
  fi
done

if grep -R --include='*.go' -n 'internal/storage/memory' cmd/ferventio-backend >/dev/null 2>&1; then
  fail "production composition root imports the in-memory test adapter"
fi

if ! grep -R --include='*.go' -n 'storage/postgres' cmd/ferventio-backend >/dev/null 2>&1; then
  fail "production composition root does not wire PostgreSQL storage"
fi

if find internal/application -type f -name '*.sql' -print | grep -q .; then
  fail "SQL migrations belong in internal/storage/postgres/migrations"
fi

if ! grep -F 'FIREBASE_ENABLED: "false"' compose.yaml >/dev/null 2>&1; then
  fail "base compose stack must explicitly disable Firebase"
fi

if ! grep -F 'FIREBASE_ENABLED: "true"' compose.fcm.yaml >/dev/null 2>&1; then
  fail "FCM compose overlay must explicitly enable Firebase"
fi

if ! grep -F 'target: firebase-service-account.json' compose.fcm.yaml >/dev/null 2>&1; then
  fail "FCM secret target must match GOOGLE_APPLICATION_CREDENTIALS"
fi

if ! grep -F 'GOOGLE_APPLICATION_CREDENTIALS: /run/secrets/firebase-service-account.json' compose.fcm.yaml >/dev/null 2>&1; then
  fail "FCM credential path must match the mounted secret target"
fi

if [ "$failed" -ne 0 ]; then
  exit 1
fi

printf '%s\n' 'Backend package boundaries OK'

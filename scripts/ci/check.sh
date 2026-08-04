#!/bin/sh
set -eu

./scripts/security/scan-repository-secrets.sh
./scripts/ci/check-makefile.sh
./scripts/architecture/check-package-boundaries.sh
go mod verify

unformatted="$(gofmt -l $(find . -type f -name '*.go' -not -path './vendor/*'))"
if [ -n "$unformatted" ]; then
  printf '%s\n' 'Go files require gofmt:' "$unformatted" >&2
  exit 1
fi
go vet ./...
go test ./...
CGO_ENABLED=0 go build -trimpath ./cmd/ferventio-backend

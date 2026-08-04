SHELL := /bin/sh
.DEFAULT_GOAL := help
.DELETE_ON_ERROR:
.NOTPARALLEL: up up-fcm start start-fcm restart restart-fcm rebuild rebuild-fcm db-reset run check ci
MAKEFLAGS += --no-print-directory

APP_NAME := ferventio-backend
VERSION := $(shell cat VERSION 2>/dev/null || printf 'dev')
BINARY ?= build/$(APP_NAME)
ENV_FILE ?= .env
BACKEND_PORT ?= 8080
BACKEND_URL ?= http://127.0.0.1:$(BACKEND_PORT)
COMPOSE ?= docker compose
COMPOSE_BASE = $(COMPOSE) --env-file "$(ENV_FILE)" -f compose.yaml
COMPOSE_FCM = $(COMPOSE_BASE) -f compose.fcm.yaml
WAIT_ATTEMPTS ?= 30
WAIT_INTERVAL ?= 2
TAIL ?= 200
FCM_CREDENTIALS ?=
LEGACY_DATA_DIR ?=
BACKUP ?=

.PHONY: help setup init doctor env-check fcm-check \
	config config-fcm up up-fcm compose-up compose-up-fcm compose-down start start-fcm stop down restart restart-fcm \
	rebuild rebuild-fcm status ps logs logs-once logs-backend logs-db health wait \
	shell db-up db-wait db-shell db-backup db-restore db-reset fcm-setup \
	run migrate-json vapid \
	fmt format fmt-check format-check architecture secrets mod-check test test-race \
	coverage integration vet build check ci clean

##@ Getting started
help: ## Show the command reference and first-run workflow.
	@printf '%s\n' \
	  'Ferventio Backend $(VERSION)' \
	  '' \
	  'First run:' \
	  '  1. make setup' \
	  '  2. edit .env' \
	  '  3. make up' \
	  '  4. make health' \
	  '  5. make logs' \
	  '' \
	  'With Firebase Cloud Messaging:' \
	  '  make fcm-setup FCM_CREDENTIALS=/absolute/path/service-account.json' \
	  '  set FIREBASE_PROJECT_ID in .env' \
	  '  make up-fcm' \
	  '' \
	  'Commands:'
	@awk 'BEGIN { FS = ":.*## " } \
	  /^##@/ { section = substr($$0, 5); printf "\n%s\n", section; next } \
	  /^[a-zA-Z0-9_.-]+:.*## / { printf "  %-19s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)
	@printf '%s\n' \
	  '' \
	  'Useful overrides:' \
	  '  ENV_FILE=.env.local BACKEND_PORT=9080 TAIL=500 make up' \
	  '  TEST_DATABASE_URL=postgres://... make integration'

setup: ## Create .env and local secret directories without overwriting existing files.
	@if [ -e "$(ENV_FILE)" ]; then \
	  printf 'Keeping existing %s\n' "$(ENV_FILE)"; \
	else \
	  cp config/examples/backend.env "$(ENV_FILE)"; \
	  printf 'Created %s from config/examples/backend.env\n' "$(ENV_FILE)"; \
	fi
	@mkdir -p .secrets build backups
	@printf '%s\n' \
	  'Next:' \
	  '  1. Replace placeholder values in $(ENV_FILE).' \
	  '  2. Run: make up' \
	  '  3. Verify: make health'

init: setup ## Alias for setup.

doctor: ## Check local Go, Docker Compose, curl, and configuration prerequisites.
	@status=0; \
	for tool in docker curl; do \
	  if command -v "$$tool" >/dev/null 2>&1; then \
	    printf 'ok   %s: %s\n' "$$tool" "$$(command -v "$$tool")"; \
	  else \
	    printf 'miss %s\n' "$$tool" >&2; status=1; \
	  fi; \
	done; \
	if command -v go >/dev/null 2>&1; then \
	  local_go="$$(GOTOOLCHAIN=local go version 2>/dev/null || true)"; \
	  required_go="$$(sed -n 's/^toolchain[[:space:]]*//p' go.mod)"; \
	  printf 'ok   go: %s\n' "$${local_go:-installed}"; \
	  [ -z "$$required_go" ] || printf 'note repository toolchain: %s\n' "$$required_go"; \
	else \
	  printf '%s\n' 'note Go is not installed; Docker workflow can still be used.'; \
	fi; \
	if command -v docker >/dev/null 2>&1; then \
	  $(COMPOSE) version >/dev/null 2>&1 || { printf '%s\n' 'miss Docker Compose v2' >&2; status=1; }; \
	fi; \
	if [ -f "$(ENV_FILE)" ]; then \
	  printf 'ok   env: %s\n' "$(ENV_FILE)"; \
	else \
	  printf 'miss %s (run: make setup)\n' "$(ENV_FILE)" >&2; status=1; \
	fi; \
	exit $$status

env-check:
	@test -f "$(ENV_FILE)" || { \
	  printf 'Missing %s. Run: make setup\n' "$(ENV_FILE)" >&2; \
	  exit 1; \
	}
	@set -a; . "./$(ENV_FILE)"; set +a; \
	case "$${POSTGRES_PASSWORD:-}" in \
	  ''|replace-with-*) \
	    printf 'Set a real POSTGRES_PASSWORD in %s before starting.\n' "$(ENV_FILE)" >&2; \
	    exit 1 ;; \
	esac

fcm-check: env-check
	@set -a; . "./$(ENV_FILE)"; set +a; \
	if [ -z "$${FIREBASE_PROJECT_ID:-}" ]; then \
	  printf 'Set FIREBASE_PROJECT_ID in %s before make up-fcm.\n' "$(ENV_FILE)" >&2; \
	  exit 1; \
	fi; \
	secret="$${FIREBASE_SERVICE_ACCOUNT_FILE:-.secrets/firebase-service-account.json}"; \
	if [ ! -s "$$secret" ]; then \
	  printf 'Firebase credential file is missing or empty: %s\n' "$$secret" >&2; \
	  printf 'Run: make fcm-setup FCM_CREDENTIALS=/absolute/path/service-account.json\n' >&2; \
	  exit 1; \
	fi

##@ Docker application
config: env-check ## Validate the base Docker Compose configuration without printing secrets.
	@$(COMPOSE_BASE) config --quiet
	@printf '%s\n' 'Base Compose configuration is valid (FCM disabled).'

config-fcm: fcm-check ## Validate the base plus Firebase Compose configuration.
	@$(COMPOSE_FCM) config --quiet
	@printf '%s\n' 'Firebase Compose configuration is valid.'

up: config ## Build and start PostgreSQL and backend without Firebase, then wait for readiness.
	@$(COMPOSE_BASE) up --build -d
	@$(MAKE) wait
	@$(COMPOSE_BASE) ps

up-fcm: config-fcm ## Build and start PostgreSQL and backend with Firebase enabled.
	@$(COMPOSE_FCM) up --build -d
	@$(MAKE) wait
	@$(COMPOSE_FCM) ps

# Backward-compatible operator aliases retained for existing local workflows.
compose-up: up
compose-up-fcm: up-fcm
compose-down: down

start: env-check ## Start existing base-stack containers without rebuilding.
	@$(COMPOSE_BASE) start
	@$(MAKE) wait

start-fcm: fcm-check ## Start existing Firebase-stack containers without rebuilding.
	@$(COMPOSE_FCM) start
	@$(MAKE) wait

stop: env-check ## Stop containers without removing them.
	@$(COMPOSE_BASE) stop

restart: env-check ## Restart the base stack without rebuilding images.
	@$(COMPOSE_BASE) restart
	@$(MAKE) wait

restart-fcm: fcm-check ## Restart the Firebase stack without rebuilding images.
	@$(COMPOSE_FCM) restart
	@$(MAKE) wait

down: env-check ## Stop and remove containers and networks; keep PostgreSQL data.
	@$(COMPOSE_BASE) down --remove-orphans

rebuild: config ## Rebuild and recreate the base stack from scratch; keep PostgreSQL data.
	@$(COMPOSE_BASE) build --pull backend
	@$(COMPOSE_BASE) up -d --force-recreate
	@$(MAKE) wait

rebuild-fcm: config-fcm ## Rebuild and recreate the Firebase stack; keep PostgreSQL data.
	@$(COMPOSE_FCM) build --pull backend
	@$(COMPOSE_FCM) up -d --force-recreate
	@$(MAKE) wait

status: env-check ## Show container state and health.
	@$(COMPOSE_BASE) ps

ps: status ## Alias for status.

logs: env-check ## Follow backend and PostgreSQL logs (TAIL controls initial lines).
	@$(COMPOSE_BASE) logs --tail="$(TAIL)" -f backend postgres

logs-once: env-check ## Print recent backend and PostgreSQL logs without following.
	@$(COMPOSE_BASE) logs --tail="$(TAIL)" backend postgres

logs-backend: env-check ## Follow only backend logs.
	@$(COMPOSE_BASE) logs --tail="$(TAIL)" -f backend

logs-db: env-check ## Follow only PostgreSQL logs.
	@$(COMPOSE_BASE) logs --tail="$(TAIL)" -f postgres

health: ## Check liveness and database-backed readiness endpoints.
	@printf 'healthz: '; curl --fail --silent --show-error "$(BACKEND_URL)/healthz"; printf '\n'
	@printf 'readyz:  '; curl --fail --silent --show-error "$(BACKEND_URL)/readyz"; printf '\n'

wait: ## Wait until /readyz succeeds; show backend logs when the timeout expires.
	@attempt=1; \
	while [ $$attempt -le "$(WAIT_ATTEMPTS)" ]; do \
	  if curl --fail --silent --output /dev/null "$(BACKEND_URL)/readyz"; then \
	    printf 'Backend is ready: %s/readyz\n' "$(BACKEND_URL)"; \
	    exit 0; \
	  fi; \
	  printf 'Waiting for backend readiness (%s/%s)...\n' "$$attempt" "$(WAIT_ATTEMPTS)"; \
	  attempt=$$((attempt + 1)); \
	  sleep "$(WAIT_INTERVAL)"; \
	done; \
	printf 'Backend did not become ready. Recent logs:\n' >&2; \
	$(COMPOSE_BASE) logs --tail=100 backend >&2 || true; \
	exit 1

shell: env-check ## Open a shell inside the running backend container.
	@$(COMPOSE_BASE) exec backend /bin/sh

##@ PostgreSQL
db-up: env-check ## Start only PostgreSQL and wait until it accepts connections.
	@$(COMPOSE_BASE) up -d postgres
	@$(MAKE) db-wait

db-wait: env-check ## Wait until PostgreSQL reports ready.
	@attempt=1; \
	while [ $$attempt -le "$(WAIT_ATTEMPTS)" ]; do \
	  if $(COMPOSE_BASE) exec -T postgres sh -ec 'pg_isready -U "$$POSTGRES_USER" -d "$$POSTGRES_DB"' >/dev/null 2>&1; then \
	    printf '%s\n' 'PostgreSQL is ready.'; \
	    exit 0; \
	  fi; \
	  printf 'Waiting for PostgreSQL (%s/%s)...\n' "$$attempt" "$(WAIT_ATTEMPTS)"; \
	  attempt=$$((attempt + 1)); \
	  sleep "$(WAIT_INTERVAL)"; \
	done; \
	printf '%s\n' 'PostgreSQL did not become ready.' >&2; \
	exit 1

db-shell: env-check ## Open psql in the running PostgreSQL container.
	@$(COMPOSE_BASE) exec postgres sh -ec 'exec psql -U "$$POSTGRES_USER" -d "$$POSTGRES_DB"'

db-backup: env-check ## Create a timestamped custom-format database dump under backups/.
	@mkdir -p backups
	@file="backups/ferventio-$$(date -u +%Y%m%d-%H%M%S).dump"; \
	tmp="$$file.tmp"; \
	trap 'rm -f "$$tmp"' 0 1 2 15; \
	$(COMPOSE_BASE) exec -T postgres sh -ec 'pg_dump -U "$$POSTGRES_USER" -d "$$POSTGRES_DB" --format=custom' > "$$tmp"; \
	test -s "$$tmp"; \
	mv "$$tmp" "$$file"; \
	trap - 0 1 2 15; \
	printf 'Database backup created: %s\n' "$$file"

db-restore: env-check ## Restore a custom-format dump (requires BACKUP=file and CONFIRM=restore).
	@test -n "$(BACKUP)" || { \
	  printf '%s\n' 'Usage: make db-restore BACKUP=backups/file.dump CONFIRM=restore' >&2; \
	  exit 1; \
	}
	@test -s "$(BACKUP)" || { \
	  printf 'Backup file is missing or empty: %s\n' "$(BACKUP)" >&2; \
	  exit 1; \
	}
	@if [ "$(CONFIRM)" != 'restore' ]; then \
	  printf '%s\n' 'Restore replaces current database objects. Re-run with CONFIRM=restore.' >&2; \
	  exit 1; \
	fi
	@$(COMPOSE_BASE) stop backend >/dev/null 2>&1 || true
	@$(COMPOSE_BASE) exec -T postgres sh -ec 'pg_restore -U "$$POSTGRES_USER" -d "$$POSTGRES_DB" --clean --if-exists --no-owner --no-privileges' < "$(BACKUP)"
	@$(COMPOSE_BASE) start backend
	@$(MAKE) wait

db-reset: env-check ## DELETE the PostgreSQL volume and start a fresh database (requires CONFIRM=reset).
	@if [ "$(CONFIRM)" != 'reset' ]; then \
	  printf '%s\n' 'Refusing to delete data. Re-run with: make db-reset CONFIRM=reset' >&2; \
	  exit 1; \
	fi
	@$(COMPOSE_BASE) down --volumes --remove-orphans
	@$(MAKE) db-up

##@ Firebase
fcm-setup: ## Copy a service-account JSON into .secrets (requires FCM_CREDENTIALS=/path/file.json).
	@test -n "$(FCM_CREDENTIALS)" || { \
	  printf '%s\n' 'Usage: make fcm-setup FCM_CREDENTIALS=/absolute/path/service-account.json' >&2; \
	  exit 1; \
	}
	@test -s "$(FCM_CREDENTIALS)" || { \
	  printf 'Credential file is missing or empty: %s\n' "$(FCM_CREDENTIALS)" >&2; \
	  exit 1; \
	}
	@target='.secrets/firebase-service-account.json'; \
	if [ -f "$(ENV_FILE)" ]; then \
	  set -a; . "./$(ENV_FILE)"; set +a; \
	  target="$${FIREBASE_SERVICE_ACCOUNT_FILE:-$$target}"; \
	fi; \
	mkdir -p "$$(dirname "$$target")"; \
	cp "$(FCM_CREDENTIALS)" "$$target"; \
	chmod 600 "$$target"; \
	printf 'Firebase credentials installed at %s.\n' "$$target"; \
	printf 'Set FIREBASE_PROJECT_ID in %s, then run: make up-fcm\n' "$(ENV_FILE)"

##@ Native development
run: env-check db-up ## Run the Go service on the host against Compose PostgreSQL.
	@set -a; . "./$(ENV_FILE)"; set +a; exec go run ./cmd/ferventio-backend

migrate-json: env-check ## Import legacy JSON state (requires LEGACY_DATA_DIR=/absolute/path/data).
	@test -n "$(LEGACY_DATA_DIR)" || { \
	  printf '%s\n' 'Usage: make migrate-json LEGACY_DATA_DIR=/absolute/path/old/server/data' >&2; \
	  exit 1; \
	}
	@test -d "$(LEGACY_DATA_DIR)" || { \
	  printf 'Legacy data directory does not exist: %s\n' "$(LEGACY_DATA_DIR)" >&2; \
	  exit 1; \
	}
	@set -a; . "./$(ENV_FILE)"; set +a; exec go run ./cmd/ferventio-migrate-json --directory "$(LEGACY_DATA_DIR)"

vapid: ## Generate legacy Web Push VAPID keys.
	@go run ./cmd/vapid

##@ Quality
fmt: ## Format all Go sources.
	@gofmt -w $$(find . -type f -name '*.go' -not -path './vendor/*')

format: fmt ## Alias for fmt.

fmt-check: ## Fail when Go sources are not formatted.
	@unformatted="$$(gofmt -l $$(find . -type f -name '*.go' -not -path './vendor/*'))"; \
	if [ -n "$$unformatted" ]; then \
	  printf '%s\n%s\n' 'Go files require gofmt:' "$$unformatted" >&2; \
	  exit 1; \
	fi

format-check: fmt-check ## Alias for fmt-check.

architecture: ## Validate package and production-wiring boundaries.
	@./scripts/architecture/check-package-boundaries.sh

secrets: ## Scan tracked project content for committed credentials.
	@./scripts/security/scan-repository-secrets.sh

mod-check: ## Verify downloaded modules and require a tidy go.mod/go.sum.
	@go mod verify
	@go mod tidy -diff

test: ## Run unit tests.
	@go test ./...

test-race: ## Run unit tests with the race detector.
	@go test -race ./...

coverage: ## Write build/coverage.out and print package coverage totals.
	@mkdir -p build
	@go test -coverprofile=build/coverage.out ./...
	@go tool cover -func=build/coverage.out

integration: ## Run PostgreSQL integration tests (requires TEST_DATABASE_URL).
	@test -n "$(TEST_DATABASE_URL)" || { \
	  printf '%s\n' 'Set TEST_DATABASE_URL before running integration tests.' >&2; \
	  exit 1; \
	}
	@TEST_DATABASE_URL="$(TEST_DATABASE_URL)" go test -tags=integration ./internal/storage/postgres

vet: ## Run go vet for all packages.
	@go vet ./...

build: ## Build the production binary at build/ferventio-backend.
	@mkdir -p "$$(dirname "$(BINARY)")"
	@CGO_ENABLED=0 go build -trimpath -o "$(BINARY)" ./cmd/ferventio-backend
	@printf 'Built %s\n' "$(BINARY)"

check: ## Run the complete local quality gate.
	@$(MAKE) secrets
	@$(MAKE) architecture
	@$(MAKE) fmt-check
	@$(MAKE) mod-check
	@$(MAKE) vet
	@$(MAKE) test
	@$(MAKE) build

ci: ## Run the same repository checks used by continuous integration.
	@./scripts/ci/check.sh

clean: ## Remove local Go build and coverage output; keep containers and database data.
	@rm -rf build coverage.out

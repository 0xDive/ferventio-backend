# Ferventio Backend

Ferventio Backend is the Go service used by the Ferventio Android client for Twitch OAuth, EventSub processing, push delivery and settings sync.

> **Beta:** `0.0.1` is intended for controlled testing. Back up PostgreSQL and expect configuration or API changes before `1.0.0`.

The Android client lives in [`0xDive/ferventio-android`](https://github.com/0xDive/ferventio-android).

## What it provides

- Twitch Authorization Code flow and refresh-token rotation
- EventSub webhook verification, deduplication and reconciliation
- FOSS push through an authenticated WebSocket transport
- Optional Play push through Firebase Cloud Messaging
- Device registration, delivery state and settings synchronization
- PostgreSQL persistence with embedded migrations
- Structured JSON logs and liveness/readiness endpoints

## Quick start

Requirements: Docker Engine with Compose v2 and GNU Make.

```bash
git clone https://github.com/0xDive/ferventio-backend.git
cd ferventio-backend

make setup
# Replace every placeholder in .env.
make up
make health
make logs
```

The base stack starts PostgreSQL and the backend with Firebase disabled. OAuth, EventSub, settings sync and FOSS WebSocket push remain available.

Run `make help` for the complete command reference.

## Firebase Cloud Messaging

FCM is opt-in:

```bash
make fcm-setup FCM_CREDENTIALS=/absolute/path/firebase-service-account.json
# Set FIREBASE_PROJECT_ID in .env.
make up-fcm
make health
```

The service-account file is mounted as a Docker secret. Never copy it into the image or repository.

## Configuration

Start from [`config/examples/backend.env`](config/examples/backend.env). Production deployments need, at minimum:

- PostgreSQL credentials
- a public HTTPS base URL
- Twitch client credentials
- an EventSub secret
- an OAuth encryption key
- an administrative token

Keep `.env`, `.secrets/`, database dumps, encryption keys and tokens out of Git.

## Operations

```bash
make doctor
make status
make logs-backend
make db-backup
```

`make down`, restart and rebuild operations preserve PostgreSQL data. Only this explicit command removes the database volume:

```bash
make db-reset CONFIRM=reset
```

Deployment, backup, restore and rollback notes are in [`docs/operations.md`](docs/operations.md).

## Development

The required Go toolchain is declared in `go.mod`.

```bash
make setup
make db-up
make run
```

Run the local quality gate before opening a pull request:

```bash
make check
```

PostgreSQL integration tests are opt-in:

```bash
TEST_DATABASE_URL='postgres://ferventio:ferventio@localhost:5432/ferventio_test?sslmode=disable' \
  make integration
```

## API and architecture

- `GET /healthz` reports process liveness.
- `GET /readyz` reports process and PostgreSQL readiness.
- HTTP endpoints are versioned under `/v1`.

The service semantic version and the `/v1` API path are independent. See [`docs/architecture.md`](docs/architecture.md) for package boundaries and persistence rules.

## Beta limitations

- Run one backend replica until shared coordination is implemented and tested.
- FCM requires the explicit Compose overlay and valid Google credentials.
- Read the changelog before upgrading during `0.0.x`.

Use GitHub Issues for reproducible bugs and focused feature requests. Do not attach `.env` files, database dumps, tokens or user data.

Security reports must be submitted privately as described in [`SECURITY.md`](SECURITY.md).

## Contributing and license

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Ferventio Backend is available under the [MIT License](LICENSE).

Ferventio is an independent project and is not affiliated with Twitch Interactive, Inc. or Google LLC.

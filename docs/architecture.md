# Architecture

Ferventio Backend is a single Go service with explicit package boundaries and PostgreSQL as the only production persistence layer.

## Package direction

```text
cmd -> application -> domain
  \-> config
  \-> push --------> domain
  \-> storage/* ---> domain
  \-> security
```

- `cmd/ferventio-backend` is the production composition root.
- `internal/domain` defines models and ports.
- `internal/application` implements HTTP handlers, use cases and workers.
- `internal/storage/postgres` implements production persistence and migrations.
- `internal/storage/memory` contains deterministic test adapters only.
- `internal/push` implements delivery adapters.
- `internal/security` contains cryptographic helpers.

Adapters must not import `internal/application`. Production wiring must not use the memory adapter. The repository enforces these rules with `scripts/architecture/check-package-boundaries.sh`.

## PostgreSQL

SQL migrations live in `internal/storage/postgres/migrations` and are embedded into the binary. With `DATABASE_MIGRATE=true`, startup applies unapplied `.up.sql` files in lexical order while holding a PostgreSQL advisory lock. Applied filenames are recorded in `schema_migrations`.

Never modify a migration that may have been deployed. Add a new numbered migration.

PostgreSQL owns durable OAuth state, push registrations, EventSub inbox/deduplication, deliveries, audit records and settings snapshots.

## API contracts

The HTTP API is versioned under `/v1`. Service semantic versions do not renumber the API route automatically.

- `/healthz` is process liveness.
- `/readyz` includes PostgreSQL readiness.

Android and backend release independently. Breaking API changes require a new route or a coordinated client/server release.

## Scaling

Database uniqueness constraints protect durable deduplication and settings revisions, but some rate limiting and reconciliation coordination remains process-local. Use one replica during the first beta.

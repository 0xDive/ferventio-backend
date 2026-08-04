# Database migrations

Production SQL migrations are stored in
`internal/storage/postgres/migrations` and embedded into the backend binary.

Migrations are applied in lexical order when `DATABASE_MIGRATE=true`. Startup takes a
PostgreSQL advisory lock, records applied filenames in `schema_migrations`, and fails
closed if a migration cannot complete.

The top-level `migrations/` directory is documentation-only so operators can discover
the migration policy without coupling deployment tooling to an internal package path.

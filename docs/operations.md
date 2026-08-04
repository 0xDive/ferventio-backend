# Operations

The root `Makefile` is the supported interface for local and Docker operations. Run `make help` for the current command list.

## Deployment

```bash
make setup
# Edit .env and replace all placeholders.
make up
make health
make status
```

For FCM:

```bash
make fcm-setup FCM_CREDENTIALS=/secure/path/firebase-service-account.json
# Set FIREBASE_PROJECT_ID in .env.
make up-fcm
make health
```

The base stack forces Firebase off. A project ID alone must not make startup depend on Google credentials.

## Health and logs

- `GET /healthz` checks process liveness.
- `GET /readyz` checks process and PostgreSQL readiness.
- Logs are structured JSON written to stdout.

```bash
make status
make health
make logs-backend
make logs-db
```

Do not increase logging by printing credentials, token payloads or private user data.

## Backup and restore

```bash
make db-backup
make db-restore BACKUP=backups/file.dump CONFIRM=restore
```

Test restores in an isolated database. PostgreSQL backups do not contain `AUTH_ENCRYPTION_KEY`; preserve that key separately or encrypted OAuth credentials cannot be recovered.

Only the following command deletes the named PostgreSQL volume:

```bash
make db-reset CONFIRM=reset
```

## Upgrade and rollback

1. Back up PostgreSQL.
2. Read `CHANGELOG.md` for migration or configuration changes.
3. Start one backend instance with migrations enabled.
4. Verify `/readyz`, OAuth, EventSub and the enabled push transport.
5. Enable public traffic.

Application rollback should keep PostgreSQL and use a backend version compatible with the already-applied schema. Do not return to a legacy JSON writer after PostgreSQL has accepted newer writes.

## Secret rotation

Rotate PostgreSQL credentials, admin token, Twitch client secret, EventSub secret, Firebase key and VAPID keys independently.

Changing `AUTH_ENCRYPTION_KEY` without re-encrypting stored credentials invalidates existing OAuth ciphertext and must be treated as a planned migration.

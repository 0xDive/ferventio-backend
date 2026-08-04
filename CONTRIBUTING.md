# Contributing

The early beta prioritizes correctness, data safety and small reviewable changes.

## Before you start

- Search existing issues and pull requests.
- Open an issue before API, migration, cryptography, authentication or deployment changes.
- Keep Android work in [`0xDive/ferventio-android`](https://github.com/0xDive/ferventio-android).
- Never include credentials, database dumps, tokens or real user data.

## Workflow

```bash
git switch main
git pull --ff-only
git switch -c fix/short-description

make check
```

Persistence changes should also run PostgreSQL integration tests.

Never edit a migration that may have been deployed. Add a new numbered `.up.sql` and `.down.sql` pair and explain rollout and rollback behavior in the pull request.

## Pull requests

Explain:

- the problem and solution
- API and Android-client compatibility
- database and configuration impact
- validation performed
- deployment order and rollback

Use short, imperative commit subjects, for example:

```text
eventsub: persist retry state
```

The project follows the account-level [Code of Conduct](https://github.com/0xDive/.github/blob/main/CODE_OF_CONDUCT.md).

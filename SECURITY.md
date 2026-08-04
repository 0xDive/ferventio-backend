# Security

## Supported versions

Only the latest public beta receives security fixes. Modified or unsupported deployments are not covered.

## Reporting a vulnerability

Do not open a public issue. Use a [private GitHub security advisory](https://github.com/0xDive/ferventio-backend/security/advisories/new).

Include the affected version, deployment topology, impact and reproduction steps. Do not include real credentials, database dumps, tokens or user data.

If a secret may have been exposed, rotate or revoke it before cleaning Git history or issue content.

## Deployment baseline

- terminate public traffic with HTTPS
- keep PostgreSQL on a private network
- use unique random secrets
- back up PostgreSQL and test restores
- store `AUTH_ENCRYPTION_KEY` separately from database backups
- deploy one replica during the first beta

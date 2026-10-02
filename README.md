# الثلاثية الثقافية — الخزنة

Vault Web v0.41 — preliminary web platform for the cultural committee.

## Features
- Dynamic multi-room Vault game with SSE realtime updates.
- Email/password supervisor accounts.
- One-time Super Admin bootstrap protected by the legacy admin PIN.
- New supervisor accounts remain pending until approved by the Super Admin.
- Supervisors can create and operate only their own rooms; Super Admin can access all rooms.
- Persistent room snapshots, event logs and account sessions.
- Room history/archive with full event log, leaderboard and Excel export.
- Branded UI using the approved Althulathia visual palette.

## Persistence
- SQLite by default.
- Set `VAULT_DB_PATH=/data/vault_state.db` when using a persistent Railway volume.
- PostgreSQL is supported automatically when `DATABASE_URL` is set.

## Important environment variables
- `VAULT_ADMIN_PIN` — used only for the one-time Super Admin bootstrap after v0.40.
- `VAULT_DB_PATH` — SQLite database path.
- `DATABASE_URL` — optional PostgreSQL connection string.
- `VAULT_LOG_DIR` — optional JSONL backup directory.

## Health check
`/api/health`

## Email authentication
v0.41 adds optional transactional email flows for supervisor accounts:
- 6-digit email OTP, valid for 10 minutes.
- Supervisor approval email after Super Admin approval.
- Single-use password reset link, valid for 30 minutes.
- Support email shown in the admin authentication UI.

The feature is gated by `EMAIL_AUTH_ENABLED`. Keep it disabled until the outbound email domain is verified and a Resend API key is configured.

### Email environment variables
- `EMAIL_AUTH_ENABLED` — set to `1` only after mail setup is complete.
- `RESEND_API_KEY` — Resend API key; never commit it to Git.
- `EMAIL_TOKEN_SECRET` — high-entropy server secret used when hashing OTP values.
- `EMAIL_FROM` — recommended: `الثلاثية الثقافية <no-reply@playalthulathia.com>`.
- `SUPPORT_EMAIL` — `support@playalthulathia.com`.
- `APP_BASE_URL` — `https://playalthulathia.com`.

### Account state flow
`email_unverified -> pending -> approved`

Existing v0.40 accounts are preserved.

# الثلاثية الثقافية — الخزنة

Vault Web v0.40 — preliminary web platform for the cultural committee.

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
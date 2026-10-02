# الثلاثية الثقافية — الخزنة

Vault Web v0.32 — preliminary web deployment.

## Runtime
- Python 3.12
- SQLite by default
- PostgreSQL automatically when `DATABASE_URL` is set
- SSE realtime updates
- Health check: `/api/health`

## Important environment variables
- `VAULT_ADMIN_PIN` — supervisor PIN
- `DATABASE_URL` — production PostgreSQL connection string (recommended)
- `VAULT_DB_PATH` — SQLite path when PostgreSQL is not configured
- `VAULT_LOG_DIR` — optional local JSONL log directory

## Data
Questions and settings are stored in `Questions.json` so they can be edited and reviewed directly in GitHub.

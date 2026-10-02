# الثلاثية الثقافية — الخزنة

Vault Web v0.50 — منصة الويب لفقرة الخزنة في «الثلاثية الثقافية».

## Features
- Dynamic multi-room Vault game with SSE realtime updates.
- Email/password accounts with OTP verification and password recovery.
- Three admin roles: Super Admin, Assistant Admin (مسؤول مساعد), and Supervisor (مشرف).
- Normal rooms for all approved staff roles.
- Private Festival Rooms visible only to Super Admin and Assistant Admin.
- Fifteen private question-pack slots: rounds 1–12 plus 3 reserve rounds.
- Festival question packs are stored in the private application database, not in GitHub.
- Private rooms freeze the selected question-pack version at creation time so later pack replacements do not change existing rooms.
- Two private rooms created from the same pack use the same 12 questions in the same order.
- Adaptive supervisor layout: 1–4 teams use full team cards; 5+ teams use a team dropdown with one full selected-team card.
- Persistent room snapshots, event logs and account sessions.
- Room closure/archive with Super Admin reopening.
- Excel event-log export.

## Roles
### Super Admin — مسؤول رئيسي
- Manages accounts and can promote/demote approved accounts between Supervisor and Assistant Admin.
- Can create normal and private Festival Rooms.
- Can see all rooms.
- Can upload or replace Festival question packs.
- Can reopen administratively closed rooms.

### Assistant Admin — مسؤول مساعد
- Can create normal rooms.
- Can create private Festival Rooms.
- Can see and operate all private Festival Rooms.
- Can select an already-uploaded Festival question pack when creating a private room.
- Cannot upload or replace Festival question packs or manage account roles.

### Supervisor — مشرف
- Can create and operate normal rooms only.
- Private Festival Rooms and Festival question-pack controls are not returned to this role.

## Festival question packs
The application reserves these fixed private slots:
- الجولة 1 through الجولة 12
- احتياط 1 through احتياط 3

Each uploaded JSON file must contain exactly 12 questions. Accepted structure:

```json
{
  "questions": [
    {
      "number": 1,
      "question": "...",
      "correct_answer": "...",
      "difficulty": 1
    }
  ]
}
```

`difficulty` must be 1, 2, or 3. The uploaded order is the exact order used in private Festival Rooms; no per-room randomization is applied.

Question-pack contents are stored in the application database only. Do not commit Festival question files to this repository.

## Persistence
- SQLite by default.
- Production currently uses the persistent Railway volume through `VAULT_DB_PATH`.
- PostgreSQL remains supported automatically when `DATABASE_URL` is set.

## Important environment variables
- `VAULT_ADMIN_PIN` — one-time Super Admin bootstrap PIN.
- `VAULT_DB_PATH` — SQLite database path.
- `DATABASE_URL` — optional PostgreSQL connection string.
- `VAULT_LOG_DIR` — optional JSONL backup directory.
- `EMAIL_AUTH_ENABLED` — enables OTP/password-recovery flows.
- `EMAIL_TOKEN_SECRET` — server secret used when hashing OTP values.
- `EMAIL_FROM` — transactional sender identity.
- `SUPPORT_EMAIL` — support mailbox.
- `APP_BASE_URL` — public application base URL.
- `EMAIL_WORKER_URL` and `EMAIL_WORKER_SECRET` — Cloudflare Worker delivery bridge when used.

## Health check
`/api/health`

## Account state flow
`email_unverified -> pending -> approved`

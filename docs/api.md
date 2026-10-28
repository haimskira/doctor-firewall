# API for developers and other systems

Everything the system knows can be pulled over HTTPS as JSON. The UI page **Integrations → API for
developers** (`/api-docs`) has the overview, token management, an interactive explorer and the full
reference of finding and recommendation kinds.

## Authentication

| Client | How |
|---|---|
| A browser | the signed-in session (cookie); writes also need the `X-CSRF-Token` header |
| Another system | `Authorization: Bearer dfk_<prefix>_<secret>` — a token created on the API page |

Tokens (`app/auth/tokens.py`):

* **read-only** — GET / HEAD only; any other method answers `403 token_read_only`. Writes to the
  firewall stay in the UI, behind the four-eyes approval;
* **the owner's read permissions only** — `policy:read`, and `audit:read` when the owner has it;
* shown **once**; only the SHA-256 is stored; valid 1–365 days; revocable; `last_used_at` is kept;
* up to 20 live tokens per user; an administrator sees and can revoke everyone's;
* created and revoked in a signed-in session only (never with a token), both audited
  (`api_token.created`, `api_token.revoked`).

## The read API

`GET /api/openapi.json` (signed in or a token) is the OpenAPI 3 document of every GET endpoint —
the explorer is built from it. Lists take `limit` (≤ 500) and `offset` and answer `total`; many take
`sort` and `order`. Errors: HTTP status with `{"detail": "<code>"}`.

| What | Endpoints |
|---|---|
| Inventory | `/api/snapshots`, `/api/snapshots/{id}/policies`, `/api/snapshots/{id}/policies/{policy}/rules`, `/api/snapshots/{id}/objects[/{object}[/relations\|/tree]]` |
| Findings | `/api/snapshots/{id}/findings` (each with the recommendations that fix it) |
| Scores, dashboard | `/api/snapshots/{id}/scores`, `/api/snapshots/{id}/dashboard` |
| Recommendations | `/api/snapshots/{id}/recommendations` (`kind`, `phase`, `state`, `rule`, `policy`), `/api/snapshots/{id}/recommendations/{rec}` |
| Clean-up roadmap | `/api/snapshots/{id}/roadmap` |
| Connectivity map | `/api/snapshots/{id}/map` |
| Attack surface | `/api/snapshots/{id}/attack-surface`, `.../attack-surface/targets` |
| Clusters, routing | `/api/snapshots/{id}/clusters`, `/api/snapshots/{id}/clusters/{cluster}/network` |
| Changesets | `/api/changesets`, `/api/changesets/{id}` |
| History | `/api/history`, `/api/changesets/{id}/batches/{seq}/changes` |
| Jobs | `/api/jobs` |
| Audit log | `/api/audit` (`audit:read`) |

```bash
export DF_TOKEN=dfk_...
curl -s -H "Authorization: Bearer $DF_TOKEN" https://doctor-firewall.example/api/snapshots?limit=5
curl -s -H "Authorization: Bearer $DF_TOKEN" \
  "https://doctor-firewall.example/api/snapshots/42/findings?severity=high&limit=500"
```

In production FastAPI's own schema browser stays off; in development it is at `/api/docs`
(schema `/api/dev/openapi.json`).

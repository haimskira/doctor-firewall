# FMC integration log

Monitor → Events → *FMC log* (`/fmc-log`, permission `audit:read`). Every operation against the
FMC and every HTTP request it made, kept in the database for 30 days (`fmc_events`).

| Operation | Where it starts |
|---|---|
| `test` | "Test connection" on the FMC connection page |
| `collect` | a collection ("pull now" or scheduled) |
| `batch` | executing an approved batch (writes, verification, deploy, automatic rollback) |
| `revert` / `rollback` | reverting a deployed batch / finishing an interrupted rollback |
| `watch` | the post-deploy hit-count watch |

Each operation records `started`, one `request` row per HTTP attempt (method, path with query,
status, duration — retries included), `failed` with the error code and message when it fails,
and `finished` with the outcome, duration and request counts. The collector names its current
step (`objects: hosts`, `access policy ACP-1: accessrules`, `… hit counts`, `interfaces and
routes: <cluster>`), so a failure says exactly what was being read.

**Never recorded:** request headers (credentials, tokens), request bodies. The response body is
kept only for a failed request (or a 200 answer the client could not use — invalid JSON, a
malformed page), truncated to 2 KB and scrubbed like logs (sensitive JSON members such as
`"password"`, `"token"`, `"apiKey"` are masked).

The snapshots page shows a failed collection's detail and links to its log; a failed connection
test points to the log. `GET /api/fmc/events/export` downloads the filtered log as CSV — the
file to send onwards when asking for help. The log can never fail the operation it describes.

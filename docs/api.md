# REST API

Every endpoint requires a signed-in session cookie. API authentication failures return JSON 401; role/scope failures return 403. Login uses `/login` and a CSRF token. After login, GET `/api/csrf-token` provides a fresh token. POSTs require `X-CSRFToken` or form field `csrf_token`. There are no public/bearer API tokens.

| Method | Path | Input/output |
|---|---|---|
| GET | /api/csrf-token | `{csrf_token: string}` |
| GET | /api/networks | Paginated facts/current findings |
| GET | /api/networks/:id | Facts, stations, observation history |
| POST | /api/scans | `{mode: "demo" or "live", authorized: true, duration: 5..60, bssid?, interface?}` |
| GET | /api/scans | Paginated status, scope, counts, timestamps |
| POST | /api/assessments | `{network_id: integer, authorized: true}` |
| POST | /api/captures/analyze | Multipart `file`, `network_id`, `authorized=true` |
| GET | /api/findings | Current findings, optional severity filter |
| GET | /api/reports | IDs, assessment IDs, download URLs |
| POST | /api/reports/generate | `{network_id: integer, authorized: true}` |
| GET | /api/interfaces | `{items: [...]}`, current detection |
| GET | /api/audit-logs | Administrator only, paginated events |
| GET | /reports/:id/download | Authenticated PDF attachment |

Pagination: `{items: [], total, page, pages, per_page}`. Default size 12, allowed 1–100. Out-of-range pages return empty lists. Network filters: `q` (literal ESSID/BSSID substring), exact `encryption`, `severity`, `channel`, `date` (YYYY-MM-DD, last observed UTC), `source` (demo/live), `page`, `per_page`.

## Signed-in browser example

```javascript
const {csrf_token} = await fetch('/api/csrf-token').then(r => r.json());
// Submit only after explicitly confirming authorization for this operation.
const response = await fetch('/api/scans', {
  method: 'POST',
  headers: {'Content-Type': 'application/json', 'X-CSRFToken': csrf_token},
  body: JSON.stringify({mode: 'demo', duration: 10, authorized: true})
});
console.log(await response.json());
```

Creation returns 201. Scans are synchronous; responses arrive after completion of the bounded observation. Live channel comes from approved scope, not client input. User/configuration management uses administrator HTML forms with CSRF.

Errors use `{error: "safe message"}`: 400 validation/CSRF, 401 authentication, 403 scope/role, 404 missing record, 413 request size, 429 rate limit, 503 scanner/tool failure, 500 unexpected failure without traceback. Do not automatically retry mutations; inspect history first to avoid duplicate operations.

Login: 10 POSTs/minute/IP; scans: 6/minute; captures/reports: 10/minute; password changes: 5/minute; default: 300/minute. Memory rate counters are per process and reset on restart.

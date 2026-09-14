# D2Vita crash-report API

Cloudflare Worker (`d2vita-crash`) that receives crash reports from the D2Vita
PS Vita port, deduplicates them by signature, keeps **one** sealed sample per
signature, and serves a small admin API to the maintainer's local tool. It also
receives bug reports from the public site.

- TypeScript, no framework, no runtime dependency (WebCrypto only).
- D1 (`DB`): signatures, counters, claims, bugs, rate limits, settings.
- R2 (`ARTIFACTS`): sealed pieces, `artifacts/<signature>/<report_id>/<name>.sealed`.
- Daily cron `0 3 * * *`: retention.
- Pieces are sealed on the console for the maintainer's X25519 key: neither
  Cloudflare nor this Worker can read them.

## Layout

| Path | Role |
|---|---|
| `src/index.ts` | `fetch` and `scheduled` handlers |
| `src/router.ts` | routes, admin authorization, signing of console responses |
| `src/http.ts` | JSON bodies, errors, CORS, `Content-Length` guard, response signing |
| `src/validate.ts` | strict validation of every JSON payload |
| `src/signature.ts` | signature rules v1 (`canon`, `signatureId`) — the only place that maps a claim to a signature |
| `src/crypto.ts` | SHA-256, HMAC, base32/64, Ed25519 signing, constant-time compare |
| `src/token.ts` | upload token (HMAC) |
| `src/limits.ts` | daily counters, settings (kill switch, caps), IP pseudonyms |
| `src/claims.ts` | `POST /v1/claims`: dedup transaction and sample lease |
| `src/uploads.ts` | `PUT …/artifacts/{name}` (streamed to R2) and `POST …/complete` |
| `src/bugs.ts` | `POST /v1/bugs` (Turnstile, CORS) |
| `src/admin.ts` | admin routes |
| `src/notify.ts` | optional Telegram notifications |
| `src/cron.ts` | retention |
| `migrations/` | D1 schema |
| `test/` | Vitest suites running inside workerd |
| `scripts/` | local development helpers |

## Requirements

Node.js 22 and npm. Install with `npm ci` (works with npm 10 and 11). To add or
upgrade dependencies use npm 11 (`npx npm@11 install …`): npm 10.9 crashes
("Cannot read properties of null (reading 'edgesOut')") while resolving Vite 8's
optional peers. Vitest is 4.1 because `@cloudflare/vitest-pool-workers` 0.22
requires `vitest ^4.1.0`, and Vite is pinned to 7.3.6 to avoid that npm crash.
Cloudflare's documentation now names the same integration
`@cloudflare/vitest-plugin` (1.x, same Vitest 4.1 peer range).

## Tests

```sh
npm ci
npm test            # vitest + @cloudflare/vitest-pool-workers (D1 and R2 simulated locally)
npm run typecheck
```

Each test file gets its own D1 database with `migrations/` applied
(`test/apply-migrations.ts`) and a local R2 bucket. Throwaway secrets are
generated for every run in `vitest.config.ts` (an Ed25519 key pair for response
signatures, an admin token, HMAC keys). Outbound `fetch` (Turnstile, Telegram)
is mocked. The suite covers, among others: a new signature gets `upload`, a
known one `count_only`; **30 simultaneous claims of a new signature produce
exactly one upload decision** (atomic conditional `UPDATE`; mutation-checked);
a replay returns the identical signed decision without counting; every cap
answers 429; unknown build 403; forged, expired or unrequested upload token
403; missing or oversized `Content-Length` 413; regression reopens a fixed
signature; merges; CORS; Turnstile; cron retention.

The upload tests that cut a body short or send too much ("refuses a body that
does not match its Content-Length", "charges nothing for an interrupted
piece") make the local R2 simulator print two `uncaught exception … Network
connection lost` lines and one workerd `fixed-length pipe ended prematurely`
trace per aborted put (three puts). They come from the simulator itself
(reproduced with a bare `FixedLengthStream` + `put` and every promise observed;
the storage-failure test, which replaces the simulator's put, prints none) and
are expected.

## Local development

```sh
npm run dev:secrets   # throwaway secrets -> .dev.vars and .dev.client.json (both gitignored)
npm run dev:migrate   # apply migrations to the local D1
npm run dev           # wrangler dev --local on http://127.0.0.1:8787
npm run dev:smoke     # register a test build, claim, upload, complete, read back, replay
```

`dev:smoke` checks every console response signature with `node:crypto` against
the public key written in `.dev.client.json`. A manual cron run:
`curl http://127.0.0.1:8787/cdn-cgi/local/scheduled`. Point the console build
at a local server with `D2_CRASHREPORT_URL`.

## API v1

All JSON bodies carry `"v": 1`. Errors are `{"v":1,"error":"<code>","message":"…"}`
plus `retry_after_s` (429) or `disable_until_unix` (503).

Console answers are bound to their request so that a signed answer captured
from one report cannot be replayed to a console for another: `report_id` is in
every decision, in every answer to a valid claim (400 header mismatch, 403
`unknown_build`, 429), and in every answer past a valid upload token (plus
`name` on piece routes once the piece is known to be requested). Answers to
requests that prove nothing (invalid claim, missing or bad token, 413 before the
token is checked, 503 kill switch) are not bound: anyone could obtain them for
any report id. The console should only act on a bound answer whose `report_id`
(and `name`) match its request.

### Console

Requests carry `X-D2V-Client: d2vita/<build_id>` and `X-D2V-Install: <install_id>`.
**Every** response on these routes, errors included, carries
`X-D2V-Signature: <base64 Ed25519 of the exact body bytes>`.

| Method | Path | Answers |
|---|---|---|
| POST | `/v1/claims` | `200` decision · `400 invalid_payload` · `403 unknown_build` · `413` · `429 rate_limited` · `503 not_accepting` |
| PUT | `/v1/reports/{report_id}/artifacts/{name}` | `201 {name, bytes, sha256}` · `400` (body shorter/longer than declared, or cut off) · `403 bad_token` · `409 exists` · `413` · `429` · `500 storage_unavailable` (R2 failed: retry later) |
| POST | `/v1/reports/{report_id}/complete` | `200 {"report_id":…,"sample_stored":bool}` · `400` · `403 bad_token` · `409 incomplete` (`missing`) |

Decision (`action` is `upload` or `count_only`; `upload` is `null` for `count_only`):

```json
{"v":1,"report_id":"01…","signature":"S…","action":"upload",
 "upload":{"token":"eyJyIjoi….…","expires_unix":1789286000,"artifacts":[{"name":"crash_txt","max_bytes":65536}]},
 "retry_after_s":null,"disable_until_unix":null}
```

Pieces requested per kind (only those listed in the claim with `bytes` within
the cap): `host_fault` → `dump` (2 MiB), `crash_log`, `boot_progress`;
`halt`/`abnormal_exit` → `crash_txt` (64 KiB), `crash_log` (64 KiB),
`boot_progress` (320 KiB); `guest_fault`/`hang` → `crash_log`, `boot_progress`.
Uploads and `complete` use `Authorization: D2V-Upload <token>` (valid 30 min,
the length of the sample lease).

### Public site

| Method | Path | Answers |
|---|---|---|
| POST | `/v1/bugs` | `201 {"id":"B…"}` · `400` · `403 turnstile` · `403 origin_not_allowed` · `413` · `429` |
| OPTIONS | `/v1/bugs` | CORS preflight (`ALLOWED_ORIGIN` only) |

### Admin (`Authorization: Bearer <token>`)

| Method | Path | Role |
|---|---|---|
| GET | `/v1/admin/signatures?status=&kind=&build=&sort=count\|last_seen&limit=&cursor=` | list (`items`, `next_cursor`) |
| GET | `/v1/admin/signatures/{id}` | detail: per-build counters, distinct consoles, merged children, sample, 20 recent claims |
| PATCH | `/v1/admin/signatures/{id}` | `status` (`open`/`fixed`/`ignored`), `fixed_in_version`, `merged_into`, `issue_url`, `note`, `resample: true` |
| GET | `/v1/admin/reports/{id}` | stored claim and decision |
| GET | `/v1/admin/artifacts/{report_id}/{name}` | sealed bytes (`X-D2V-SHA256`) |
| GET | `/v1/admin/bugs?status=&limit=&cursor=`, `/v1/admin/bugs/{id}` | bug reports |
| PATCH | `/v1/admin/bugs/{id}` | `status`, `issue_url`, `note` |
| POST | `/v1/admin/builds` | `{build_id, version, channel}` (201 created, 200 updated) |
| DELETE | `/v1/admin/installs/{install_id}` | erase the claims and pieces of one installation |
| GET | `/v1/admin/stats` | today's global quota use, totals, settings |
| PUT | `/v1/admin/settings` | `{accepting, disable_until_unix, caps: {…}}` |

### Choices made where the design left room

- A missing `Content-Length` is answered **413** `length_required` on every
  route with a body (claims, uploads, complete, bugs, admin writes).
- `X-D2V-Client` and `X-D2V-Install` are required on `/v1/claims` and must
  match `build_id` and `install_id` of the claim (400 otherwise).
- The body of `complete` may list names (`["crash_log"]`) or objects
  (`[{"name":"crash_log","bytes":123}]`); every name must have been requested.
- `host_fault` with a PC region `unknown` is not in the rules table; it is
  grouped per build as `hfault_unknown|<build_id>|<pc.offset>|<lr.offset>`.
- The claim schema accepts an optional top-level `redactions` count. Feature
  fields may be missing or `null` (written `-` in the canon); unknown fields are
  rejected. Free-text fields are printable ASCII without `|`.
- The daily byte caps are charged for **stored** pieces only. A read-only check
  answers 429 before the body is read when the budget is already short; the
  atomic charge happens once R2 has the piece (if another upload took the last
  bytes meanwhile, the piece is deleted and the answer is 429). A failed attempt
  costs nothing, so a console can retry a piece cut off by a Wi-Fi drop within
  its 3 MiB, and repeated failures write nothing to D1. A storage failure is a
  `500 storage_unavailable`, not a 400, and not a 503, which the spec reserves
  for the kill switch (`not_accepting` with `disable_until_unix`).
- The SHA-256 of a piece is recorded in D1 (`reports.artifacts`) and returned
  as `X-D2V-SHA256`; R2 custom metadata carries `bytes` and `build_id`. R2 needs
  metadata before a streamed body starts, and bodies are never buffered.
- Only `install_hash` is stored; the raw `install_id` is removed from the
  stored claim.
- Rate limits use the channel of the **registered** build, not the one claimed.
  Counters are consumed most specific first and stop at the first refusal.
- `503` without an end date set by the admin answers `disable_until_unix = now + 24 h`.
- A replay with the same `report_id` from another installation is a 400.
- IP pseudonym: `HMAC(HMAC(INSTALL_HASH_KEY, day|salt), network)` with a random
  salt per UTC day stored in `settings`; the cron deletes salts and counters from
  two days ago, after which old hashes cannot be linked to an address.
- What "one IP" means for the per-IP caps: an IPv4 address (IPv4-mapped IPv6
  counts as its IPv4 address); for IPv6, a **/48** on claims and a **/64** on bug
  reports. One IPv6 host controls a whole prefix (a VPS gets a /64, a free
  tunnel broker a /48), so counting full addresses would let one machine use
  the whole global budget. The console network stack is IPv4-only (VitaSDK has
  no `AF_INET6`), so no player shares a /48 claim counter; browsers on home
  IPv6 do share /48s with other customers of their ISP, hence /64 for bugs.

### Limits (defaults, adjustable with `PUT /v1/admin/settings`)

| Cap | Default |
|---|---|
| `install_claims` / `install_artifact_bytes` | 3 / 3 MiB per day |
| `install_claims_dev` / `install_artifact_bytes_dev` (dev/test builds) | 50 / 64 MiB per day |
| `ip_claims` / `ip_bugs` | 10 / 3 per day, per IPv4 address or IPv6 /48 (claims) or /64 (bugs) |
| `global_claims` / `global_artifact_bytes` | 2000 / 300 MiB per day |
| `global_new_signatures` / `global_bugs` | 200 / 100 per day |

D1 rows written per claim, measured with the local simulator: 10 for a known
signature from a known console, 12 from a new console, 17 for a new signature
(including the once-a-day IP salt). New signatures are capped at 200 per day,
so the daily worst case stays near 25 000 writes (free quota: 100 000).

### Retention (cron)

Rate counters and IP salts after two days; pieces of signatures `fixed` or
`ignored` for 90 days; orphan pieces (upload window closed, not a stored
sample); claims older than 180 days with their pieces (aggregate counters
stay); bugs older than one year.

## Configuration

`wrangler.jsonc` defines the production Worker and `env.staging`
(`d2vita-crash-staging`, its own D1 and R2). Plain variable: `ALLOWED_ORIGIN`
(default `https://franckrst.github.io`).

Secrets (never in the repository):

| Secret | Format |
|---|---|
| `ADMIN_TOKEN_SHA256` | hex SHA-256 of the admin bearer token (the token itself stays with the local admin tool) |
| `UPLOAD_TOKEN_KEY` | 32+ random bytes, hex |
| `RESPONSE_SIGNING_KEY` | Ed25519 **seed**, 32 bytes as 64 hex characters; its public key is built into the console |
| `INSTALL_HASH_KEY` | 32+ random bytes, hex. Do not rotate: install hashes, distinct-console counts and erasure depend on it |
| `TURNSTILE_SECRET` | Turnstile secret key of the site widget |
| `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` | optional; notifications are sent only when both are set |

Generating an Ed25519 seed and its public key with OpenSSL:

```sh
openssl genpkey -algorithm ed25519 -outform DER -out sk.der     # keep offline
tail -c 32 sk.der | xxd -p -c 64                                  # RESPONSE_SIGNING_KEY
openssl pkey -inform DER -in sk.der -pubout -outform DER | tail -c 32 | xxd -p -c 64   # public key for the console
```

## Deployment (maintainer machine only)

Nothing here has been deployed yet. Every `REPLACE_AT_DEPLOY…` value in
`wrangler.jsonc` is a placeholder that makes a deploy fail until replaced.
Run with the Cloudflare API token exported in the shell for these commands
only (it is not stored in this repository or on GitHub). Do staging first.

1. Enable R2 on the account (dashboard → R2).
2. Create the databases and put their ids into `wrangler.jsonc`:
   ```sh
   npx wrangler d1 create d2vita_crash_staging   # -> env.staging database_id
   npx wrangler d1 create d2vita_crash           # -> top-level database_id
   ```
3. Create the buckets:
   ```sh
   npx wrangler r2 bucket create d2vita-crash-artifacts-staging
   npx wrangler r2 bucket create d2vita-crash-artifacts
   ```
4. Apply the migrations:
   ```sh
   npx wrangler d1 migrations apply DB --remote --env staging
   npx wrangler d1 migrations apply DB --remote
   ```
5. Set the secrets (values typed or piped, never committed), for each name above:
   ```sh
   npx wrangler secret put ADMIN_TOKEN_SHA256 --env staging
   npx wrangler secret put ADMIN_TOKEN_SHA256
   ```
6. Deploy and check:
   ```sh
   npx wrangler deploy --env staging   # https://d2vita-crash-staging.<subdomain>.workers.dev
   npx wrangler deploy                 # https://d2vita-crash.<subdomain>.workers.dev
   ```
   Register builds with the local admin tool (`POST /v1/admin/builds`); the API
   refuses claims from unregistered builds. Production tests must use a build
   registered with `channel=test`, then erase what they created.

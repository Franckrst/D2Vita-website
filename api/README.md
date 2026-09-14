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
| `src/maintenance.ts` | D1 statement budget and piece purge shared by the cron and erasure |
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
is mocked. Ajv 2020 (a test dependency, never shipped in the Worker) compiles
the four contract schemas, and `test/helpers.ts` checks **every** answer a test
receives: the definition of its route for a success, `admin.v1#ErrorBody` with
the documented status for a failure, the binding rules of the console routes,
and, for those routes, the Ed25519 signature verified over the exact bytes the
way the console verifies it. `test/contract-*.test.ts`
add the vectors: 26 signature canons and ids, 70 refused claims, 9 response
signatures and 5 that must not verify, one case per error code and one per
answer body of the contract.

The suite covers, among others: a new signature gets `upload`, a
known one `count_only`; **30 simultaneous claims of a new signature produce
exactly one upload decision** (atomic conditional `UPDATE`; mutation-checked);
a replay returns the identical signed decision without counting; every cap
answers 429, IPv6 counted per prefix; unknown build 403; forged, expired or
unrequested upload token 403; missing or oversized `Content-Length` 413; an
interrupted or refused upload charges nothing and its retry is accepted;
answers bound to their report; regression reopens a fixed signature; merges;
erasure; CORS; Turnstile; cron retention within the D1 statement budget
(counted by `test/d1-counter.ts`).

The upload tests that cut a body short, send too much or drop the connection
("refuses a body that does not match its Content-Length", "charges nothing for
an interrupted piece", "answers 400 when the connection drops mid-body") make
the local R2 simulator print two `uncaught exception … Network connection lost`
lines and one workerd `fixed-length pipe ended prematurely` trace per aborted
put (four puts). They come from the simulator itself
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

Known limit of local development: `wrangler dev` 4.124 exits ("Uncaught Error:
Network connection lost", raised in its dev proxy) when a client disconnects in
the middle of a request body. This happens with any Worker code (reproduced on
this API before and after the upload changes) and does not concern Cloudflare's
edge. Test interrupted uploads with `npm test`, or restart `wrangler dev` after
such a test.

`dev:smoke` checks every console response signature with `node:crypto` against
the public key written in `.dev.client.json`. A manual cron run:
`curl http://127.0.0.1:8787/cdn-cgi/local/scheduled`. Point the console build
at a local server with `D2_CRASHREPORT_URL`.

## API v1

`../contract` is the authority on every byte on the wire: JSON schemas,
signature rules, sealed format and vectors. The tests hold this Worker against
it — the signature and response-signature vectors, the valid and invalid claim
vectors plus a mutation sweep of the claim validator, and **every answer of
every test** validated with Ajv 2020 in strict mode (`test/contract.ts`,
`test/contract-*.test.ts`). What follows repeats the contract for a reader; if
the two ever disagree, the contract is right.

All JSON bodies carry `"v": 1`. Errors are `{"v":1,"error":"<code>","message":"…"}`
with the thirteen codes of `admin.v1#ErrorBody` and their statuses, plus
`retry_after_s` (429) or `disable_until_unix` (503).

Console answers name the request they answer, so that a signed answer captured
from one report cannot be replayed to a console waiting for another:
`report_id` is in every decision, in every answer to a valid claim (400 header
mismatch, 403 `unknown_build`, 429), and in every answer on a piece route whose
path parameters are valid — with `artifact` (the piece name) in the errors of a
PUT, and `name` in its 201. Answers to a request that names no valid report
(an invalid claim, a malformed path, 413 or 503 before the claim is read) are
not bound: there is nothing to name. The console acts on a bound answer only
when `report_id` (and the piece name) match its own request.

### Console

Requests carry `X-D2V-Client: d2vita/<build_id>` and `X-D2V-Install: <install_id>`.
**Every** response on these routes, errors included, carries
`X-D2V-Signature: <base64 Ed25519 of the exact body bytes>`.

| Method | Path | Answers |
|---|---|---|
| POST | `/v1/claims` | `200` decision · `400 invalid_payload` · `403 unknown_build` · `413` · `429 rate_limited` · `503 not_accepting` |
| PUT | `/v1/reports/{report_id}/artifacts/{name}` | `201 {report_id, name, bytes}` and `X-D2V-SHA256` · `400 invalid_payload` (bad path, body shorter/longer than declared or cut off, fewer than 88 bytes) · `403 bad_token` · `409 exists` · `413` · `429` · `500 internal_error` (R2 failed: retry later) · `503 not_accepting` |
| POST | `/v1/reports/{report_id}/complete` | `200 {"report_id":…,"sample_stored":bool}` · `400 invalid_payload` · `403 bad_token` · `409 incomplete` · `503 not_accepting` |

The kill switch covers the three console routes: with `accepting: false` a
claim, an upload and a `complete` all answer 503 with `disable_until_unix`.

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
| POST | `/v1/bugs` | `201 {"id":"B…"}` · `400 invalid_payload` (bad body, or an `Origin` that is not the site) · `403 turnstile` · `413` · `429` |
| OPTIONS | `/v1/bugs` | CORS preflight (`ALLOWED_ORIGIN` only) |

### Admin (`Authorization: Bearer <token>`)

| Method | Path | Role |
|---|---|---|
| GET | `/v1/admin/signatures?status=&kind=&build=&sort=count\|last_seen&limit=&cursor=` | `admin.v1#SignatureList` (`limit` is an extension: 1 to 200, 50 by default) |
| GET | `/v1/admin/signatures/{id}` | `admin.v1#SignatureDetail`: per-build counters, distinct consoles, sample and lease, 20 recent claims |
| PATCH | `/v1/admin/signatures/{id}` | `status` (`open`/`fixed`/`ignored`), `fixed_in_version`, `merged_into`, `issue_url`, `note`, `resample: true` |
| GET | `/v1/admin/reports/{id}` | `admin.v1#ReportDetail`: the stored claim and what happened to it |
| GET | `/v1/admin/artifacts/{report_id}/{name}` | sealed bytes (`X-D2V-SHA256`) |
| GET | `/v1/admin/bugs?status=&limit=&cursor=`, `/v1/admin/bugs/{id}` | `admin.v1#BugList`, `admin.v1#BugDetail` |
| PATCH | `/v1/admin/bugs/{id}` | `status`, `issue_url` |
| POST | `/v1/admin/builds` | `{build_id, version, channel}` -> `admin.v1#BuildRecord` (201 created, 200 updated) |
| DELETE | `/v1/admin/installs/{install_id}` | erase the claims and pieces of one installation: `200 admin.v1#ForgetInstallResult`, or the same body with **202** when the run hit its D1 statement budget — call again until it answers 200 (counts are per call) |
| GET | `/v1/admin/stats` | `admin.v1#Stats`: today's global quota use and the kill switch |
| PUT | `/v1/admin/settings` | `admin.v1#SettingsUpdate` -> `admin.v1#Settings` |

### Choices made where the design left room

- A missing `Content-Length` is answered **413** `payload_too_large` on every
  route with a body (claims, uploads, complete, bugs, admin writes), the code
  the contract gives that case.
- `X-D2V-Client` and `X-D2V-Install` are required on `/v1/claims` and must
  match `build_id` and `install_id` of the claim (400 otherwise).
- The body of `complete` is `decision.v1#CompleteRequest`: one to four piece
  names (`{"v":1,"artifacts":["crash_log"]}`). What decides completion is the
  decision: every piece it asked for has to be stored, whatever the body lists.
- A `PUT` shorter than 88 bytes is `400 invalid_payload`: no D2VSEAL1 object is
  that small (72-byte header plus one 16-byte tag).
- A bug report whose `Origin` is not the site is `400 invalid_payload`: the
  contract has no code for a refused origin.
- A bug body is taken exactly as `bug.v1` describes it: no control character
  outside tab and line breaks in the description, none at all elsewhere, a
  Turnstile token of printable ASCII without spaces, `contact` absent or a
  string (never `null`). A blank title passes here and the site refuses it:
  what the API stores has to validate as an `admin.v1#BugItem` later.
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
  `500 internal_error`, not a 400, and not a 503, which the spec reserves for
  the kill switch (`not_accepting` with `disable_until_unix`).
- The SHA-256 of a piece is recorded in D1 (`reports.artifacts`) and returned
  as `X-D2V-SHA256` on the PUT and on the admin download; R2 custom metadata
  carries `bytes` and `build_id`. R2 needs metadata before a streamed body
  starts, and bodies are never buffered.
- Two refusals the contract does not describe, both about states it could not
  represent honestly: a signature cannot become `fixed` without a
  `fixed_in_version` (a regression could never be noticed afterwards), and
  `merged_into` has to name a known signature that is not this one and creates
  no cycle. Both answer 400 `invalid_payload`.
- The claim is stored as received, `install_id` included, because
  `admin.v1#ReportDetail` returns it and the contract validates it against
  `claim.v1`, where `install_id` is required. Everything else uses the
  pseudonym `install_hash = HMAC(INSTALL_HASH_KEY, install_id)`: counters,
  distinct-console counts, links and erasure. Claims are deleted after 180
  days.
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
| `install_claims_per_day` / `install_artifact_bytes_per_day` | 3 / 3 MiB per day |
| `prerelease_install_claims_per_day` / `prerelease_install_artifact_bytes_per_day` (dev and test builds) | 50 / 64 MiB per day |
| `ip_claims_per_day` / `ip_bugs_per_day` | 10 / 3 per day, per IPv4 address or IPv6 /48 (claims) or /64 (bugs) |
| `global_claims_per_day` / `global_artifact_bytes_per_day` | 2000 / 300 MiB per day |
| `global_new_signatures_per_day` / `global_bugs_per_day` | 200 / 100 per day |

D1 rows written per claim, measured with the local simulator: 10 for a known
signature from a known console, 12 from a new console, 17 for a new signature
(including the once-a-day IP salt). New signatures are capped at 200 per day,
so the daily worst case stays near 25 000 writes (free quota: 100 000).

### Retention (cron)

In this order:

1. rate counters and IP salts from two days ago and older;
2. bugs older than one year;
3. claims older than 180 days with their pieces (aggregate counters stay), and
   the per-console links (`signature_installs`: install hash, signature, first
   seen) that no remaining claim refers to; a console that reports the family
   again later is counted again in `installs`;
4. orphan pieces (upload window closed, not a stored sample);
5. pieces of signatures `fixed` or `ignored` for 90 days.

D1 on the Workers Free plan allows 50 queries per invocation, and the limit
applies to each statement of a batch. The cron and the erasure route therefore
spend at most 40 statements (`src/maintenance.ts`), work set-based where they
can, and stop cleanly when the budget runs out: rows are only deleted once
their pieces are gone, and the next run (the next day for the cron, the next
call for erasure) continues. An idle cron run executes 12 statements and needs
15 of its budget (a piece-purge round reserves two before it knows whether
anything is left); each round of up to 50 reports whose pieces it deletes adds
two. The summary it logs says `complete`.

## Capacity

Three things fill up on the free plans: the D1 database (500 MB, after which
**every write fails** — claims, bugs and admin writes alike), the R2 bucket
(10 GB), and the daily quotas (100 000 requests, 100 000 D1 writes, 5 M D1
reads). The caps and the retention above are what keep them in bounds; the
numbers here say how much room the defaults actually leave.

**Per claim in D1.** Measured on the local simulator by sending 40 claims and
reading `meta.size_after` before and after (page-granular, so the average over
40 is the useful figure):

| Claim | JSON | D1 growth |
|---|---|---|
| Typical (the spec example), family and console already known | 516 B | **1.1 KB** |
| Typical, new family and new console | 516 B | **2.5 KB** |
| Large (16 frames, a location, three pieces, hints), family and console known | 1 271 B | **2.2 KB** |
| Large, new family and new console | 1 271 B | **4.7 KB** |

A claim keeps its whole JSON, so the size follows what the console sends; a new
family adds the signature row, its per-build counter and the per-console link;
the daily rate counters in those figures are deleted two days later by the cron.

**What the defaults imply.** At the global cap a day holds at most 200 new
families and 1 800 repeats, so 2.5 MB of D1 a day with typical claims and
4.9 MB with large ones. Claims are kept 180 days, so a flood sustained at the
cap settles between **0.45 GB and 0.88 GB**, before the bugs (100 a day for a
year, about 36 MB) and the aggregate rows retention keeps for good. The upper
half of that range is **past the 500 MB wall**, where D1 Free refuses every
write. Nothing near it is expected from a few hundred players, but the default
caps alone do not guarantee the database stays writable.

**R2.** One sealed sample per family, at most 2.4 MiB (a 2 MiB dump plus the
logs), bounded by `global_artifact_bytes_per_day`: **300 MiB a day**. Samples
go when their claim reaches 180 days, or 90 days after the family is closed, so
a sustained flood fills the 10 GB in about **five weeks**.

**Recommendation (not applied — this is a maintainer decision).** The defaults
above are the ones the design asked for, and they are what this Worker ships.
If the VPK is published widely and nobody is watching the dashboard daily, the
safer set is:

| Setting | Default | Safer | Why |
|---|---|---|---|
| `global_claims_per_day` | 2 000 | 500 | 180 days of flood becomes 0.11 to 0.22 GB instead of 0.45 to 0.88 |
| `global_new_signatures_per_day` | 200 | 50 | new families are the expensive claims, and 50 a day is already more bugs than a person can read |
| `global_artifact_bytes_per_day` | 300 MiB | 50 MiB | 10 GB of R2 then takes seven months of flood, not five weeks |
| claim retention (`RETENTION.reportDays` in `src/cron.ts`) | 180 days | 90 days | halves the steady state; the aggregate counters of a family are kept anyway |

The first three are one call away and take effect at once:

```sh
curl -X PUT "$API/v1/admin/settings" -H "authorization: Bearer $ADMIN_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"caps":{"global_claims_per_day":500,"global_new_signatures_per_day":50,"global_artifact_bytes_per_day":52428800}}'
```

**Watching it.** The daily cron logs the database size (`database_bytes` in its
summary, `npx wrangler tail`), R2 is on the Cloudflare dashboard, and
`GET /v1/admin/stats` gives the day's use of every global cap. If the database
does climb: lower `global_claims_per_day`, switch claims off
(`{"accepting":false}`, which answers 503 with `disable_until_unix`), shorten
retention, or move to D1 paid (10 GB).

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

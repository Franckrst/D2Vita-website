# D2Vita crash report contract, v1

This directory fixes what the crash report pieces exchange: the console
(d2-vita, private), the Cloudflare Worker API (`api/`), the local admin
(d2-vita `tools/crash`) and the public site (`site/`). When an implementation
and this contract disagree, the contract is right (design, section 3).

It holds JSON schemas, the signature rules, the sealed artifact format, test
vectors shared by the Python, TypeScript and C implementations, and the tools
that generate and check them.

## Version rule

**v1 is frozen.** An incompatible change creates v2 (new `*.v2.*` files, new
`/v2` routes) and leaves every v1 file as it is. Incompatible means: a
message that a conforming v1 implementation would reject or read
differently, a different signature for the same claim, or different sealed
bytes for the same inputs.

Allowed in v1: clearer wording that changes no accepted message, signature or
byte, and new vectors for behavior this contract already specifies. Never
edit a vector file by hand: change `tools/gen_vectors.py`, regenerate, review
the diff.

## Files

| File | Role |
|---|---|
| `schemas/claim.v1.schema.json` | Claim sent by the console (`POST /v1/claims`), design section 4.4 |
| `schemas/decision.v1.schema.json` | Signed decision, plus the other console upload messages |
| `schemas/bug.v1.schema.json` | Bug form body of the public site, and its 201 response |
| `schemas/admin.v1.schema.json` | Local admin routes, and `ErrorBody` for every route |
| `signature-rules.v1.md` | How the API turns a claim into a signature id |
| `sealed-format.md` | D2VSEAL1, the encrypted container of artifacts |
| `vectors/signatures.v1.json` | Valid claims with their `canon` and `signature` |
| `vectors/claims-invalid.v1.json` | Claims the schema must reject, with the JSON pointer of the error |
| `vectors/sealed.v1.json` | D2VSEAL1 objects to reproduce, and objects that must not open |
| `vectors/response-sig.v1.json` | Ed25519 response signatures that must, or must not, verify |
| `tools/gen_vectors.py` | Generates the four vector files deterministically; reference sealer and opener (PyNaCl) |
| `tools/check_schemas.py` | Checks the schemas and the claim vectors; reference implementation of the signature rules |
| `tools/c_check/Makefile` | `make check`: verifies the Monocypher sources, builds and runs `check_sealed` |
| `tools/c_check/check_sealed.c` | Monocypher 4.0.2 against `sealed.v1.json` and `response-sig.v1.json` |
| `tools/c_check/d2vseal.c`, `tools/c_check/d2vseal.h` | D2VSEAL1 in C with Monocypher (whole buffers) |
| `tools/c_check/jsonlite.c`, `tools/c_check/jsonlite.h` | Strict JSON reader for the vector files |
| `tools/c_check/MONOCYPHER_SHA256` | SHA-256 of the Monocypher tarball and of each copied file (`sha256sum -c` format) |
| `tools/tests/` | Unit tests of the tools, schemas and documents (`unittest`) |
| `requirements.txt` | Pinned Python packages of `.venv` |
| `Makefile` | `venv`, `test` and `check` targets |

`tools/c_check/` also holds unmodified Monocypher 4.0.2 files
(`monocypher.c`, `monocypher.h`, `monocypher-ed25519.c`,
`monocypher-ed25519.h`, `LICENCE.md`), see [Monocypher](#monocypher).

## Setup and checks

Python 3.12 with PyNaCl 1.5.0 (system package) and a C compiler. The schema
checks need `jsonschema`, installed once in `contract/.venv` (gitignored):

```sh
make -C contract venv    # python3 -m venv --system-site-packages contract/.venv
                         # contract/.venv/bin/python -m pip install -r contract/requirements.txt
```

Checks, from the repository root:

```sh
python3 contract/tools/gen_vectors.py --check   # vector files are exactly the generator output
python3 contract/tools/check_schemas.py         # schemas, signature vectors, invalid claims
make -C contract/tools/c_check check            # Monocypher reproduces the sealed and signature vectors
make -C contract check                          # unit tests, then the three checks above
```

`check_schemas.py` re-runs itself with `contract/.venv/bin/python` when
`jsonschema` is not importable. To regenerate the vectors after changing the
generator: `python3 contract/tools/gen_vectors.py`.

## Routes and messages

`schema#Name` means `$defs/Name` in `schemas/<schema>.schema.json`; `schema`
alone means the root of the file. Every JSON response carries `"v": 1`.
Errors use `admin.v1#ErrorBody` (codes below).

**Console** (plain HTTP accepted). Every response, errors included, is signed.

| Method and path | Request | Success | Errors |
|---|---|---|---|
| `POST /v1/claims` | `claim.v1`, at most 16384 bytes | 200 `decision.v1` | 400 `invalid_payload`, 403 `unknown_build`, 413 `payload_too_large`, 429 `rate_limited`, 503 `not_accepting` |
| `PUT /v1/reports/{report_id}/artifacts/{name}` | sealed bytes (`sealed-format.md`), `Content-Length` required, at most `max_bytes` | 201 `decision.v1#ArtifactStored` | 403 `bad_token`, 409 `exists`, 413 `payload_too_large`, 429 `rate_limited` |
| `POST /v1/reports/{report_id}/complete` | `decision.v1#CompleteRequest` | 200 `decision.v1#CompleteResponse` | 403 `bad_token`, 409 `incomplete` |

**Public site** (HTTPS, CORS for `https://franckrst.github.io`). Not signed.

| Method and path | Request | Success | Errors |
|---|---|---|---|
| `POST /v1/bugs` | `bug.v1` | 201 `bug.v1#BugCreated` | 400 `invalid_payload`, 403 `turnstile`, 429 `rate_limited` |

**Local admin** (HTTPS, `Authorization: Bearer <token>`). Not signed. A
missing or wrong token gives 401 `unauthorized`.

| Method and path | Request | Success |
|---|---|---|
| `GET /v1/admin/signatures?status=&kind=&build=&sort=count\|last_seen&cursor=` | | 200 `admin.v1#SignatureList` |
| `GET /v1/admin/signatures/{id}` | | 200 `admin.v1#SignatureDetail` |
| `PATCH /v1/admin/signatures/{id}` | `admin.v1#SignaturePatch` | 200 `admin.v1#SignatureDetail` |
| `GET /v1/admin/reports/{report_id}` | | 200 `admin.v1#ReportDetail` |
| `GET /v1/admin/artifacts/{report_id}/{name}` | | 200 sealed bytes, `application/octet-stream` |
| `GET /v1/admin/bugs?status=&cursor=` | | 200 `admin.v1#BugList` |
| `GET /v1/admin/bugs/{id}` | | 200 `admin.v1#BugDetail` |
| `PATCH /v1/admin/bugs/{id}` | `admin.v1#BugPatch` | 200 `admin.v1#BugDetail` |
| `POST /v1/admin/builds` | `admin.v1#BuildRegistration` | 201 or 200 `admin.v1#BuildRecord` |
| `DELETE /v1/admin/installs/{install_id}` | | 200 `admin.v1#ForgetInstallResult` |
| `GET /v1/admin/stats` | | 200 `admin.v1#Stats` |
| `PUT /v1/admin/settings` | `admin.v1#SettingsUpdate` | 200 `admin.v1#Settings` |

## Headers

| Header | Where | Value |
|---|---|---|
| `X-D2V-Client` | console requests | `d2vita/<build_id>` |
| `X-D2V-Install` | console requests | `<install_id>` (32 lowercase hex digits) |
| `Authorization: D2V-Upload <token>` | `PUT .../artifacts/{name}` and `POST .../complete` | `token` of the decision |
| `X-D2V-Signature` | every response to a console route | see below |
| `Authorization: Bearer <token>` | admin routes | admin token, compared in constant time with `ADMIN_TOKEN_SHA256` |

The design lists 403 for `complete` without naming its header: this contract
uses the upload token there too.

## Response signatures

- Algorithm: Ed25519 as in RFC 8032 (SHA-512, no prehash, no context).
  Console: `crypto_ed25519_check` from `monocypher-ed25519`. Worker: WebCrypto
  `Ed25519`.
- Signed message: the exact bytes of the response body, as produced by the
  Worker. Consoles send no `Accept-Encoding`, so no content encoding applies.
  Nothing is re-serialized or normalized before signing or verifying.
- `X-D2V-Signature`: standard base64 (RFC 4648 section 4) with padding of the
  64-byte signature, 88 characters.
- The console verifies before parsing. A missing or invalid signature is
  handled like a network failure: retry later, and never apply
  `retry_after_s` or `disable_until_unix` from an unverified response.
- Vectors: `vectors/response-sig.v1.json`, including a non-BMP body, an empty
  body and five signatures that must be rejected (among them `S + L`).

A valid signature proves that the Worker wrote the body, not that the body
answers this request: anyone can obtain signed bodies from their own client,
and an on-path attacker can replay them. So every body that concerns one
report names it, and the console checks what the body names against its own
request:

<!-- response-binding:begin -->
| Body | The console checks |
|---|---|
| `decision.v1` | `report_id` equals the `report_id` of the claim |
| `decision.v1#ArtifactStored` | `report_id` and `name` equal those of the PUT path, `bytes` equals the `Content-Length` sent |
| `decision.v1#CompleteResponse` | `report_id` equals the one of the path |
| `admin.v1#ErrorBody` | `report_id` and `artifact`, when present, equal those of the request |
<!-- response-binding:end -->

- A verified body that names another request is handled like a network
  failure.
- The Worker sets `report_id` in every error of `PUT .../artifacts/{name}`
  (with `artifact`) and of `POST .../complete` whose path parameters are
  valid, and in the errors of `POST /v1/claims` that it returns after the
  claim was parsed with a valid `report_id`. The schema requires them for
  `exists` and `incomplete`.
- The console deletes a pending report only after a verified body that names
  it: a decision with `action: count_only`, or a `CompleteResponse`.
- `429 rate_limited` and `503 not_accepting` are honoured even without
  `report_id`: the daily caps and the kill switch are not per report, and the
  Worker may answer them before reading the claim. Their effect cannot outlast
  what the Worker signed (`disable_until_unix` is absolute).
- Status codes are not signed. The console reads a body with the schema that
  its status announces (a 2xx success body, otherwise `ErrorBody`) and treats
  a body that does not match like a network failure.

## Error codes

`error` of `admin.v1#ErrorBody`. `rate_limited` requires `retry_after_s`;
`not_accepting` requires `disable_until_unix`.

<!-- error-codes:begin -->
| Code | Status | Meaning |
|---|---|---|
| `invalid_payload` | 400 | Body is not JSON, or does not match its schema; bad path parameter |
| `unauthorized` | 401 | Admin route without the right bearer token |
| `unknown_build` | 403 | Claim for a `build_id` that was never registered |
| `bad_token` | 403 | Upload token missing, forged, expired, or artifact not requested |
| `turnstile` | 403 | Turnstile verification of a bug report failed |
| `not_found` | 404 | Unknown route or resource |
| `method_not_allowed` | 405 | Known route, other method |
| `exists` | 409 | Artifact already uploaded |
| `incomplete` | 409 | `complete` before every requested artifact was uploaded |
| `payload_too_large` | 413 | `Content-Length` missing, or above the limit (checked before reading) |
| `rate_limited` | 429 | A daily cap is reached (design, section 5.5) |
| `internal_error` | 500 | Unexpected server failure |
| `not_accepting` | 503 | Kill switch on |
<!-- error-codes:end -->

## Notes for implementers

- Schemas are JSON Schema 2020-12. Validators must resolve the relative
  `$ref`s between the four files (register them all by `$id`), and must not
  rely on `format`, which is not used.
- The schemas are written for ajv's strict mode (`new Ajv2020({strict: true})`):
  every subschema that uses a type-specific keyword declares its `type`, and
  every `required` name is listed in the same object's `properties`.
  `check_schemas.py` enforces both rules.
- Patterns are ECMA-262 regular expressions, always anchored `^...$`, with
  ASCII classes only. In Python, `$` also matches before a final newline:
  `check_schemas.py` validates with `\Z` instead, and several invalid claim
  vectors end with a newline to catch this.
- String lengths count Unicode code points (the ajv default).
- `type: integer` accepts `1420.0`; the signature rules format it as `1420`
  (vector `halt_code_written_as_float`).
- Compute a signature only for a claim that passed validation.
- `claim.artifacts[].bytes` and `max_bytes` are sealed sizes:
  `72 + n + 16 * (floor(n / 65536) + 1)` for `n` plaintext bytes. The caps
  of design section 4.5, and the largest plaintext that fits under each one
  with the console's 65536-byte chunks:

<!-- artifact-caps:begin -->
| Artifact | Sealed cap, bytes | Largest plaintext, bytes |
|---|---|---|
| `dump` | 2097152 (2 MiB) | 2096568 |
| `crash_txt` | 65536 (64 KiB) | 65448 |
| `crash_log` | 65536 (64 KiB) | 65448 |
| `boot_progress` | 327680 (320 KiB) | 327528 |
<!-- artifact-caps:end -->

## Decisions this contract adds to the design

The design (`docs/superpowers/specs/2026-09-14-crash-reports-design.md` in
d2-vita) leaves these points open; v1 settles them as follows.

1. `claim.artifacts[].bytes` is the size of the sealed object, which is the
   `Content-Length` of its PUT, so the section 4.5 caps apply to it.
2. `host_fault` with `features.pc.region = unknown` has no row in the design
   table: `hfault_unknown|{build_id}|{features.pc.offset}|{features.lr.offset}`.
3. Addresses and hex values are normalized (lowercase, no leading zeros); the
   schema rejects other spellings, so the API can use them as received.
4. Every `features` key is required; `null` means unknown (`location`,
   `exception`, `stop_reason`, `thread_name`, `code` and `import` of
   `abnormal_exit`, `eip` and `runner_state` of `hang`, `uptime_s`).
5. `platform.model` is `vita`, `pstv` or `unknown`; `platform.fw` is `X.YY`
   or `unknown`.
6. Section 4.6 puts the number of redactions in the claim: optional
   top-level `redactions`.
7. `hints` only contains kinds strictly less severe than `kind`, without
   repetition.
8. `abnormal_exit.reason` is one of `main_thread_fault`, `unshimmed_import`,
   `fatal_app_exit`, `raise_exception`, `exit_process`; `guest_fault.exception`
   and `host_fault.stop_reason` are `0x` hex codes.
9. `report_id` is an uppercase ULID whose first character is 0 to 7;
   `build_id` is at most 64 characters.
10. `complete` sends the names of the uploaded artifacts; the 201 body of a
    PUT is `decision.v1#ArtifactStored`.
11. Error codes for the statuses the design leaves unnamed (401, 404, 405,
    409 `incomplete`, 413, 500).
12. The bug request has no `v`; `contact` may be absent or empty; no control
    characters except tab, line feed and carriage return in `description`.
13. The design's example signature id `S4KQ7M2X9D3T8B6A` contains `8` and `9`,
    which RFC 4648 base32 does not use: it is illustrative only.
14. Opening a sealed object has four results (`truncated`, `malformed`,
    `wrong_key`, `tampered`), checked in a fixed order; readers accept a
    `chunk_size` from 1 to 1048576; an all-zero X25519 output is refused.
15. Admin definitions: the design lists tables but no columns, so the fields
    come from sections 5.2 to 5.6. Bugs use the signature statuses `open`,
    `fixed`, `ignored`.
16. Only a `host_fault` claim whose `features.redaction` is `clean` may offer
    the `dump`; the schema rejects a dump offered by any other kind or
    marked `withheld` (section 4.5). The other artifacts are not tied to a
    kind: the "sent for" column of section 4.5 is applied by the API when it
    chooses what to request.
17. Signed bodies about one report name it (`ArtifactStored` and
    `CompleteResponse` carry `report_id`; `ErrorBody` may carry `report_id`
    and `artifact`), and the console checks them against its request. The
    signature itself stays over the body alone, as section 5.2 says, instead
    of also covering the method, path and status.

## Monocypher

- Version 4.0.2, from `https://monocypher.org/download/monocypher-4.0.2.tar.gz`.
  SHA-256 of the tarball:
  `38d07179738c0c90677dba3ceb7a7b8496bcfea758ba1a53e803fed30ae0879c`.
- monocypher.org publishes BLAKE2b and SHA-512 checksums, not SHA-256: both
  matched the downloaded tarball. They come from the same server; the
  GitHub release asset of tag 4.0.2, from another origin, has the same
  SHA-256.
- The copied files are unmodified; `make check` verifies them against
  `tools/c_check/MONOCYPHER_SHA256` first. Licence: `tools/c_check/LICENCE.md`
  (BSD-2-Clause or CC0-1.0).
- Monocypher 4.0.3 (2026-06-15) hardens `fe_cswap` and `fe_ccopy` against a
  compiler-introduced timing leak (EdDSA signing, and the X25519 ladder that
  the console runs with its ephemeral secret). Outputs do not change, so the
  vectors hold for 4.0.3 as well.

// Admin routes (spec section 5.2), used by the maintainer's local tool only.
// Authorization: Bearer <token>; SHA-256(token) is compared in constant time
// with ADMIN_TOKEN_SHA256. The router checks it before any admin dispatch.

import { fromBase64Url, fromHex, installHash, sha256, timingSafeEqual, toBase64Url, utf8 } from "./crypto";
import { requireSecret, type Env } from "./env";
import { error, json, readBoundedJson } from "./http";
import { SCOPE, loadSettings, saveSettings, utcDay, type Settings } from "./limits";
import { StatementBudget, purgePieces } from "./maintenance";
import { ARTIFACT_NAMES, KINDS, type ArtifactName } from "./types";
import { artifactKey } from "./uploads";
import {
  CLAIM_PATTERNS,
  validateBugPatch,
  validateBuildRegistration,
  validateSettingsPatch,
  validateSignaturePatch,
} from "./validate";

const ADMIN_BODY_MAX_BYTES = 16 * 1024;

export async function isAdmin(request: Request, env: Env): Promise<boolean> {
  const match = /^Bearer (\S{1,512})$/.exec(request.headers.get("authorization") ?? "");
  const expected = env.ADMIN_TOKEN_SHA256;
  if (!match || !expected || !/^[0-9a-fA-F]{64}$/.test(expected)) return false;
  return timingSafeEqual(await sha256(utf8(match[1]!)), fromHex(expected));
}

export function unauthorized(): Response {
  const response = error("unauthorized", "A valid admin token is required");
  response.headers.set("www-authenticate", "Bearer");
  return response;
}

// ---------------------------------------------------------------------------
// Query helpers.

// Path parameters and query ids are matched with the patterns of the contract,
// never a looser spelling of them: an id claim.v1 or decision.v1 calls
// malformed is answered without a lookup. BugId is the narrower alphabet of the
// ids this API mints (base32 of 10 random bytes), a subset of bug.v1#BugId.
// test/contract-admin-requests.test.ts holds all five against the schemas.
export const ADMIN_PATTERNS = {
  SignatureId: /^S[A-Z2-7]{15}$/,
  BuildId: CLAIM_PATTERNS.BuildId,
  ReportId: CLAIM_PATTERNS.ReportId,
  InstallId: CLAIM_PATTERNS.InstallId,
  BugId: /^B[A-Z2-7]{16}$/,
} as const;

const { SignatureId: SIGNATURE_ID, BuildId: BUILD_ID, ReportId: REPORT_ID, BugId: BUG_ID } = ADMIN_PATTERNS;

class BadQuery extends Error {}

function queryParams(url: URL, allowed: readonly string[]): URLSearchParams {
  for (const key of url.searchParams.keys()) {
    if (!allowed.includes(key)) throw new BadQuery(`${key}: unknown query parameter`);
  }
  return url.searchParams;
}

function optionalEnum(params: URLSearchParams, key: string, values: readonly string[]): string | null {
  const value = params.get(key);
  if (value === null || value === "") return null;
  if (!values.includes(value)) throw new BadQuery(`${key}: must be one of ${values.join(", ")}`);
  return value;
}

function limitParam(params: URLSearchParams): number {
  const raw = params.get("limit");
  if (raw === null || raw === "") return 50;
  const n = Number(raw);
  if (!Number.isInteger(n) || n < 1 || n > 200) throw new BadQuery("limit: must be an integer in [1, 200]");
  return n;
}

interface Cursor {
  k: number;
  id: string;
}

function encodeCursor(cursor: Cursor): string {
  return toBase64Url(utf8(JSON.stringify(cursor)));
}

function decodeCursor(raw: string | null): Cursor | null {
  if (raw === null || raw === "") return null;
  try {
    const value = JSON.parse(new TextDecoder().decode(fromBase64Url(raw))) as Partial<Cursor>;
    if (typeof value.k === "number" && Number.isFinite(value.k) && typeof value.id === "string" && value.id.length <= 64) {
      return { k: value.k, id: value.id };
    }
  } catch {
    // fall through
  }
  throw new BadQuery("cursor: invalid");
}

function withBadQuery(fn: () => Promise<Response>): Promise<Response> {
  return fn().catch((e) => {
    if (e instanceof BadQuery) return error("invalid_payload", e.message);
    throw e;
  });
}

// ---------------------------------------------------------------------------
// Signatures.

type Row = Record<string, unknown>;

// The VERSION part of a build_id (contract admin.v1#Version), e.g.
// "0.1.3+c41b41abc61a" -> "0.1.3". Mirrors BuildCount.version in the Python
// admin client (tools/crash/d2vcrash/api.py) — same split, same meaning.
function versionOf(buildId: unknown): string | null {
  return typeof buildId === "string" ? buildId.split("+", 1)[0]! : null;
}

// admin.v1#SignatureSummary: exactly these fields, no more (the local admin
// tool checks what it receives against the contract).
function signatureSummary(row: Row) {
  return {
    id: row.id,
    kind: row.kind,
    canon: row.canon,
    status: row.status,
    count: row.count,
    installs: row.installs,
    first_seen_unix: row.first_seen,
    last_seen_unix: row.last_seen,
    sample_state: row.sample_state,
    fixed_in_version: row.fixed_in_version,
    merged_into: row.merged_into,
    issue_url: row.issue_url,
    // row.last_build_id: present when the row comes from listSignatures's
    // correlated subquery. signatureDetail overrides this field from its own
    // builds[] (already fetched, ordered by last_seen) instead of paying for
    // a second subquery.
    last_version: versionOf(row.last_build_id),
  };
}

interface StoredPiece {
  bytes: number;
  sha256: string;
  uploaded_at: number;
}

// admin.v1#StoredArtifact, from the reports.artifacts map of one report.
function storedArtifacts(artifacts: unknown) {
  const pieces = typeof artifacts === "string" ? (JSON.parse(artifacts) as Record<string, StoredPiece>) : {};
  return Object.entries(pieces).map(([name, piece]) => ({
    name,
    bytes: piece.bytes,
    sha256: piece.sha256,
    stored_unix: piece.uploaded_at,
  }));
}

export function listSignatures(request: Request, env: Env): Promise<Response> {
  return withBadQuery(async () => {
    const params = queryParams(new URL(request.url), ["status", "kind", "build", "sort", "cursor", "limit"]);
    const status = optionalEnum(params, "status", ["open", "fixed", "ignored", "regressed"]);
    const kind = optionalEnum(params, "kind", KINDS);
    const sort = optionalEnum(params, "sort", ["count", "last_seen"]) ?? "count";
    const build = params.get("build") || null;
    if (build !== null && !BUILD_ID.test(build)) throw new BadQuery("build: must be a build id");
    const limit = limitParam(params);
    const cursor = decodeCursor(params.get("cursor"));

    const where: string[] = [];
    const binds: unknown[] = [];
    if (status) where.push(`status = ?${binds.push(status)}`);
    if (kind) where.push(`kind = ?${binds.push(kind)}`);
    if (build) where.push(`id IN (SELECT signature FROM signature_builds WHERE build_id = ?${binds.push(build)})`);
    if (cursor) {
      const k = binds.push(cursor.k);
      const id = binds.push(cursor.id);
      where.push(`(${sort} < ?${k} OR (${sort} = ?${k} AND id > ?${id}))`);
    }
    const sql =
      `SELECT *, (SELECT build_id FROM signature_builds WHERE signature = signatures.id ` +
      `ORDER BY last_seen DESC LIMIT 1) AS last_build_id FROM signatures ` +
      `${where.length > 0 ? `WHERE ${where.join(" AND ")}` : ""} ` +
      `ORDER BY ${sort} DESC, id ASC LIMIT ?${binds.push(limit + 1)}`;
    const { results } = await env.DB.prepare(sql).bind(...binds).all<Row>();
    const page = results.slice(0, limit);
    const last = page[page.length - 1];
    const next = results.length > limit && last ? encodeCursor({ k: last[sort] as number, id: last.id as string }) : null;
    return json({ items: page.map(signatureSummary), next_cursor: next });
  });
}

// admin.v1#SignatureDetail. sample_artifacts describes the pieces of
// sample_report, the stored sample, so that a report id and a piece name taken
// from this body always name the same object in R2.
export async function signatureDetail(db: D1Database, id: string) {
  const row = await db.prepare("SELECT * FROM signatures WHERE id = ?1").bind(id).first<Row>();
  if (!row) return null;
  const [builds, recent] = await db.batch<Row>([
    db
      .prepare(
        "SELECT build_id, count, first_seen, last_seen FROM signature_builds WHERE signature = ?1 ORDER BY last_seen DESC, build_id",
      )
      .bind(id),
    db
      .prepare(
        `SELECT report_id, build_id, received_at, action
         FROM reports WHERE signature = ?1 ORDER BY received_at DESC, report_id LIMIT 20`,
      )
      .bind(id),
  ]);
  const sampleReport = row.sample_report as string | null;
  const sample = sampleReport
    ? await db.prepare("SELECT artifacts FROM reports WHERE report_id = ?1").bind(sampleReport).first<{ artifacts: string }>()
    : null;
  const buildRows = builds?.results ?? [];
  return {
    ...signatureSummary(row),
    // row has no last_build_id here (plain SELECT *, no subquery): buildRows
    // is already ordered by last_seen DESC, so its head is the same build the
    // listSignatures subquery would have found.
    last_version: versionOf(buildRows[0]?.build_id),
    rules_version: row.rules_version,
    note: row.note,
    sample_report: sampleReport,
    lease_report: row.lease_report,
    lease_expires_unix: row.lease_expires,
    sample_artifacts: storedArtifacts(sample?.artifacts),
    builds: buildRows.map((b) => ({
      build_id: b.build_id,
      count: b.count,
      first_seen_unix: b.first_seen,
      last_seen_unix: b.last_seen,
    })),
    recent_reports: (recent?.results ?? []).map((r) => ({
      report_id: r.report_id,
      build_id: r.build_id,
      received_unix: r.received_at,
      action: r.action,
    })),
  };
}

// Root of a signature's merge chain (chains are kept flat; the hop limit only
// guards against a corrupted chain).
async function mergeRoot(db: D1Database, id: string): Promise<string | null> {
  let current = await db.prepare("SELECT id, merged_into FROM signatures WHERE id = ?1").bind(id).first<Row>();
  if (!current) return null;
  for (let hops = 0; current.merged_into && hops < 4; hops++) {
    const next: Row | null = await db
      .prepare("SELECT id, merged_into FROM signatures WHERE id = ?1")
      .bind(current.merged_into)
      .first<Row>();
    if (!next) break;
    current = next;
  }
  return current.id as string;
}

export async function patchSignature(
  request: Request,
  env: Env,
  _ctx: ExecutionContext,
  now: number,
  params: string[],
): Promise<Response> {
  const id = params[0] ?? "";
  const body = await readBoundedJson(request, ADMIN_BODY_MAX_BYTES);
  if (!body.ok) return body.response;
  const validation = validateSignaturePatch(body.value);
  if (!validation.ok) return error("invalid_payload", validation.error);
  const patch = validation.value;

  const db = env.DB;
  const row = SIGNATURE_ID.test(id)
    ? await db.prepare("SELECT id, status, fixed_in_version FROM signatures WHERE id = ?1").bind(id).first<Row>()
    : null;
  if (!row) return error("not_found", "No such signature");

  // A fixed signature needs its version, or regressions could never be detected.
  const status = patch.status ?? row.status;
  const version = patch.fixed_in_version !== undefined ? patch.fixed_in_version : row.fixed_in_version;
  if (status === "fixed" && !version) {
    return error("invalid_payload", "fixed_in_version: required while status is fixed");
  }

  const sets: string[] = [];
  const binds: unknown[] = [];
  const set = (column: string, value: unknown) => sets.push(`${column} = ?${binds.push(value)}`);

  if (patch.status !== undefined) {
    set("status", patch.status);
    set("status_changed_at", now);
  }
  if (patch.fixed_in_version !== undefined) set("fixed_in_version", patch.fixed_in_version);
  if (patch.issue_url !== undefined) set("issue_url", patch.issue_url);
  if (patch.note !== undefined) set("note", patch.note);

  let newRoot: string | null = null;
  if (patch.merged_into !== undefined) {
    if (patch.merged_into !== null) {
      if (patch.merged_into === id) return error("invalid_payload", "merged_into: cannot merge into itself");
      newRoot = await mergeRoot(db, patch.merged_into);
      if (!newRoot) return error("invalid_payload", "merged_into: unknown signature");
      if (newRoot === id) return error("invalid_payload", "merged_into: would create a cycle");
    }
    set("merged_into", newRoot);
  }
  if (patch.resample) {
    set("sample_state", "none");
    set("lease_report", null);
    set("lease_expires", null);
  }

  const statements = [db.prepare(`UPDATE signatures SET ${sets.join(", ")} WHERE id = ?${binds.push(id)}`).bind(...binds)];
  // Keep chains flat: whatever was merged into this signature follows it.
  if (newRoot) statements.push(db.prepare("UPDATE signatures SET merged_into = ?1 WHERE merged_into = ?2").bind(newRoot, id));
  await db.batch(statements);
  return json(await signatureDetail(db, id) as Record<string, unknown>);
}

export async function getSignature(
  _request: Request,
  env: Env,
  _ctx: ExecutionContext,
  _now: number,
  params: string[],
): Promise<Response> {
  const id = params[0] ?? "";
  const detail = SIGNATURE_ID.test(id) ? await signatureDetail(env.DB, id) : null;
  if (!detail) return error("not_found", "No such signature");
  return json(detail);
}

// ---------------------------------------------------------------------------
// Reports and sealed pieces.

export async function getReport(
  _request: Request,
  env: Env,
  _ctx: ExecutionContext,
  _now: number,
  params: string[],
): Promise<Response> {
  const id = params[0] ?? "";
  const row = REPORT_ID.test(id) ? await env.DB.prepare("SELECT * FROM reports WHERE report_id = ?1").bind(id).first<Row>() : null;
  if (!row) return error("not_found", "No such report");
  // admin.v1#ReportDetail: the stored claim and what happened to it.
  return json({
    report_id: row.report_id,
    signature: row.signature,
    install_hash: row.install_hash,
    received_unix: row.received_at,
    // The version the signature of THIS report was computed under, not the
    // version this build of the Worker uses (design section 5.3).
    rules_version: row.rules_version,
    action: row.action,
    completed_unix: row.completed_at,
    claim: JSON.parse(row.claim as string),
    artifacts: storedArtifacts(row.artifacts),
  });
}

export async function getArtifact(
  _request: Request,
  env: Env,
  _ctx: ExecutionContext,
  _now: number,
  params: string[],
): Promise<Response> {
  const [reportId = "", name = ""] = params;
  if (!REPORT_ID.test(reportId) || !ARTIFACT_NAMES.includes(name as ArtifactName)) {
    return error("not_found", "No such piece");
  }
  const row = await env.DB.prepare("SELECT signature, build_id, artifacts FROM reports WHERE report_id = ?1")
    .bind(reportId)
    .first<{ signature: string; build_id: string; artifacts: string }>();
  const object = row ? await env.ARTIFACTS.get(artifactKey(row.signature, reportId, name)) : null;
  if (!row || !object) return error("not_found", "No such piece");
  const meta = (JSON.parse(row.artifacts) as Record<string, { sha256?: string }>)[name];
  const headers = new Headers({
    "content-type": "application/octet-stream",
    "content-length": String(object.size),
    "x-d2v-build-id": row.build_id,
  });
  if (meta?.sha256) headers.set("x-d2v-sha256", meta.sha256);
  return new Response(object.body, { headers });
}

// ---------------------------------------------------------------------------
// Bugs from the public site.

// admin.v1#BugItem: the contract keeps no note and no updated time on a bug.
const BUG_COLUMNS = "id, title, description, version, contact, lang, status, issue_url, created_at AS created_unix";

export function listBugs(request: Request, env: Env): Promise<Response> {
  return withBadQuery(async () => {
    const params = queryParams(new URL(request.url), ["status", "cursor", "limit"]);
    const status = optionalEnum(params, "status", ["open", "fixed", "ignored"]);
    const limit = limitParam(params);
    const cursor = decodeCursor(params.get("cursor"));
    const where: string[] = [];
    const binds: unknown[] = [];
    if (status) where.push(`status = ?${binds.push(status)}`);
    if (cursor) {
      const k = binds.push(cursor.k);
      const id = binds.push(cursor.id);
      where.push(`(created_at < ?${k} OR (created_at = ?${k} AND id > ?${id}))`);
    }
    const sql =
      `SELECT ${BUG_COLUMNS} FROM bugs ${where.length > 0 ? `WHERE ${where.join(" AND ")}` : ""} ` +
      `ORDER BY created_at DESC, id ASC LIMIT ?${binds.push(limit + 1)}`;
    const { results } = await env.DB.prepare(sql).bind(...binds).all<Row>();
    const page = results.slice(0, limit);
    const last = page[page.length - 1];
    const next = results.length > limit && last ? encodeCursor({ k: last.created_unix as number, id: last.id as string }) : null;
    return json({ items: page, next_cursor: next });
  });
}

async function bugById(db: D1Database, id: string): Promise<Row | null> {
  return BUG_ID.test(id) ? db.prepare(`SELECT ${BUG_COLUMNS} FROM bugs WHERE id = ?1`).bind(id).first<Row>() : null;
}

export async function getBug(
  _request: Request,
  env: Env,
  _ctx: ExecutionContext,
  _now: number,
  params: string[],
): Promise<Response> {
  const bug = await bugById(env.DB, params[0] ?? "");
  if (!bug) return error("not_found", "No such bug");
  return json(bug);
}

export async function patchBug(
  request: Request,
  env: Env,
  _ctx: ExecutionContext,
  now: number,
  params: string[],
): Promise<Response> {
  const id = params[0] ?? "";
  const body = await readBoundedJson(request, ADMIN_BODY_MAX_BYTES);
  if (!body.ok) return body.response;
  const validation = validateBugPatch(body.value);
  if (!validation.ok) return error("invalid_payload", validation.error);
  if (!(await bugById(env.DB, id))) return error("not_found", "No such bug");

  const sets: string[] = [];
  const binds: unknown[] = [];
  for (const column of ["status", "issue_url"] as const) {
    if (validation.value[column] !== undefined) sets.push(`${column} = ?${binds.push(validation.value[column])}`);
  }
  sets.push(`updated_at = ?${binds.push(now)}`);
  await env.DB.prepare(`UPDATE bugs SET ${sets.join(", ")} WHERE id = ?${binds.push(id)}`).bind(...binds).run();
  return json((await bugById(env.DB, id)) as Row);
}

// ---------------------------------------------------------------------------
// Builds, erasure, quotas and settings.

export async function postBuild(
  request: Request,
  env: Env,
  _ctx: ExecutionContext,
  now: number,
): Promise<Response> {
  const body = await readBoundedJson(request, ADMIN_BODY_MAX_BYTES);
  if (!body.ok) return body.response;
  const validation = validateBuildRegistration(body.value);
  if (!validation.ok) return error("invalid_payload", validation.error);
  const { build_id, version, channel } = validation.value;
  const [inserted, , row] = await env.DB.batch<Row>([
    env.DB.prepare(
      "INSERT INTO builds (build_id, version, channel, registered_at) VALUES (?1, ?2, ?3, ?4) ON CONFLICT (build_id) DO NOTHING",
    ).bind(build_id, version, channel, now),
    env.DB.prepare("UPDATE builds SET version = ?2, channel = ?3 WHERE build_id = ?1").bind(build_id, version, channel),
    env.DB.prepare("SELECT build_id, version, channel, registered_at AS registered_unix FROM builds WHERE build_id = ?1").bind(
      build_id,
    ),
  ]);
  const created = (inserted?.meta.changes ?? 0) > 0;
  // admin.v1#BuildRecord, 201 when this call created the row.
  return json(row?.results[0] as Row, created ? 201 : 200);
}


export interface Erasure {
  done: boolean;
  reports_deleted: number;
  artifacts_deleted: number;
}

// GDPR erasure: claims and sealed pieces of one installation. Aggregate
// counters (count, per-build counts) stay; distinct consoles lose this one.
// Bounded by a D1 statement budget: when it runs out, `done` is false and a
// new run continues (every step is safe to repeat).
export async function eraseInstall(env: Env, hash: string, budget = new StatementBudget()): Promise<Erasure> {
  const db = env.DB;
  const ofInstall = "SELECT report_id FROM reports WHERE install_hash = ?1";
  const erasure: Erasure = { done: false, reports_deleted: 0, artifacts_deleted: 0 };

  if (!budget.take(5)) return erasure;
  await db.batch([
    // A stored sample and a lease can belong to different installations (after
    // a resample): only what belongs to this one is cleared.
    db.prepare(
      `UPDATE signatures SET sample_report = NULL,
              sample_state = CASE WHEN sample_state = 'stored' THEN 'none' ELSE sample_state END
       WHERE sample_report IN (${ofInstall})`,
    ).bind(hash),
    db.prepare(
      `UPDATE signatures SET lease_report = NULL, lease_expires = NULL,
              sample_state = CASE WHEN sample_state = 'leased' THEN 'none' ELSE sample_state END
       WHERE lease_report IN (${ofInstall})`,
    ).bind(hash),
    db.prepare(
      "UPDATE signatures SET installs = MAX(installs - 1, 0) WHERE id IN (SELECT signature FROM signature_installs WHERE install_hash = ?1)",
    ).bind(hash),
    db.prepare("DELETE FROM signature_installs WHERE install_hash = ?1").bind(hash),
    db.prepare("DELETE FROM rate_counters WHERE subject = ?1").bind(hash),
  ]);

  // Pieces first; the rows go in one statement once none has pieces left.
  const pieces = await purgePieces(env, budget, "install_hash = ?1", [hash]);
  erasure.artifacts_deleted = pieces.deleted;
  if (!pieces.done || !budget.take(1)) return erasure;
  const rows = await db.prepare("DELETE FROM reports WHERE install_hash = ?1 AND artifacts = '{}'").bind(hash).run();
  erasure.reports_deleted = rows.meta.changes;
  erasure.done = true;
  return erasure;
}

// DELETE /v1/admin/installs/{install_id}: 200 when the erasure is complete,
// 202 with the same body (admin.v1#ForgetInstallResult) when the D1 statement
// budget ran out and the call has to be repeated; the counts are per call.
export async function deleteInstall(
  _request: Request,
  env: Env,
  _ctx: ExecutionContext,
  _now: number,
  params: string[],
): Promise<Response> {
  const installId = params[0] ?? "";
  if (!ADMIN_PATTERNS.InstallId.test(installId)) return error("invalid_payload", "install_id: must be 32 lower-case hex characters");
  const hash = await installHash(requireSecret(env.INSTALL_HASH_KEY, "INSTALL_HASH_KEY"), installId);
  const { done, ...counts } = await eraseInstall(env, hash);
  return json(counts, done ? 200 : 202);
}

// admin.v1#Settings: the kill switch and every cap.
function publicSettings(settings: Settings) {
  return { accepting: settings.accepting, disable_until_unix: settings.disable_until_unix, caps: settings.caps };
}

export async function getStats(
  _request: Request,
  env: Env,
  _ctx: ExecutionContext,
  now: number,
): Promise<Response> {
  const day = utcDay(now);
  const settings = await loadSettings(env.DB);
  const counters = await env.DB.prepare("SELECT scope, n FROM rate_counters WHERE subject = '*' AND day = ?1")
    .bind(day)
    .all<Row>();
  const used = (scope: string) => (counters.results.find((c) => c.scope === scope)?.n as number | undefined) ?? 0;
  // admin.v1#Stats: the global quota use of the current UTC day. The database
  // size is not part of it; the daily cron logs it (README, Capacity).
  return json({
    day,
    accepting: settings.accepting,
    usage: {
      claims: { used: used(SCOPE.globalClaims), cap: settings.caps.global_claims_per_day },
      artifact_bytes: { used: used(SCOPE.globalBytes), cap: settings.caps.global_artifact_bytes_per_day },
      new_signatures: { used: used(SCOPE.globalNewSignatures), cap: settings.caps.global_new_signatures_per_day },
      bugs: { used: used(SCOPE.globalBugs), cap: settings.caps.global_bugs_per_day },
    },
  });
}

export async function putSettings(request: Request, env: Env): Promise<Response> {
  const body = await readBoundedJson(request, ADMIN_BODY_MAX_BYTES);
  if (!body.ok) return body.response;
  const validation = validateSettingsPatch(body.value);
  if (!validation.ok) return error("invalid_payload", validation.error);
  await saveSettings(env.DB, validation.value);
  return json(publicSettings(await loadSettings(env.DB)));
}

// Admin routes (spec section 5.2), used by the maintainer's local tool only.
// Authorization: Bearer <token>; SHA-256(token) is compared in constant time
// with ADMIN_TOKEN_SHA256. The router checks it before any admin dispatch.

import { fromBase64Url, fromHex, sha256, timingSafeEqual, toBase64Url, utf8 } from "./crypto";
import type { Env } from "./env";
import { error, json } from "./http";
import { KINDS } from "./types";

export async function isAdmin(request: Request, env: Env): Promise<boolean> {
  const match = /^Bearer (\S{1,512})$/.exec(request.headers.get("authorization") ?? "");
  const expected = env.ADMIN_TOKEN_SHA256;
  if (!match || !expected || !/^[0-9a-fA-F]{64}$/.test(expected)) return false;
  return timingSafeEqual(await sha256(utf8(match[1]!)), fromHex(expected));
}

export function unauthorized(): Response {
  const response = error(401, "unauthorized", "A valid admin token is required");
  response.headers.set("www-authenticate", "Bearer");
  return response;
}

// ---------------------------------------------------------------------------
// Query helpers.

const SIGNATURE_ID = /^S[A-Z2-7]{15}$/;
const BUILD_ID = /^[0-9]+\.[0-9]+\.[0-9]+\+[0-9a-f]{12}(-dirty)?$/;

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
    if (e instanceof BadQuery) return error(400, "invalid_payload", e.message);
    throw e;
  });
}

// ---------------------------------------------------------------------------
// Signatures.

type Row = Record<string, unknown>;

function signatureSummary(row: Row) {
  return {
    id: row.id,
    kind: row.kind,
    status: row.status,
    count: row.count,
    installs: row.installs,
    first_seen: row.first_seen,
    last_seen: row.last_seen,
    first_build: row.first_build,
    last_build: row.last_build,
    status_changed_at: row.status_changed_at,
    fixed_in_version: row.fixed_in_version,
    merged_into: row.merged_into,
    issue_url: row.issue_url,
    note: row.note,
    sample_state: row.sample_state,
    sample_report: row.sample_report,
    rules_version: row.rules_version,
    canon: row.canon,
  };
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
      `SELECT * FROM signatures ${where.length > 0 ? `WHERE ${where.join(" AND ")}` : ""} ` +
      `ORDER BY ${sort} DESC, id ASC LIMIT ?${binds.push(limit + 1)}`;
    const { results } = await env.DB.prepare(sql).bind(...binds).all<Row>();
    const page = results.slice(0, limit);
    const last = page[page.length - 1];
    const next = results.length > limit && last ? encodeCursor({ k: last[sort] as number, id: last.id as string }) : null;
    return json({ items: page.map(signatureSummary), next_cursor: next });
  });
}

export async function signatureDetail(db: D1Database, id: string) {
  const row = await db.prepare("SELECT * FROM signatures WHERE id = ?1").bind(id).first<Row>();
  if (!row) return null;
  const [builds, children, recent] = await db.batch<Row>([
    db
      .prepare(
        "SELECT build_id, count, first_seen, last_seen FROM signature_builds WHERE signature = ?1 ORDER BY last_seen DESC, build_id",
      )
      .bind(id),
    db.prepare("SELECT id, count FROM signatures WHERE merged_into = ?1 ORDER BY count DESC, id").bind(id),
    db
      .prepare(
        `SELECT report_id, raw_signature, build_id, channel, kind, received_at, action, completed_at, sample_stored
         FROM reports WHERE signature = ?1 ORDER BY received_at DESC, report_id LIMIT 20`,
      )
      .bind(id),
  ]);
  const sampleReport = (row.sample_state === "leased" ? row.lease_report : row.sample_report) as string | null;
  const sampleArtifacts = sampleReport
    ? await db.prepare("SELECT artifacts FROM reports WHERE report_id = ?1").bind(sampleReport).first<{ artifacts: string }>()
    : null;
  const mergedFrom = children?.results ?? [];
  return {
    ...signatureSummary(row),
    lease_report: row.lease_report,
    lease_expires: row.lease_expires,
    sample_purged_at: row.sample_purged_at,
    total_count: (row.count as number) + mergedFrom.reduce((sum, c) => sum + (c.count as number), 0),
    merged_from: mergedFrom,
    builds: builds?.results ?? [],
    sample: {
      state: row.sample_state,
      report_id: sampleReport,
      lease_expires: row.lease_expires,
      purged_at: row.sample_purged_at,
      artifacts: sampleArtifacts ? JSON.parse(sampleArtifacts.artifacts) : {},
    },
    recent_reports: (recent?.results ?? []).map((r) => ({
      ...r,
      sample_stored: r.sample_stored === null ? null : r.sample_stored === 1,
    })),
  };
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
  if (!detail) return error(404, "not_found", "No such signature");
  return json({ signature: detail });
}

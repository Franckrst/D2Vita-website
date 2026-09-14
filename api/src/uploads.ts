// PUT /v1/reports/{report_id}/artifacts/{name} and POST …/complete (spec
// sections 4.8, 5.2, 5.4 step 5).
//
// Bodies are streamed straight into R2 (never buffered): the size is checked
// from Content-Length before anything is read, and a FixedLengthStream makes
// R2 refuse a body that does not match it. The SHA-256 is computed on the same
// stream. R2 custom metadata has to be given when the put starts, so the hash
// is recorded in D1 (reports.artifacts) instead of R2 metadata.
//
// The daily byte budget is charged for stored pieces only. A read-only check
// refuses before the body is read when the budget is already short; the atomic
// charge happens once the piece is stored. A failed attempt (connection lost,
// storage error) costs nothing, so a console can retry an interrupted piece
// within its caps, and repeating failures writes nothing to D1.

import { toHex } from "./crypto";
import { requireSecret, type Env } from "./env";
import { declaredLength, error, json, readBoundedJson } from "./http";
import {
  SCOPE,
  consumeAllOrNothing,
  hasRoom,
  installCaps,
  loadSettings,
  rateLimited,
  utcDay,
  type LimitCheck,
} from "./limits";
import { verifyUploadToken, type UploadGrant } from "./token";
import type { Channel } from "./types";
import { validateComplete } from "./validate";

export const MAX_ARTIFACT_BYTES = 2 * 1024 * 1024;
const COMPLETE_MAX_BYTES = 4096;

export function artifactKey(signature: string, reportId: string, name: string): string {
  return `artifacts/${signature}/${reportId}/${name}.sealed`;
}

interface ReportForUpload {
  signature: string;
  install_hash: string;
  build_id: string;
  channel: Channel;
  action: string;
  artifacts: string;
  completed_at: number | null;
  sample_stored: number | null;
}

async function authorize(request: Request, env: Env, reportId: string, now: number): Promise<UploadGrant | Response> {
  const match = /^D2V-Upload ([A-Za-z0-9_.-]{1,4096})$/.exec(request.headers.get("authorization") ?? "");
  if (!match) return error(403, "bad_token", "An upload token is required");
  const check = await verifyUploadToken(requireSecret(env.UPLOAD_TOKEN_KEY, "UPLOAD_TOKEN_KEY"), match[1]!, now);
  if (!check.ok) return error(403, "bad_token", check.reason === "expired" ? "Upload token expired" : "Invalid upload token");
  if (check.grant.report_id !== reportId) return error(403, "bad_token", "Upload token is for another report");
  return check.grant;
}

async function loadReport(db: D1Database, reportId: string): Promise<ReportForUpload | null> {
  return db
    .prepare(
      `SELECT signature, install_hash, build_id, channel, action, artifacts, completed_at, sample_stored
       FROM reports WHERE report_id = ?1`,
    )
    .bind(reportId)
    .first<ReportForUpload>();
}

type StreamResult =
  | { ok: true; sha256: string }
  // "body": the client's fault (length differs from Content-Length, connection
  // lost); "storage": R2 failed while the body was fine.
  | { ok: false; cause: "body" | "storage"; error: unknown };

// One pass: request body -> counting and hashing stream -> FixedLengthStream
// -> R2. The body is pulled one chunk at a time, fed to a native DigestStream
// and passed on (workerd cannot pipe a tee() branch into a FixedLengthStream).
// Counting here tells a bad body from a storage failure; FixedLengthStream
// makes the put fail, and store nothing, when the length is wrong.
async function streamToR2(
  bucket: R2Bucket,
  key: string,
  body: ReadableStream<Uint8Array> | null,
  length: number,
  customMetadata: Record<string, string>,
): Promise<StreamResult> {
  const source = (body ?? new ReadableStream<Uint8Array>({ start: (c) => c.close() })).getReader();
  const digest = new crypto.DigestStream("SHA-256");
  const hashed = digest.digest;
  hashed.catch(() => {}); // observed below on success; a failed upload must not leave it unhandled
  const hashWriter = digest.getWriter();
  let received = 0;
  let badBody = false;

  const counted = new ReadableStream<Uint8Array>({
    async pull(controller) {
      let next: ReadableStreamReadResult<Uint8Array>;
      try {
        next = await source.read();
      } catch (e) {
        badBody = true; // the client went away mid-body
        throw e;
      }
      if (next.done) {
        if (received !== length) {
          badBody = true;
          throw new Error("body shorter than Content-Length");
        }
        await hashWriter.close();
        controller.close();
        return;
      }
      received += next.value.byteLength;
      if (received > length) {
        badBody = true;
        source.cancel().catch(() => {});
        throw new Error("body longer than Content-Length");
      }
      await hashWriter.write(next.value);
      controller.enqueue(next.value);
    },
    cancel(reason) {
      return source.cancel(reason);
    },
  });

  const fixed = new FixedLengthStream(length);
  const [piped, put] = await Promise.allSettled([
    counted.pipeTo(fixed.writable),
    bucket.put(key, fixed.readable, { customMetadata, httpMetadata: { contentType: "application/octet-stream" } }),
  ]);
  if (piped.status === "fulfilled" && put.status === "fulfilled") {
    return { ok: true, sha256: toHex(new Uint8Array(await hashed)) };
  }
  hashWriter.abort().catch(() => {});
  // Defensive: never keep an object whose body failed.
  if (put.status === "fulfilled") await bucket.delete(key);
  const reason = piped.status === "rejected" ? piped.reason : (put as PromiseRejectedResult).reason;
  return { ok: false, cause: badBody ? "body" : "storage", error: reason };
}

function recordedPieces(report: { artifacts: string }): Record<string, unknown> {
  return JSON.parse(report.artifacts) as Record<string, unknown>;
}

export async function handleUpload(
  request: Request,
  env: Env,
  _ctx: ExecutionContext,
  now: number,
  params: string[],
): Promise<Response> {
  const [reportId = "", name = ""] = params;
  const declared = declaredLength(request);
  if (declared === null) return error(413, "length_required", "Content-Length is required");
  if (declared > MAX_ARTIFACT_BYTES) return error(413, "payload_too_large", "Piece is too large");

  const grant = await authorize(request, env, reportId, now);
  if (grant instanceof Response) return grant;
  // Past the token, answers are bound to the report (and to the piece once it
  // is known to be requested): a captured answer cannot serve another request.
  const piece = grant.artifacts.find((a) => a.name === name);
  if (!piece) return error(403, "bad_token", "This piece was not requested", { report_id: reportId });
  const bound = { report_id: reportId, name: piece.name };
  if (declared > piece.max_bytes) {
    return error(413, "payload_too_large", `Piece is limited to ${piece.max_bytes} bytes`, bound);
  }

  const report = await loadReport(env.DB, reportId);
  if (!report || report.action !== "upload") return error(403, "bad_token", "No upload is expected for this report", bound);
  if (report.completed_at !== null) return error(409, "exists", "This report is already complete", bound);
  if (recordedPieces(report)[name]) return error(409, "exists", "This piece is already stored", bound);

  const settings = await loadSettings(env.DB);
  const perInstall = installCaps(settings.caps, report.channel);
  const day = utcDay(now);
  const budget: LimitCheck[] = [
    { scope: SCOPE.installBytes, subject: report.install_hash, amount: declared, cap: perInstall.bytes },
    { scope: SCOPE.globalBytes, subject: "*", amount: declared, cap: settings.caps.global_artifact_bytes },
  ];
  if (!(await hasRoom(env.DB, day, budget))) return rateLimited(now, bound);

  const key = artifactKey(grant.signature, reportId, name);
  const stored = await streamToR2(env.ARTIFACTS, key, request.body, declared, {
    bytes: String(declared),
    build_id: report.build_id,
  });
  if (!stored.ok) {
    if (stored.cause === "body") return error(400, "invalid_payload", "Body does not match Content-Length", bound);
    console.error("artifact storage failed:", stored.error instanceof Error ? stored.error.message : String(stored.error));
    return error(500, "storage_unavailable", "The piece could not be stored, retry later", bound);
  }

  if (await consumeAllOrNothing(env.DB, day, budget)) {
    // Another upload took the last of the budget while this body streamed:
    // undo this one. If a concurrent PUT of the same piece was recorded
    // meanwhile, the object is that record's and stays.
    const current = await loadReport(env.DB, reportId);
    if (!current || !recordedPieces(current)[name]) await env.ARTIFACTS.delete(key);
    return rateLimited(now, bound);
  }

  await env.DB.prepare("UPDATE reports SET artifacts = json_set(artifacts, '$.' || ?2, json(?3)) WHERE report_id = ?1")
    .bind(reportId, name, JSON.stringify({ bytes: declared, sha256: stored.sha256, uploaded_at: now }))
    .run();
  return json({ report_id: reportId, name, bytes: declared, sha256: stored.sha256 }, 201);
}

export async function handleComplete(
  request: Request,
  env: Env,
  _ctx: ExecutionContext,
  now: number,
  params: string[],
): Promise<Response> {
  const [reportId = ""] = params;
  const grant = await authorize(request, env, reportId, now);
  if (grant instanceof Response) return grant;
  const bound = { report_id: reportId };

  const body = await readBoundedJson(request, COMPLETE_MAX_BYTES, bound);
  if (!body.ok) return body.response;
  const listed = validateComplete(
    body.value,
    grant.artifacts.map((a) => a.name),
  );
  if (!listed.ok) return error(400, "invalid_payload", listed.error, bound);

  const report = await loadReport(env.DB, reportId);
  if (!report || report.action !== "upload") return error(403, "bad_token", "No upload is expected for this report", bound);
  if (report.completed_at !== null) return json({ ...bound, sample_stored: report.sample_stored === 1 });

  const stored = recordedPieces(report);
  const missing = grant.artifacts.filter((a) => !stored[a.name]).map((a) => a.name);
  if (missing.length > 0) {
    return error(409, "incomplete", "Some requested pieces are not stored yet", { ...bound, missing });
  }

  const [, , readBack] = await env.DB.batch<{ sample_stored: number }>([
    env.DB.prepare(
      `UPDATE signatures SET sample_state = 'stored', sample_report = ?1, lease_report = NULL, lease_expires = NULL,
              sample_purged_at = NULL
       WHERE id = ?2 AND sample_state = 'leased' AND lease_report = ?1`,
    ).bind(reportId, grant.signature),
    env.DB.prepare(
      `UPDATE reports SET completed_at = ?3,
              sample_stored = EXISTS (SELECT 1 FROM signatures WHERE id = ?2 AND sample_state = 'stored' AND sample_report = ?1)
       WHERE report_id = ?1 AND completed_at IS NULL`,
    ).bind(reportId, grant.signature, now),
    env.DB.prepare("SELECT sample_stored FROM reports WHERE report_id = ?1").bind(reportId),
  ]);
  return json({ ...bound, sample_stored: readBack?.results[0]?.sample_stored === 1 });
}

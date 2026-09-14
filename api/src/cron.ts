// Daily retention job (spec section 5.6). The clock is injected so tests can
// run it at any date. Work per run is bounded; leftovers wait for the next run.
//
//  1. rate counters and IP salts from two days ago and older;
//  2. pieces of signatures fixed or ignored for 90 days (sample marked purged);
//  3. orphan pieces: upload window closed and not a stored sample;
//  4. claims older than 180 days, with their pieces (aggregate counters stay);
//  5. bugs older than one year.

import type { Env } from "./env";
import { utcDay } from "./limits";
import { artifactKey } from "./uploads";

const DAY = 86400;
export const RETENTION = {
  counterDays: 2,
  closedSignatureDays: 90,
  reportDays: 180,
  bugDays: 365,
  orphanGraceSeconds: 3600,
} as const;

const BATCH = 50; // stays far below D1's bound-parameter limit
const MAX_ROUNDS = 20;

export interface CronSummary {
  rate_counters: number;
  ip_salts: number;
  closed_signatures: number;
  closed_artifacts: number;
  orphan_artifacts: number;
  old_reports: number;
  old_report_artifacts: number;
  bugs: number;
}

interface PieceRow {
  report_id: string;
  signature: string;
  artifacts: string;
}

function keysOf(rows: PieceRow[]): string[] {
  return rows.flatMap((r) =>
    Object.keys(JSON.parse(r.artifacts) as object).map((name) => artifactKey(r.signature, r.report_id, name)),
  );
}

function placeholders(count: number, first = 1): string {
  return Array.from({ length: count }, (_, i) => `?${first + i}`).join(", ");
}

// Deletes the R2 pieces of the reports matching `where` and clears their
// piece records. Returns the number of objects deleted.
async function purgePieces(env: Env, where: string, binds: unknown[]): Promise<number> {
  let deleted = 0;
  for (let round = 0; round < MAX_ROUNDS; round++) {
    const { results } = await env.DB.prepare(
      `SELECT report_id, signature, artifacts FROM reports WHERE artifacts != '{}' AND ${where} LIMIT ${BATCH}`,
    )
      .bind(...binds)
      .all<PieceRow>();
    if (results.length === 0) break;
    const keys = keysOf(results);
    if (keys.length > 0) await env.ARTIFACTS.delete(keys);
    const ids = results.map((r) => r.report_id);
    await env.DB.prepare(`UPDATE reports SET artifacts = '{}' WHERE report_id IN (${placeholders(ids.length)})`)
      .bind(...ids)
      .run();
    deleted += keys.length;
  }
  return deleted;
}

export async function runCron(env: Env, now: number): Promise<CronSummary> {
  const db = env.DB;
  const summary: CronSummary = {
    rate_counters: 0,
    ip_salts: 0,
    closed_signatures: 0,
    closed_artifacts: 0,
    orphan_artifacts: 0,
    old_reports: 0,
    old_report_artifacts: 0,
    bugs: 0,
  };

  // 1. Counters and salts (IP hashes become unlinkable once the salt is gone).
  const cutoffDay = utcDay(now - RETENTION.counterDays * DAY);
  const [counters, salts] = await db.batch([
    db.prepare("DELETE FROM rate_counters WHERE day <= ?1").bind(cutoffDay),
    db.prepare("DELETE FROM settings WHERE substr(key, 1, 8) = 'ip_salt:' AND substr(key, 9) <= ?1").bind(cutoffDay),
  ]);
  summary.rate_counters = counters?.meta.changes ?? 0;
  summary.ip_salts = salts?.meta.changes ?? 0;

  // 2. Closed signatures.
  for (let round = 0; round < MAX_ROUNDS; round++) {
    const { results } = await db
      .prepare(
        `SELECT id FROM signatures
         WHERE status IN ('fixed', 'ignored') AND status_changed_at <= ?1 AND sample_purged_at IS NULL LIMIT ${BATCH}`,
      )
      .bind(now - RETENTION.closedSignatureDays * DAY)
      .all<{ id: string }>();
    if (results.length === 0) break;
    for (const { id } of results) {
      summary.closed_artifacts += await purgePieces(env, "signature = ?1", [id]);
      await db.prepare("UPDATE signatures SET sample_purged_at = ?1 WHERE id = ?2").bind(now, id).run();
      summary.closed_signatures++;
    }
  }

  // 3. Orphans: nobody can upload or complete after the window, and the
  // pieces never became a stored sample.
  summary.orphan_artifacts = await purgePieces(env, "COALESCE(sample_stored, 0) = 0 AND upload_expires < ?1", [
    now - RETENTION.orphanGraceSeconds,
  ]);

  // 4. Old claims.
  for (let round = 0; round < MAX_ROUNDS; round++) {
    const { results } = await db
      .prepare(`SELECT report_id, signature, artifacts FROM reports WHERE received_at <= ?1 LIMIT ${BATCH}`)
      .bind(now - RETENTION.reportDays * DAY)
      .all<PieceRow>();
    if (results.length === 0) break;
    const keys = keysOf(results);
    if (keys.length > 0) await env.ARTIFACTS.delete(keys);
    const ids = results.map((r) => r.report_id);
    const list = placeholders(ids.length, 2);
    await db.batch([
      // Open families ask for a fresh sample next time; closed ones keep
      // their state and are marked purged.
      db
        .prepare(
          `UPDATE signatures SET sample_state = CASE WHEN sample_state = 'stored' THEN 'none' ELSE sample_state END,
                  sample_report = NULL
           WHERE ?1 = ?1 AND sample_report IN (${list}) AND status IN ('open', 'regressed')`,
        )
        .bind(now, ...ids),
      db
        .prepare(`UPDATE signatures SET sample_purged_at = ?1 WHERE sample_report IN (${list}) AND status IN ('fixed', 'ignored')`)
        .bind(now, ...ids),
      db
        .prepare(
          `UPDATE signatures SET sample_state = 'none', lease_report = NULL, lease_expires = NULL
           WHERE ?1 = ?1 AND sample_state = 'leased' AND lease_report IN (${list})`,
        )
        .bind(now, ...ids),
      db.prepare(`DELETE FROM reports WHERE report_id IN (${placeholders(ids.length)})`).bind(...ids),
    ]);
    summary.old_reports += ids.length;
    summary.old_report_artifacts += keys.length;
  }

  // 5. Bugs.
  const bugs = await db.prepare("DELETE FROM bugs WHERE created_at <= ?1").bind(now - RETENTION.bugDays * DAY).run();
  summary.bugs = bugs.meta.changes;
  return summary;
}

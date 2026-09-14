// Daily retention job (spec section 5.6). The clock is injected so tests can
// run it at any date.
//
// A run spends at most a D1 statement budget (see maintenance.ts) and stops
// cleanly when it runs out; leftovers wait for the next day. Phases run in
// order of value, each safe to interrupt:
//  1. rate counters and IP salts from two days ago and older;
//  2. bugs older than one year;
//  3. claims older than 180 days: their pieces first, then the rows once no
//     old claim has pieces left, and the (signature, install_hash) links no
//     remaining claim refers to (aggregate counters, installs included, stay);
//  4. orphan pieces: upload window closed and not a stored sample;
//  5. pieces of signatures fixed or ignored for 90 days, then the signatures
//     are marked purged.

import type { Env } from "./env";
import { utcDay } from "./limits";
import { StatementBudget, purgePieces } from "./maintenance";

const DAY = 86400;
export const RETENTION = {
  counterDays: 2,
  closedSignatureDays: 90,
  reportDays: 180,
  bugDays: 365,
  orphanGraceSeconds: 3600,
} as const;

export interface CronSummary {
  complete: boolean; // false when the statement budget ran out (the next run continues)
  database_bytes: number | null; // D1 Free refuses every write at 500 MB
  rate_counters: number;
  ip_salts: number;
  bugs: number;
  old_reports: number;
  old_report_artifacts: number;
  install_links: number;
  orphan_artifacts: number;
  closed_signatures: number;
  closed_artifacts: number;
}

export async function runCron(env: Env, now: number, budget = new StatementBudget()): Promise<CronSummary> {
  const db = env.DB;
  const summary: CronSummary = {
    complete: false,
    database_bytes: null,
    rate_counters: 0,
    ip_salts: 0,
    bugs: 0,
    old_reports: 0,
    old_report_artifacts: 0,
    install_links: 0,
    orphan_artifacts: 0,
    closed_signatures: 0,
    closed_artifacts: 0,
  };

  // 1. Counters and salts (IP hashes become unlinkable once the salt is gone).
  if (!budget.take(2)) return summary;
  const cutoffDay = utcDay(now - RETENTION.counterDays * DAY);
  const [counters, salts] = await db.batch([
    db.prepare("DELETE FROM rate_counters WHERE day <= ?1").bind(cutoffDay),
    db.prepare("DELETE FROM settings WHERE substr(key, 1, 8) = 'ip_salt:' AND substr(key, 9) <= ?1").bind(cutoffDay),
  ]);
  summary.rate_counters = counters?.meta.changes ?? 0;
  summary.ip_salts = salts?.meta.changes ?? 0;
  summary.database_bytes = salts?.meta.size_after ?? null;

  // 2. Bugs.
  if (!budget.take(1)) return summary;
  const bugs = await db.prepare("DELETE FROM bugs WHERE created_at <= ?1").bind(now - RETENTION.bugDays * DAY).run();
  summary.bugs = bugs.meta.changes;

  // 3. Old claims. Rows are deleted only once every old claim has lost its
  // pieces, so an interrupted run never leaves R2 objects without a record.
  const reportCutoff = now - RETENTION.reportDays * DAY;
  const oldPieces = await purgePieces(env, budget, "received_at <= ?1", [reportCutoff]);
  summary.old_report_artifacts = oldPieces.deleted;
  if (!oldPieces.done || !budget.take(5)) return summary;
  const oldClaims = "SELECT report_id FROM reports WHERE received_at <= ?1 AND artifacts = '{}'";
  const [, , , links, deleted] = await db.batch([
    // Open families ask for a fresh sample next time; closed ones keep their
    // state and are marked purged.
    db
      .prepare(
        `UPDATE signatures SET sample_state = CASE WHEN sample_state = 'stored' THEN 'none' ELSE sample_state END,
                sample_report = NULL
         WHERE status IN ('open', 'regressed') AND sample_report IN (${oldClaims})`,
      )
      .bind(reportCutoff),
    db
      .prepare(
        `UPDATE signatures SET sample_purged_at = COALESCE(sample_purged_at, ?2)
         WHERE status IN ('fixed', 'ignored') AND sample_report IN (${oldClaims})`,
      )
      .bind(reportCutoff, now),
    db
      .prepare(
        `UPDATE signatures SET sample_state = 'none', lease_report = NULL, lease_expires = NULL
         WHERE sample_state = 'leased' AND lease_report IN (${oldClaims})`,
      )
      .bind(reportCutoff),
    // Pseudonymous per-console links are kept only as long as a claim of that
    // console for that family is. A console seen again later is counted again
    // in `installs`, like any console new to the family.
    db
      .prepare(
        `DELETE FROM signature_installs
         WHERE (signature, install_hash) IN (SELECT signature, install_hash FROM reports WHERE received_at <= ?1 AND artifacts = '{}')
           AND NOT EXISTS (SELECT 1 FROM reports r
                           WHERE r.install_hash = signature_installs.install_hash AND r.signature = signature_installs.signature
                             AND r.received_at > ?1)`,
      )
      .bind(reportCutoff),
    db.prepare("DELETE FROM reports WHERE received_at <= ?1 AND artifacts = '{}'").bind(reportCutoff),
  ]);
  summary.install_links = links?.meta.changes ?? 0;
  summary.old_reports = deleted?.meta.changes ?? 0;

  // 4. Orphans: nobody can upload or complete after the window, and the
  // pieces never became a stored sample.
  const orphans = await purgePieces(env, budget, "COALESCE(sample_stored, 0) = 0 AND upload_expires < ?1", [
    now - RETENTION.orphanGraceSeconds,
  ]);
  summary.orphan_artifacts = orphans.deleted;
  if (!orphans.done) return summary;

  // 5. Closed signatures, all at once rather than one by one.
  const closedCutoff = now - RETENTION.closedSignatureDays * DAY;
  const closed = "status IN ('fixed', 'ignored') AND status_changed_at <= ?1 AND sample_purged_at IS NULL";
  const closedPieces = await purgePieces(env, budget, `signature IN (SELECT id FROM signatures WHERE ${closed})`, [closedCutoff]);
  summary.closed_artifacts = closedPieces.deleted;
  if (!closedPieces.done || !budget.take(1)) return summary;
  const marked = await db.prepare(`UPDATE signatures SET sample_purged_at = ?2 WHERE ${closed}`).bind(closedCutoff, now).run();
  summary.closed_signatures = marked.meta.changes;

  summary.complete = true;
  return summary;
}

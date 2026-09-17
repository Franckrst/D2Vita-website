// Bounded maintenance shared by the retention cron and GDPR erasure.
//
// D1 on the Workers Free plan allows 50 queries per invocation, and the D1
// limits apply to each statement of a batch. Long jobs therefore spend a
// statement budget below that and stop cleanly when it runs out; every step
// leaves the data consistent, so the next run picks up where this one stopped.

import type { Env } from "./env";
import { artifactKey } from "./uploads";

export const STATEMENT_BUDGET = 40;

export class StatementBudget {
  #left: number;

  constructor(statements = STATEMENT_BUDGET) {
    this.#left = statements;
  }

  // Reserves `n` statements; false, and nothing reserved, when they are not left.
  take(n: number): boolean {
    if (n > this.#left) return false;
    this.#left -= n;
    return true;
  }
}

const REPORTS_PER_ROUND = 50; // report ids bound in one UPDATE (D1: 100 parameters)

interface PieceRow {
  report_id: string;
  signature: string;
  artifacts: string;
}

// Deletes the R2 pieces of the reports matching `where` (SQL on `reports`,
// with `binds`) and clears their piece records, one round of up to 50 reports
// and two statements at a time. `done` is false when the budget ran out
// before every matching report was processed.
export async function purgePieces(
  env: Env,
  budget: StatementBudget,
  where: string,
  binds: unknown[],
): Promise<{ deleted: number; done: boolean }> {
  let deleted = 0;
  for (;;) {
    if (!budget.take(2)) return { deleted, done: false };
    const { results } = await env.DB.prepare(
      `SELECT report_id, signature, artifacts FROM reports WHERE artifacts != '{}' AND (${where}) LIMIT ${REPORTS_PER_ROUND}`,
    )
      .bind(...binds)
      .all<PieceRow>();
    if (results.length === 0) return { deleted, done: true };
    const keys = results.flatMap((r) =>
      Object.keys(JSON.parse(r.artifacts) as object).map((name) => artifactKey(r.signature, r.report_id, name)),
    );
    // Objects first: an interrupted round leaves records that the next run
    // clears (deleting a missing key is harmless).
    if (keys.length > 0) await env.ARTIFACTS.delete(keys);
    const ids = results.map((r) => r.report_id);
    await env.DB.prepare(`UPDATE reports SET artifacts = '{}' WHERE report_id IN (${ids.map((_, i) => `?${i + 1}`).join(", ")})`)
      .bind(...ids)
      .run();
    deleted += keys.length;
  }
}

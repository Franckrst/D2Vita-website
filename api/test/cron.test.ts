import { createExecutionContext, createScheduledController, waitOnExecutionContext } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { beforeEach, describe, expect, it } from "vitest";
import { runCron } from "../src/cron";
import worker from "../src/index";
import { utcDay } from "../src/limits";
import { artifactKey } from "../src/uploads";
import { ulid } from "./fixtures";
import { NOW, resetDatabase, signatureRow } from "./helpers";

const DAY = 86400;
const T = NOW + 400 * DAY; // cron run time

let seq = 0;
function sigId(): string {
  seq++;
  return `S${"A".repeat(14)}${"BCDEFGHIJKLMNOPQRSTUVWXYZ"[seq % 25]}`;
}

async function insertSignature(o: {
  id?: string;
  status?: string;
  status_changed_at?: number | null;
  sample_state?: string;
  sample_report?: string | null;
  count?: number;
}): Promise<string> {
  const id = o.id ?? sigId();
  await env.DB.prepare(
    `INSERT INTO signatures (id, kind, canon, rules_version, count, installs, first_seen, last_seen, status, status_changed_at,
                             sample_state, sample_report)
     VALUES (?1, 'hang', 'hang|-', 1, ?2, 1, 0, 0, ?3, ?4, ?5, ?6)`,
  )
    .bind(id, o.count ?? 5, o.status ?? "open", o.status_changed_at ?? null, o.sample_state ?? "none", o.sample_report ?? null)
    .run();
  return id;
}

async function insertReport(o: {
  signature: string;
  received_at: number;
  pieces?: string[];
  sample_stored?: number | null;
  completed_at?: number | null;
  upload_expires?: number | null;
}): Promise<string> {
  const reportId = ulid();
  const artifacts: Record<string, unknown> = {};
  for (const name of o.pieces ?? []) {
    artifacts[name] = { bytes: 3, sha256: "00", uploaded_at: o.received_at };
    await env.ARTIFACTS.put(artifactKey(o.signature, reportId, name), new Uint8Array([1, 2, 3]));
  }
  await env.DB.prepare(
    `INSERT INTO reports (report_id, ingest_nonce, signature, raw_signature, install_hash, build_id, channel, kind,
                          received_at, claim, decision, action, requested, upload_expires, artifacts, completed_at, sample_stored)
     VALUES (?1, 'n', ?2, ?2, 'h', '0.1.0+ab12cd34ef56', 'release', 'hang', ?3, '{}', '{}', ?4, NULL, ?5, ?6, ?7, ?8)`,
  )
    .bind(
      reportId,
      o.signature,
      o.received_at,
      o.pieces?.length ? "upload" : "count_only",
      o.upload_expires ?? null,
      JSON.stringify(artifacts),
      o.completed_at ?? null,
      o.sample_stored ?? null,
    )
    .run();
  return reportId;
}

async function objectCount(prefix = "artifacts/"): Promise<number> {
  return (await env.ARTIFACTS.list({ prefix })).objects.length;
}

beforeEach(async () => {
  await resetDatabase();
});

describe("runCron retention (spec section 5.6)", () => {
  it("deletes rate counters and IP salts from two days ago and older", async () => {
    const days = [0, 1, 2, 10].map((d) => utcDay(T - d * DAY));
    await env.DB.batch(
      days.flatMap((day) => [
        env.DB.prepare("INSERT INTO rate_counters (scope, subject, day, n) VALUES ('claims:global', '*', ?1, 1)").bind(day),
        env.DB.prepare("INSERT INTO settings (key, value) VALUES (?1, 'salt')").bind(`ip_salt:${day}`),
      ]),
    );
    await env.DB.prepare("INSERT INTO settings (key, value) VALUES ('accepting', 'true')").run();
    const summary = await runCron(env, T);
    expect(summary).toMatchObject({ rate_counters: 2, ip_salts: 2 });
    const counters = await env.DB.prepare("SELECT day FROM rate_counters ORDER BY day DESC").all();
    expect(counters.results).toEqual([{ day: days[0] }, { day: days[1] }]);
    const settings = await env.DB.prepare("SELECT key FROM settings ORDER BY key").all();
    expect(settings.results).toEqual([{ key: "accepting" }, { key: `ip_salt:${days[1]}` }, { key: `ip_salt:${days[0]}` }]);
  });

  it("deletes the pieces of signatures fixed or ignored for 90 days, once", async () => {
    const fixed = await insertSignature({ status: "fixed", status_changed_at: T - 91 * DAY, sample_state: "stored" });
    const sample = await insertReport({ signature: fixed, received_at: T - 100 * DAY, pieces: ["crash_txt", "crash_log"], sample_stored: 1 });
    await env.DB.prepare("UPDATE signatures SET sample_report = ?1 WHERE id = ?2").bind(sample, fixed).run();
    await insertReport({ signature: fixed, received_at: T - 95 * DAY, pieces: ["boot_progress"], sample_stored: 1 });
    const recent = await insertSignature({ status: "ignored", status_changed_at: T - 89 * DAY });
    await insertReport({ signature: recent, received_at: T - 100 * DAY, pieces: ["crash_log"], sample_stored: 1 });
    const open = await insertSignature({ status: "open", status_changed_at: T - 300 * DAY });
    await insertReport({ signature: open, received_at: T - 100 * DAY, pieces: ["crash_log"], sample_stored: 1 });

    const summary = await runCron(env, T);
    expect(summary).toMatchObject({ closed_signatures: 1, closed_artifacts: 3 });
    expect(await objectCount(`artifacts/${fixed}/`)).toBe(0);
    expect(await objectCount(`artifacts/${recent}/`)).toBe(1);
    expect(await objectCount(`artifacts/${open}/`)).toBe(1);
    expect(await signatureRow(fixed)).toMatchObject({ sample_state: "stored", sample_report: sample, sample_purged_at: T });
    const pieces = await env.DB.prepare("SELECT artifacts FROM reports WHERE signature = ?1").bind(fixed).all();
    expect(pieces.results).toEqual([{ artifacts: "{}" }, { artifacts: "{}" }]);

    // Re-running does not reprocess it; a day later the ignored one reaches 90 days.
    expect(await runCron(env, T)).toMatchObject({ closed_signatures: 0, closed_artifacts: 0 });
    expect(await runCron(env, T + DAY)).toMatchObject({ closed_signatures: 1, closed_artifacts: 1 });
    expect(await objectCount(`artifacts/${recent}/`)).toBe(0);
    expect(await objectCount(`artifacts/${open}/`)).toBe(1);
  });

  it("deletes orphan pieces once the upload window has closed, keeping stored samples", async () => {
    const sig = await insertSignature({ status: "open" });
    const expired = await insertReport({ signature: sig, received_at: T - DAY, pieces: ["crash_txt"], upload_expires: T - 7200 });
    const lostLease = await insertReport({
      signature: sig,
      received_at: T - DAY,
      pieces: ["crash_log", "boot_progress"],
      upload_expires: T - 7200,
      completed_at: T - 7300,
      sample_stored: 0,
    });
    const inGrace = await insertReport({ signature: sig, received_at: T - 1000, pieces: ["crash_txt"], upload_expires: T - 600 });
    const stored = await insertReport({
      signature: sig,
      received_at: T - 100 * DAY,
      pieces: ["crash_log"],
      upload_expires: T - 99 * DAY,
      completed_at: T - 99 * DAY,
      sample_stored: 1,
    });

    const summary = await runCron(env, T);
    expect(summary).toMatchObject({ orphan_artifacts: 3 });
    expect(await objectCount(`artifacts/${sig}/${expired}/`)).toBe(0);
    expect(await objectCount(`artifacts/${sig}/${lostLease}/`)).toBe(0);
    expect(await objectCount(`artifacts/${sig}/${inGrace}/`)).toBe(1);
    expect(await objectCount(`artifacts/${sig}/${stored}/`)).toBe(1);
    const rows = await env.DB.prepare("SELECT report_id, artifacts FROM reports WHERE artifacts = '{}' ORDER BY report_id").all();
    expect(rows.results.map((r) => r.report_id)).toEqual([expired, lostLease].sort());
  });

  it("deletes claims older than 180 days with their pieces, keeping aggregate counters", async () => {
    const open = await insertSignature({ status: "open", sample_state: "stored", count: 9 });
    const oldSample = await insertReport({ signature: open, received_at: T - 181 * DAY, pieces: ["crash_log"], sample_stored: 1 });
    await env.DB.prepare("UPDATE signatures SET sample_report = ?1 WHERE id = ?2").bind(oldSample, open).run();
    const fresh = await insertReport({ signature: open, received_at: T - 10 * DAY });
    const closed = await insertSignature({ status: "fixed", status_changed_at: T - 10 * DAY, sample_state: "stored", count: 4 });
    const closedSample = await insertReport({ signature: closed, received_at: T - 200 * DAY, pieces: ["crash_txt"], sample_stored: 1 });
    await env.DB.prepare("UPDATE signatures SET sample_report = ?1 WHERE id = ?2").bind(closedSample, closed).run();

    const summary = await runCron(env, T);
    expect(summary).toMatchObject({ old_reports: 2, old_report_artifacts: 2 });
    const remaining = await env.DB.prepare("SELECT report_id FROM reports").all();
    expect(remaining.results).toEqual([{ report_id: fresh }]);
    expect(await objectCount()).toBe(0);
    expect(await signatureRow(open)).toMatchObject({ count: 9, sample_state: "none", sample_report: null });
    expect(await signatureRow(closed)).toMatchObject({ count: 4, sample_state: "stored", sample_purged_at: T });
  });

  it("deletes bugs older than one year", async () => {
    const insert = (id: string, created: number) =>
      env.DB.prepare(
        "INSERT INTO bugs (id, title, description, version, lang, created_at, updated_at) VALUES (?1, 't', 'd', '0.1.0', 'en', ?2, ?2)",
      ).bind(id, created);
    await env.DB.batch([insert("BAAAAAAAAAAAAAAAA", T - 366 * DAY), insert("BBBBBBBBBBBBBBBBB", T - 364 * DAY)]);
    expect(await runCron(env, T)).toMatchObject({ bugs: 1 });
    expect((await env.DB.prepare("SELECT id FROM bugs").all()).results).toEqual([{ id: "BBBBBBBBBBBBBBBBB" }]);
  });

  it("is run by the scheduled handler with the trigger time", async () => {
    await env.DB.prepare(
      "INSERT INTO bugs (id, title, description, version, lang, created_at, updated_at) VALUES ('BAAAAAAAAAAAAAAAA', 't', 'd', '0.1.0', 'en', ?1, ?1)",
    )
      .bind(T - 400 * DAY)
      .run();
    const ctx = createExecutionContext();
    await worker.scheduled!(createScheduledController({ scheduledTime: T * 1000, cron: "0 3 * * *" }), env, ctx);
    await waitOnExecutionContext(ctx);
    expect((await env.DB.prepare("SELECT COUNT(*) AS n FROM bugs").first())).toEqual({ n: 0 });
  });
});

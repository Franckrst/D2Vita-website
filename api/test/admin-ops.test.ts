import { env } from "cloudflare:workers";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { eraseInstall } from "../src/admin";
import { installHash } from "../src/crypto";
import { StatementBudget } from "../src/maintenance";
import { admin, adminRequest, sendClaim, sigOf } from "./admin-helpers";
import { BUILD_ID, bugBody, haltClaim, installId } from "./fixtures";
import {
  NOW,
  bytesOf,
  call,
  claimRequest,
  completeRequest,
  putRequest,
  registerBuild,
  resetDatabase,
  signatureRow,
  signedJson,
  storeSample,
} from "./helpers";

beforeEach(async () => {
  await resetDatabase();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("POST /v1/admin/builds", () => {
  it("registers a build, after which its claims are accepted", async () => {
    expect((await call(claimRequest(haltClaim()))).status).toBe(403);
    const res = await admin("POST", "/v1/admin/builds", { build_id: BUILD_ID, version: "0.1.0", channel: "test" });
    expect(res.status).toBe(201);
    expect(res.body).toEqual({
      v: 1,
      created: true,
      build: { build_id: BUILD_ID, version: "0.1.0", channel: "test", registered_at: NOW },
    });
    expect((await call(claimRequest(haltClaim()))).status).toBe(200);
  });

  it("is idempotent and can change the channel", async () => {
    await admin("POST", "/v1/admin/builds", { build_id: BUILD_ID, version: "0.1.0", channel: "test" });
    const again = await admin("POST", "/v1/admin/builds", { build_id: BUILD_ID, version: "0.1.0", channel: "release" }, NOW + 99);
    expect(again.status).toBe(200);
    expect(again.body).toEqual({
      v: 1,
      created: false,
      build: { build_id: BUILD_ID, version: "0.1.0", channel: "release", registered_at: NOW },
    });
  });

  it("refuses an invalid registration", async () => {
    expect((await admin("POST", "/v1/admin/builds", { build_id: BUILD_ID, version: "0.2.0", channel: "dev" })).status).toBe(400);
    const noLength = adminRequest("POST", "/v1/admin/builds", { build_id: BUILD_ID, version: "0.1.0", channel: "dev" });
    noLength.headers.delete("content-length");
    expect((await call(noLength)).status).toBe(413);
  });
});

describe("DELETE /v1/admin/installs/{install_id}", () => {
  it("erases the reports and pieces of one installation, keeping aggregate counters", async () => {
    await registerBuild();
    const x = installId();
    const y = installId();
    const { decision } = await storeSample(haltClaim({ install_id: x }));
    await sendClaim(haltClaim({ install_id: x }));
    const kept = haltClaim({ install_id: y });
    await sendClaim(kept);
    const sig = await sigOf(haltClaim());
    const hashX = await installHash(env.INSTALL_HASH_KEY!, x);
    expect(await signatureRow(sig)).toMatchObject({ count: 3, installs: 2, sample_state: "stored" });

    const res = await admin("DELETE", `/v1/admin/installs/${x}`);
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ v: 1, done: true, deleted_reports: 2, deleted_artifacts: 3 });

    const reports = await env.DB.prepare("SELECT report_id FROM reports").all();
    expect(reports.results).toEqual([{ report_id: kept.report_id }]);
    const listing = await env.ARTIFACTS.list({ prefix: `artifacts/${sig}/${decision.report_id}/` });
    expect(listing.objects).toHaveLength(0);
    expect(await signatureRow(sig)).toMatchObject({ count: 3, installs: 1, sample_state: "none", sample_report: null });
    const installs = await env.DB.prepare("SELECT COUNT(*) AS n FROM signature_installs WHERE install_hash = ?1").bind(hashX).first();
    expect(installs).toEqual({ n: 0 });
    const counters = await env.DB.prepare("SELECT COUNT(*) AS n FROM rate_counters WHERE subject = ?1").bind(hashX).first();
    expect(counters).toEqual({ n: 0 });

    // A new crash of the same family asks for a fresh sample.
    expect((await sendClaim(haltClaim())).action).toBe("upload");
  });

  it("keeps the lease another installation holds after a resample", async () => {
    await registerBuild();
    const x = installId();
    const y = installId();
    const { decision: sample } = await storeSample(haltClaim({ install_id: x }));
    const sig = sample.signature as string;
    expect((await admin("PATCH", `/v1/admin/signatures/${sig}`, { resample: true })).status).toBe(200);
    const leased = await sendClaim(haltClaim({ install_id: y }));
    expect(leased.action).toBe("upload");

    expect((await admin("DELETE", `/v1/admin/installs/${x}`)).status).toBe(200);
    expect(await signatureRow(sig)).toMatchObject({ sample_state: "leased", lease_report: leased.report_id, sample_report: null });

    // Y still stores the fresh sample.
    const names = (leased.upload.artifacts as Array<{ name: string }>).map((a) => a.name);
    for (const name of names) {
      expect((await call(putRequest(leased.report_id, name, bytesOf(100), leased.upload.token))).status).toBe(201);
    }
    const done = await call(completeRequest(leased.report_id, leased.upload.token, { v: 1, artifacts: names }));
    expect(await signedJson(done)).toMatchObject({ sample_stored: true });
    expect(await signatureRow(sig)).toMatchObject({ sample_state: "stored", sample_report: leased.report_id });
  });

  it("keeps another installation's stored sample when the erased one held the lease", async () => {
    await registerBuild();
    const x = installId();
    const y = installId();
    const { decision: sample } = await storeSample(haltClaim({ install_id: y }));
    const sig = sample.signature as string;
    await admin("PATCH", `/v1/admin/signatures/${sig}`, { resample: true });
    expect((await sendClaim(haltClaim({ install_id: x }))).action).toBe("upload");

    expect((await admin("DELETE", `/v1/admin/installs/${x}`)).status).toBe(200);
    expect(await signatureRow(sig)).toMatchObject({
      sample_state: "none",
      lease_report: null,
      lease_expires: null,
      sample_report: sample.report_id,
    });
    // The next crash of the family is asked for the sample again.
    expect((await sendClaim(haltClaim())).action).toBe("upload");
  });

  it("answers 400 for a malformed id and zeros for an unknown installation", async () => {
    expect((await admin("DELETE", "/v1/admin/installs/NOT-AN-ID")).status).toBe(400);
    expect((await admin("DELETE", `/v1/admin/installs/${installId()}`)).body).toEqual({
      v: 1,
      done: true,
      deleted_reports: 0,
      deleted_artifacts: 0,
    });
  });

  it("works in bounded steps: a run out of statements is not done, and the next one finishes", async () => {
    await registerBuild();
    const x = installId();
    for (const code of [1, 2, 3]) await storeSample(haltClaim({ install_id: x, features: { code, frames: [] } }));
    const hash = await installHash(env.INSTALL_HASH_KEY!, x);

    const partial = await eraseInstall(env, hash, new StatementBudget(7));
    expect(partial).toEqual({ done: false, deleted_reports: 0, deleted_artifacts: 9 });
    // Rows stay until their pieces are known to be gone.
    const rows = await env.DB.prepare("SELECT COUNT(*) AS n FROM reports WHERE install_hash = ?1").bind(hash).first();
    expect(rows).toEqual({ n: 3 });

    const rest = await admin("DELETE", `/v1/admin/installs/${x}`);
    expect(rest).toEqual({ status: 200, body: { v: 1, done: true, deleted_reports: 3, deleted_artifacts: 0 } });
    expect((await env.ARTIFACTS.list({ prefix: "artifacts/" })).objects).toHaveLength(0);
  });
});

describe("GET /v1/admin/stats", () => {
  it("reports today's quota consumption, totals and settings", async () => {
    await registerBuild();
    const decision = await sendClaim(haltClaim());
    await sendClaim(haltClaim());
    await call(putRequest(decision.report_id, "crash_txt", bytesOf(300), decision.upload.token));
    vi.spyOn(globalThis, "fetch").mockResolvedValue(Response.json({ success: true }));
    const text = JSON.stringify(bugBody());
    await call(
      new Request("https://api.test/v1/bugs", {
        method: "POST",
        headers: { "content-type": "application/json", "content-length": String(text.length) },
        body: text,
      }),
    );

    const res = await admin("GET", "/v1/admin/stats");
    expect(res.status).toBe(200);
    expect(res.body).toEqual({
      v: 1,
      day: "2026-09-13",
      now: NOW,
      today: {
        claims: { used: 2, cap: 2000 },
        artifact_bytes: { used: 300, cap: 300 * 1024 * 1024 },
        new_signatures: { used: 1, cap: 200 },
        bugs: { used: 1, cap: 100 },
      },
      totals: { signatures: 1, reports: 2, stored_samples: 0, bugs: 1, builds: 1 },
      settings: expect.objectContaining({ accepting: true, disable_until_unix: null }),
    });
    expect(JSON.stringify(res.body)).not.toContain("ip_salt");
  });
});

describe("PUT /v1/admin/settings", () => {
  it("switches claims off and on and changes caps", async () => {
    await registerBuild();
    const off = await admin("PUT", "/v1/admin/settings", {
      accepting: false,
      disable_until_unix: NOW + 3600,
      caps: { install_claims: 5 },
    });
    expect(off.status).toBe(200);
    expect(off.body.settings).toMatchObject({ accepting: false, disable_until_unix: NOW + 3600 });
    expect(off.body.settings.caps).toMatchObject({ install_claims: 5, ip_claims: 10 });
    expect(JSON.stringify(off.body)).not.toContain("salt");

    const refused = await call(claimRequest(haltClaim()));
    expect(refused.status).toBe(503);
    expect(await signedJson(refused)).toMatchObject({ disable_until_unix: NOW + 3600 });

    await admin("PUT", "/v1/admin/settings", { accepting: true, disable_until_unix: null });
    expect((await call(claimRequest(haltClaim()))).status).toBe(200);
  });

  it("refuses invalid settings", async () => {
    expect((await admin("PUT", "/v1/admin/settings", { accepting: "no" })).status).toBe(400);
    expect((await admin("PUT", "/v1/admin/settings", { caps: { made_up: 1 } })).status).toBe(400);
  });
});

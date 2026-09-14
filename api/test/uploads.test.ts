import { env } from "cloudflare:workers";
import { beforeEach, describe, expect, it } from "vitest";
import { sha256, toHex } from "../src/crypto";
import { createUploadToken } from "../src/token";
import { haltClaim } from "./fixtures";
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
} from "./helpers";

const KiB = 1024;

interface Granted {
  reportId: string;
  signature: string;
  token: string;
  names: string[];
}

async function newUploadDecision(overrides: Record<string, unknown> = {}): Promise<Granted> {
  const claim = haltClaim(overrides);
  const decision = await signedJson(await call(claimRequest(claim)));
  expect(decision.action).toBe("upload");
  return {
    reportId: claim.report_id as string,
    signature: decision.signature,
    token: decision.upload.token,
    names: decision.upload.artifacts.map((a: { name: string }) => a.name),
  };
}

beforeEach(async () => {
  await resetDatabase();
  await registerBuild();
});

describe("PUT /v1/reports/{id}/artifacts/{name}", () => {
  it("streams a requested piece to R2 and answers a signed 201", async () => {
    const g = await newUploadDecision();
    const body = bytesOf(5000);
    const res = await call(putRequest(g.reportId, "crash_txt", body, g.token));
    expect(res.status).toBe(201);
    const expectedSha = toHex(await sha256(body));
    expect(await signedJson(res)).toEqual({
      v: 1,
      report_id: g.reportId,
      name: "crash_txt",
      bytes: 5000,
      sha256: expectedSha,
    });

    const object = await env.ARTIFACTS.get(`artifacts/${g.signature}/${g.reportId}/crash_txt.sealed`);
    expect(object).not.toBeNull();
    expect(object!.customMetadata).toEqual({ bytes: "5000", build_id: "0.1.0+ab12cd34ef56" });
    expect(new Uint8Array(await object!.arrayBuffer())).toEqual(body);

    const row = await env.DB.prepare("SELECT artifacts FROM reports WHERE report_id = ?1").bind(g.reportId).first<{ artifacts: string }>();
    expect(JSON.parse(row!.artifacts)).toEqual({ crash_txt: { bytes: 5000, sha256: expectedSha, uploaded_at: NOW } });
  });

  it("refuses an expired token", async () => {
    const g = await newUploadDecision();
    const res = await call(putRequest(g.reportId, "crash_txt", bytesOf(10), g.token), NOW + 1801);
    expect(res.status).toBe(403);
    expect(await signedJson(res)).toMatchObject({ error: "bad_token" });
  });

  it("refuses a forged token", async () => {
    const g = await newUploadDecision();
    const forged = await createUploadToken("aa".repeat(32), {
      report_id: g.reportId,
      signature: g.signature,
      artifacts: [{ name: "crash_txt", max_bytes: 999999999 }],
      expires_unix: NOW + 99999,
    });
    const res = await call(putRequest(g.reportId, "crash_txt", bytesOf(10), forged));
    expect(res.status).toBe(403);
    expect(await signedJson(res)).toMatchObject({ error: "bad_token" });
  });

  it("refuses a token of another report, a missing token and another scheme", async () => {
    const a = await newUploadDecision();
    const b = await newUploadDecision({ features: { code: 7, frames: [] } });
    for (const req of [
      putRequest(b.reportId, "crash_txt", bytesOf(10), a.token),
      putRequest(a.reportId, "crash_txt", bytesOf(10), null),
      putRequest(a.reportId, "crash_txt", bytesOf(10), null, { authorization: `Bearer ${a.token}` }),
    ]) {
      const res = await call(req);
      expect(res.status).toBe(403);
      expect(await signedJson(res)).toMatchObject({ error: "bad_token" });
    }
  });

  it("refuses a piece that was not requested", async () => {
    const g = await newUploadDecision();
    expect(g.names).not.toContain("dump");
    const res = await call(putRequest(g.reportId, "dump", bytesOf(10), g.token));
    expect(res.status).toBe(403);
    expect(await signedJson(res)).toMatchObject({ error: "bad_token" });
  });

  it("refuses a valid token for a report that got count_only", async () => {
    await newUploadDecision();
    const claim = haltClaim();
    const decision = await signedJson(await call(claimRequest(claim)));
    expect(decision.action).toBe("count_only");
    const token = await createUploadToken(env.UPLOAD_TOKEN_KEY!, {
      report_id: claim.report_id as string,
      signature: decision.signature,
      artifacts: [{ name: "crash_txt", max_bytes: 65536 }],
      expires_unix: NOW + 1800,
    });
    expect((await call(putRequest(claim.report_id as string, "crash_txt", bytesOf(10), token))).status).toBe(403);
  });

  it("answers 413 without Content-Length (documented choice) and above the piece cap", async () => {
    const g = await newUploadDecision();
    const noLength = await call(putRequest(g.reportId, "crash_txt", bytesOf(10), g.token, { "content-length": null }));
    expect(noLength.status).toBe(413);
    expect(await signedJson(noLength)).toMatchObject({ error: "length_required" });
    const tooBig = await call(putRequest(g.reportId, "crash_txt", bytesOf(64 * KiB + 1), g.token));
    expect(tooBig.status).toBe(413);
    expect(await signedJson(tooBig)).toMatchObject({ error: "payload_too_large" });
    expect(await env.ARTIFACTS.head(`artifacts/${g.signature}/${g.reportId}/crash_txt.sealed`)).toBeNull();
  });

  // Note: the local R2 simulator prints two "uncaught exception: Network
  // connection lost" lines for this case even when every promise is observed
  // (checked with a bare FixedLengthStream + put); they are expected.
  it("refuses a body that does not match its Content-Length and stores nothing", async () => {
    const g = await newUploadDecision();
    const res = await call(putRequest(g.reportId, "crash_txt", bytesOf(5000), g.token, { "content-length": "6000" }));
    expect(res.status).toBe(400);
    expect(await signedJson(res)).toMatchObject({ error: "invalid_payload" });
    expect(await env.ARTIFACTS.head(`artifacts/${g.signature}/${g.reportId}/crash_txt.sealed`)).toBeNull();
    const row = await env.DB.prepare("SELECT artifacts FROM reports WHERE report_id = ?1").bind(g.reportId).first();
    expect(row).toEqual({ artifacts: "{}" });
  });

  it("answers 409 exists on a second PUT of the same piece", async () => {
    const g = await newUploadDecision();
    expect((await call(putRequest(g.reportId, "crash_log", bytesOf(100), g.token))).status).toBe(201);
    const again = await call(putRequest(g.reportId, "crash_log", bytesOf(100, 9), g.token));
    expect(again.status).toBe(409);
    expect(await signedJson(again)).toMatchObject({ error: "exists" });
    const object = await env.ARTIFACTS.get(`artifacts/${g.signature}/${g.reportId}/crash_log.sealed`);
    expect(new Uint8Array(await object!.arrayBuffer())).toEqual(bytesOf(100));
  });

  it("enforces the per-installation and global daily byte caps with 429", async () => {
    await env.DB.prepare("INSERT INTO settings (key, value) VALUES ('cap:install_artifact_bytes', '1000')").run();
    const g = await newUploadDecision();
    expect((await call(putRequest(g.reportId, "crash_txt", bytesOf(600), g.token))).status).toBe(201);
    const refused = await call(putRequest(g.reportId, "crash_log", bytesOf(600), g.token));
    expect(refused.status).toBe(429);
    expect(await signedJson(refused)).toMatchObject({ error: "rate_limited", retry_after_s: expect.any(Number) });

    // The refused attempt above did not consume the global budget: 600 used so far.
    await env.DB.prepare("INSERT INTO settings (key, value) VALUES ('cap:global_artifact_bytes', '1000')").run();
    const other = await newUploadDecision({ features: { code: 8, frames: [] } });
    expect((await call(putRequest(other.reportId, "crash_txt", bytesOf(600), other.token))).status).toBe(429);
    const global = await env.DB.prepare("SELECT n FROM rate_counters WHERE scope = 'bytes:global'").first();
    expect(global).toEqual({ n: 600 });
  });
});

describe("POST /v1/reports/{id}/complete", () => {
  async function uploadAll(g: Granted) {
    for (const name of g.names) {
      expect((await call(putRequest(g.reportId, name, bytesOf(200), g.token))).status).toBe(201);
    }
  }

  it("stores the sample once every requested piece is uploaded", async () => {
    const g = await newUploadDecision();
    await uploadAll(g);
    const res = await call(completeRequest(g.reportId, g.token, { v: 1, artifacts: g.names }), NOW + 60);
    expect(res.status).toBe(200);
    expect(await signedJson(res)).toEqual({ v: 1, sample_stored: true });
    expect(await signatureRow(g.signature)).toMatchObject({
      sample_state: "stored",
      sample_report: g.reportId,
      lease_report: null,
      lease_expires: null,
    });
    const report = await env.DB.prepare("SELECT completed_at, sample_stored FROM reports WHERE report_id = ?1").bind(g.reportId).first();
    expect(report).toEqual({ completed_at: NOW + 60, sample_stored: 1 });
  });

  it("accepts the piece list as objects with sizes too", async () => {
    const g = await newUploadDecision();
    await uploadAll(g);
    const artifacts = g.names.map((name) => ({ name, bytes: 200 }));
    expect(await signedJson(await call(completeRequest(g.reportId, g.token, { v: 1, artifacts })))).toEqual({
      v: 1,
      sample_stored: true,
    });
  });

  it("answers 409 incomplete while a requested piece is missing", async () => {
    const g = await newUploadDecision();
    await call(putRequest(g.reportId, "crash_txt", bytesOf(10), g.token));
    const res = await call(completeRequest(g.reportId, g.token, { v: 1, artifacts: ["crash_txt"] }));
    expect(res.status).toBe(409);
    expect(await signedJson(res)).toMatchObject({ error: "incomplete", missing: ["crash_log", "boot_progress"] });
    expect(await signatureRow(g.signature)).toMatchObject({ sample_state: "leased" });
  });

  it("is idempotent and closes the report to further uploads", async () => {
    const g = await newUploadDecision();
    await uploadAll(g);
    await call(completeRequest(g.reportId, g.token, { v: 1, artifacts: g.names }));
    const again = await call(completeRequest(g.reportId, g.token, { v: 1, artifacts: g.names }));
    expect(again.status).toBe(200);
    expect(await signedJson(again)).toEqual({ v: 1, sample_stored: true });
    await env.ARTIFACTS.delete(`artifacts/${g.signature}/${g.reportId}/crash_txt.sealed`);
    const put = await call(putRequest(g.reportId, "crash_txt", bytesOf(10), g.token));
    expect(put.status).toBe(409);
  });

  it("reports sample_stored false when the lease was lost meanwhile", async () => {
    const g = await newUploadDecision();
    await uploadAll(g);
    await env.DB.prepare("UPDATE signatures SET sample_state = 'none', lease_report = NULL WHERE id = ?1").bind(g.signature).run();
    expect(await signedJson(await call(completeRequest(g.reportId, g.token, { v: 1, artifacts: g.names })))).toEqual({
      v: 1,
      sample_stored: false,
    });
    expect(await signatureRow(g.signature)).toMatchObject({ sample_state: "none", sample_report: null });
  });

  it("refuses a bad token with 403 and a malformed body with 400", async () => {
    const g = await newUploadDecision();
    const res = await call(completeRequest(g.reportId, null, { v: 1, artifacts: [] }));
    expect(res.status).toBe(403);
    expect(await signedJson(res)).toMatchObject({ error: "bad_token" });
    const bad = await call(completeRequest(g.reportId, g.token, { v: 1, artifacts: ["dump"] }));
    expect(bad.status).toBe(400);
    expect(await signedJson(bad)).toMatchObject({ error: "invalid_payload" });
  });
});

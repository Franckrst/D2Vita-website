// Every answer of the API, held against the contract schemas: one success body
// per route and one case per error code, each validated with Ajv 2020 in strict
// mode. test/helpers.ts runs the same check on every call the other test files
// make; this file makes the coverage explicit and complete.
import { env } from "cloudflare:workers";
import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { admin, adminRequest, sendClaim } from "./admin-helpers";
import { ERROR_CODES, contractErrors, successRef } from "./contract";
import { BUILD_ID, bugBody, haltClaim, haltFeatures, installId, ulid } from "./fixtures";
import {
  NOW,
  bytesOf,
  call,
  claimRequest,
  completeRequest,
  putRequest,
  registerBuild,
  resetDatabase,
  signedJson,
  storeSample,
} from "./helpers";

// Filled by the cases below and checked once at the end.
const seenBodies = new Set<string>();
const seenErrors = new Set<string>();

async function expectBody(ref: string, response: Response): Promise<Record<string, any>> {
  const body = (await response.clone().json()) as Record<string, any>;
  expect(contractErrors(ref, body), `${ref}: ${JSON.stringify(body)}`).toBeNull();
  seenBodies.add(ref);
  return body;
}

async function expectError(code: string, response: Response): Promise<Record<string, any>> {
  const body = await expectBody("admin.v1#ErrorBody", response);
  expect(body.error, JSON.stringify(body)).toBe(code);
  seenErrors.add(code);
  return body;
}

function bugRequest(body: Record<string, unknown>): Request {
  const text = JSON.stringify(body);
  return new Request("https://api.test/v1/bugs", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "content-length": String(new TextEncoder().encode(text).byteLength),
      "cf-connecting-ip": "203.0.113.5",
    },
    body: text,
  });
}

beforeEach(async () => {
  await resetDatabase();
  await registerBuild();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("console answers", () => {
  it("decision, ArtifactStored and CompleteResponse", async () => {
    const claim = haltClaim();
    const decision = await expectBody("decision.v1", await call(claimRequest(claim)));
    expect(decision.action).toBe("upload");

    const put = await call(putRequest(claim.report_id as string, "crash_txt", bytesOf(500), decision.upload.token));
    const stored = await expectBody("decision.v1#ArtifactStored", put);
    expect(stored).toEqual({ v: 1, report_id: claim.report_id, name: "crash_txt", bytes: 500 });

    for (const name of ["crash_log", "boot_progress"]) {
      await call(putRequest(claim.report_id as string, name, bytesOf(500), decision.upload.token));
    }
    const done = await call(
      completeRequest(claim.report_id as string, decision.upload.token, {
        v: 1,
        artifacts: ["crash_txt", "crash_log", "boot_progress"],
      }),
    );
    const complete = await expectBody("decision.v1#CompleteResponse", done);
    expect(complete).toEqual({ v: 1, report_id: claim.report_id, sample_stored: true });

    // count_only is the other half of decision.v1.
    const again = await expectBody("decision.v1", await call(claimRequest(haltClaim())));
    expect(again).toMatchObject({ action: "count_only", upload: null });
  });
});

describe("site answers", () => {
  it("BugCreated", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(Response.json({ success: true }));
    const created = await expectBody("bug.v1#BugCreated", await call(bugRequest(bugBody())));
    expect(created.id).toMatch(/^B/);
  });
});

describe("admin answers", () => {
  it("BuildRecord, both created and already registered", async () => {
    const registration = { build_id: "0.2.0+0123456789ab", version: "0.2.0", channel: "test" };
    const created = await call(adminRequest("POST", "/v1/admin/builds", registration));
    expect(created.status).toBe(201);
    expect(await expectBody("admin.v1#BuildRecord", created)).toEqual({
      v: 1,
      build_id: "0.2.0+0123456789ab",
      version: "0.2.0",
      channel: "test",
      registered_unix: NOW,
    });
    const again = await call(adminRequest("POST", "/v1/admin/builds", { ...registration, channel: "dev" }), NOW + 5);
    expect(again.status).toBe(200);
    await expectBody("admin.v1#BuildRecord", again);
  });

  it("SignatureList, SignatureDetail and the patched detail", async () => {
    const { decision } = await storeSample(haltClaim());
    const list = await call(adminRequest("GET", "/v1/admin/signatures?sort=count"));
    const items = await expectBody("admin.v1#SignatureList", list);
    expect(items.items).toHaveLength(1);

    const detail = await expectBody(
      "admin.v1#SignatureDetail",
      await call(adminRequest("GET", `/v1/admin/signatures/${decision.signature}`)),
    );
    expect(detail).toMatchObject({ id: decision.signature, count: 1, installs: 1, sample_state: "stored" });
    expect(detail.sample_artifacts.map((a: { name: string }) => a.name).sort()).toEqual([
      "boot_progress",
      "crash_log",
      "crash_txt",
    ]);
    expect(detail.builds).toEqual([{ build_id: BUILD_ID, count: 1, first_seen_unix: NOW, last_seen_unix: NOW }]);
    expect(detail.recent_reports).toEqual([
      { report_id: decision.report_id, build_id: BUILD_ID, received_unix: NOW, action: "upload" },
    ]);

    const patched = await expectBody(
      "admin.v1#SignatureDetail",
      await call(
        adminRequest("PATCH", `/v1/admin/signatures/${decision.signature}`, {
          status: "fixed",
          fixed_in_version: "0.2.0",
          issue_url: "https://github.com/Franckrst/D2Vita/issues/1",
          note: "one line",
        }),
        NOW + 60,
      ),
    );
    expect(patched).toMatchObject({ status: "fixed", fixed_in_version: "0.2.0", note: "one line" });
  });

  it("ReportDetail", async () => {
    const claim = haltClaim({ redactions: 2 });
    const decision = await sendClaim(claim);
    const report = await expectBody(
      "admin.v1#ReportDetail",
      await call(adminRequest("GET", `/v1/admin/reports/${claim.report_id}`)),
    );
    expect(report).toMatchObject({
      report_id: claim.report_id,
      signature: decision.signature,
      action: "upload",
      completed_unix: null,
      rules_version: 1,
      artifacts: [],
    });
    expect(report.claim).toEqual(claim);
  });

  it("BugList and BugDetail", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(Response.json({ success: true }));
    const { id } = (await (await call(bugRequest(bugBody()))).json()) as { id: string };
    await expectBody("admin.v1#BugList", await call(adminRequest("GET", "/v1/admin/bugs")));
    const detail = await expectBody("admin.v1#BugDetail", await call(adminRequest("GET", `/v1/admin/bugs/${id}`)));
    expect(detail).toMatchObject({ id, status: "open", issue_url: null, created_unix: NOW });
    await expectBody(
      "admin.v1#BugDetail",
      await call(adminRequest("PATCH", `/v1/admin/bugs/${id}`, { status: "fixed" }), NOW + 10),
    );
  });

  it("ForgetInstallResult, Stats and Settings", async () => {
    const install = installId();
    await storeSample(haltClaim({ install_id: install }));
    const erased = await expectBody(
      "admin.v1#ForgetInstallResult",
      await call(adminRequest("DELETE", `/v1/admin/installs/${install}`)),
    );
    expect(erased).toEqual({ v: 1, reports_deleted: 1, artifacts_deleted: 3 });

    const stats = await expectBody("admin.v1#Stats", await call(adminRequest("GET", "/v1/admin/stats")));
    expect(stats).toMatchObject({ day: "2026-09-13", accepting: true });
    expect(stats.usage.claims).toEqual({ used: 1, cap: 2000 });

    const settings = await expectBody(
      "admin.v1#Settings",
      await call(adminRequest("PUT", "/v1/admin/settings", { accepting: false, disable_until_unix: NOW + 60 })),
    );
    expect(settings).toMatchObject({ accepting: false, disable_until_unix: NOW + 60 });
    expect(settings.caps.install_claims_per_day).toBe(3);
  });
});

describe("error bodies", () => {
  it("invalid_payload, payload_too_large and not_accepting on claims", async () => {
    await expectError("invalid_payload", await call(claimRequest(haltClaim({ kind: "meteor" }))));
    await expectError(
      "payload_too_large",
      await call(claimRequest(haltClaim(), { headers: { "content-length": null } })),
    );
    await env.DB.prepare("INSERT INTO settings (key, value) VALUES ('accepting', 'false')").run();
    const paused = await expectError("not_accepting", await call(claimRequest(haltClaim())));
    expect(paused.disable_until_unix).toBe(NOW + 86400);
  });

  it("rate_limited carries retry_after_s", async () => {
    await env.DB.prepare("INSERT INTO settings (key, value) VALUES ('cap:global_claims_per_day', '0')").run();
    const refused = await expectError("rate_limited", await call(claimRequest(haltClaim())));
    expect(refused.retry_after_s).toBeGreaterThan(0);
  });

  it("bad_token, exists and incomplete on the piece routes, each naming the piece", async () => {
    const claim = haltClaim();
    const decision = await sendClaim(claim);
    const reportId = claim.report_id as string;
    const token = decision.upload.token as string;

    const noToken = await expectError("bad_token", await call(putRequest(reportId, "crash_txt", bytesOf(100), null)));
    expect(noToken).toMatchObject({ report_id: reportId, artifact: "crash_txt" });

    expect((await call(putRequest(reportId, "crash_txt", bytesOf(100), token))).status).toBe(201);
    const twice = await expectError("exists", await call(putRequest(reportId, "crash_txt", bytesOf(100), token)));
    expect(twice).toMatchObject({ report_id: reportId, artifact: "crash_txt" });

    const tooBig = await expectError(
      "payload_too_large",
      await call(putRequest(reportId, "crash_log", bytesOf(70000), token)),
    );
    expect(tooBig).toMatchObject({ report_id: reportId, artifact: "crash_log" });

    const early = await expectError(
      "incomplete",
      await call(completeRequest(reportId, token, { v: 1, artifacts: ["crash_txt"] })),
    );
    expect(early).toMatchObject({ report_id: reportId });
  });

  it("invalid_payload for a path parameter that is not a report id or a piece name", async () => {
    const claim = haltClaim();
    const decision = await sendClaim(claim);
    const token = decision.upload.token as string;
    await expectError("invalid_payload", await call(putRequest("not-a-report", "crash_txt", bytesOf(100), token)));
    await expectError(
      "invalid_payload",
      await call(putRequest(claim.report_id as string, "savegame", bytesOf(100), token)),
    );
    await expectError("invalid_payload", await call(completeRequest("not-a-report", token, { v: 1, artifacts: [] })));
  });

  it("unauthorized, not_found and method_not_allowed", async () => {
    await expectError("unauthorized", await call(adminRequest("GET", "/v1/admin/stats", undefined, null)));
    await expectError("not_found", await call(adminRequest("GET", "/v1/admin/signatures/SAAAAAAAAAAAAAAA")));
    await expectError("not_found", await call(new Request("https://api.test/v1/nope")));
    await expectError("method_not_allowed", await call(new Request("https://api.test/v1/claims")));
  });

  it("turnstile", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(Response.json({ success: false }));
    await expectError("turnstile", await call(bugRequest(bugBody())));
  });

  it("internal_error when a secret is missing, still signed and still a contract body", async () => {
    const broken = { ...env, INSTALL_HASH_KEY: undefined };
    const response = await call(claimRequest(haltClaim()), NOW, broken);
    await expectError("internal_error", response);
    await signedJson(response);
  });

  it("truncates a message to the 500 characters of the contract", async () => {
    const long = await call(
      claimRequest(haltClaim({ features: haltFeatures({ location: "x".repeat(900) }) })),
    );
    const body = await expectError("invalid_payload", long);
    expect(body.message.length).toBeLessThanOrEqual(500);
  });
});

describe("coverage", () => {
  it("has exercised every error code and every body of the contract", () => {
    expect([...seenErrors].sort()).toEqual([...ERROR_CODES].sort());
    const bodies = [
      "admin.v1#BugDetail",
      "admin.v1#BugList",
      "admin.v1#BuildRecord",
      "admin.v1#ErrorBody",
      "admin.v1#ForgetInstallResult",
      "admin.v1#ReportDetail",
      "admin.v1#SignatureDetail",
      "admin.v1#SignatureList",
      "admin.v1#Settings",
      "admin.v1#Stats",
      "bug.v1#BugCreated",
      "decision.v1",
      "decision.v1#ArtifactStored",
      "decision.v1#CompleteResponse",
    ];
    expect([...seenBodies].sort()).toEqual(bodies.sort());
  });

  it("knows a success definition for every route of the contract", () => {
    expect(successRef("POST", "/v1/claims", 200)).toBe("decision.v1");
    expect(successRef("GET", "/v1/admin/stats", 200)).toBe("admin.v1#Stats");
    expect(successRef("GET", "/v1/admin/nope", 200)).toBeUndefined();
  });
});

afterAll(() => {
  // A route or code added without a case here fails the coverage test above.
  expect(seenErrors.size).toBe(ERROR_CODES.length);
});

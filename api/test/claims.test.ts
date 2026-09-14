import { env, exports } from "cloudflare:workers";
import { beforeEach, describe, expect, it } from "vitest";
import { canon, signatureId } from "../src/signature";
import type { Claim } from "../src/types";
import { BUILD_ID, haltClaim, hostFaultClaim, installId, ulid } from "./fixtures";
import { NOW, call, claimRequest, registerBuild, resetDatabase, signatureRow, signedJson } from "./helpers";

const KiB = 1024;
const MiB = 1024 * KiB;

async function sigOf(claim: Record<string, unknown>): Promise<string> {
  return signatureId(canon(claim as unknown as Claim));
}

beforeEach(async () => {
  await resetDatabase();
  await registerBuild();
});

describe("POST /v1/claims: refusals", () => {
  it("refuses an unknown build with a signed 403 unknown_build", async () => {
    const res = await call(claimRequest(haltClaim({ build_id: "9.9.9+000000000000" })));
    expect(res.status).toBe(403);
    expect(await signedJson(res)).toMatchObject({ v: 1, error: "unknown_build" });
  });

  it("refuses an invalid claim with a signed 400 invalid_payload", async () => {
    const res = await call(claimRequest(haltClaim({ kind: "meteor" })));
    expect(res.status).toBe(400);
    expect(await signedJson(res)).toMatchObject({ v: 1, error: "invalid_payload" });
  });

  it("requires console headers matching the claim", async () => {
    const claim = haltClaim();
    const variants: Array<Record<string, string | null>> = [
      { "x-d2v-client": null },
      { "x-d2v-client": "d2vita/0.1.0+ffffffffffff" },
      { "x-d2v-install": null },
      { "x-d2v-install": installId() },
    ];
    for (const headers of variants) {
      const res = await call(claimRequest(claim, { headers }));
      expect(res.status, JSON.stringify(headers)).toBe(400);
      expect(await signedJson(res)).toMatchObject({ error: "invalid_payload" });
    }
  });

  it("refuses a body over 16 KiB, and a missing Content-Length, with 413", async () => {
    const big = claimRequest(haltClaim(), { headers: { "content-length": String(16 * KiB + 1) } });
    const res = await call(big);
    expect(res.status).toBe(413);
    expect(await signedJson(res)).toMatchObject({ error: "payload_too_large" });
    const noLength = await call(claimRequest(haltClaim(), { headers: { "content-length": null } }));
    expect(noLength.status).toBe(413);
  });

  it("answers 503 not_accepting with disable_until_unix when the kill switch is off", async () => {
    await env.DB.batch([
      env.DB.prepare("INSERT INTO settings (key, value) VALUES ('accepting', 'false')"),
      env.DB.prepare("INSERT INTO settings (key, value) VALUES ('disable_until_unix', ?1)").bind(String(NOW + 7200)),
    ]);
    const res = await call(claimRequest(haltClaim()));
    expect(res.status).toBe(503);
    expect(await signedJson(res)).toMatchObject({ v: 1, error: "not_accepting", disable_until_unix: NOW + 7200 });
    const count = await env.DB.prepare("SELECT COUNT(*) AS n FROM reports").first();
    expect(count).toEqual({ n: 0 });
  });

  it("defaults disable_until_unix to one day when the switch has no end date", async () => {
    await env.DB.prepare("INSERT INTO settings (key, value) VALUES ('accepting', 'false')").run();
    const body = await signedJson(await call(claimRequest(haltClaim())));
    expect(body.disable_until_unix).toBe(NOW + 86400);
  });
});

describe("POST /v1/claims: deduplication (spec section 5.4)", () => {
  it("asks a new signature for one sample and leases it", async () => {
    const claim = haltClaim();
    const res = await call(claimRequest(claim));
    expect(res.status).toBe(200);
    const decision = await signedJson(res);
    const sig = await sigOf(claim);
    expect(decision).toEqual({
      v: 1,
      report_id: claim.report_id,
      signature: sig,
      action: "upload",
      upload: {
        token: expect.stringMatching(/^eyJyIjoi/),
        expires_unix: NOW + 1800,
        artifacts: [
          { name: "crash_txt", max_bytes: 64 * KiB },
          { name: "crash_log", max_bytes: 64 * KiB },
          { name: "boot_progress", max_bytes: 320 * KiB },
        ],
      },
      retry_after_s: null,
      disable_until_unix: null,
    });
    expect(await signatureRow(sig)).toMatchObject({
      kind: "halt",
      canon: "halt|1420|-|Game+0x1fedf4,Game+0x451c23,Game+0x44f570",
      rules_version: 1,
      count: 1,
      installs: 1,
      first_seen: NOW,
      last_seen: NOW,
      status: "open",
      sample_state: "leased",
      lease_report: claim.report_id,
      lease_expires: NOW + 1800,
    });
    const perBuild = await env.DB.prepare("SELECT build_id, count FROM signature_builds WHERE signature = ?1")
      .bind(sig)
      .all();
    expect(perBuild.results).toEqual([{ build_id: BUILD_ID, count: 1 }]);
    const report = await env.DB.prepare("SELECT signature, raw_signature, action, build_id, kind FROM reports WHERE report_id = ?1")
      .bind(claim.report_id)
      .first();
    expect(report).toEqual({ signature: sig, raw_signature: sig, action: "upload", build_id: BUILD_ID, kind: "halt" });
  });

  it("requests the dump for host_fault and only pieces the console listed within caps", async () => {
    const withDump = await signedJson(await call(claimRequest(hostFaultClaim())));
    expect(withDump.upload.artifacts).toEqual([
      { name: "dump", max_bytes: 2 * MiB },
      { name: "crash_log", max_bytes: 64 * KiB },
      { name: "boot_progress", max_bytes: 320 * KiB },
    ]);

    await resetDatabase();
    await registerBuild();
    const withheld = hostFaultClaim({
      artifacts: [
        { name: "crash_log", bytes: 70 * KiB }, // above its cap: not requested
        { name: "boot_progress", bytes: 1000 },
      ],
    });
    const decision = await signedJson(await call(claimRequest(withheld)));
    expect(decision.upload.artifacts).toEqual([{ name: "boot_progress", max_bytes: 320 * KiB }]);
  });

  it("counts a known signature without asking for another sample", async () => {
    const first = haltClaim();
    await call(claimRequest(first));
    const second = haltClaim();
    const decision = await signedJson(await call(claimRequest(second)));
    expect(decision).toEqual({
      v: 1,
      report_id: second.report_id,
      signature: await sigOf(first),
      action: "count_only",
      upload: null,
      retry_after_s: null,
      disable_until_unix: null,
    });
    expect(await signatureRow(await sigOf(first))).toMatchObject({
      count: 2,
      installs: 2,
      sample_state: "leased",
      lease_report: first.report_id,
    });
  });

  it("counts distinct consoles once", async () => {
    const install = installId();
    await call(claimRequest(haltClaim({ install_id: install })));
    await call(claimRequest(haltClaim({ install_id: install })));
    expect(await signatureRow(await sigOf(haltClaim()))).toMatchObject({ count: 2, installs: 1 });
  });

  it("replays the same report_id with the same decision, bytes and signature, without counting", async () => {
    const claim = haltClaim();
    const first = await call(claimRequest(claim));
    const firstBody = await first.clone().text();
    const firstSignature = first.headers.get("x-d2v-signature");
    const counters = await env.DB.prepare("SELECT scope, n FROM rate_counters ORDER BY scope").all();

    const again = await call(claimRequest(claim), NOW + 60);
    expect(again.status).toBe(200);
    expect(await again.clone().text()).toBe(firstBody);
    expect(again.headers.get("x-d2v-signature")).toBe(firstSignature);
    await signedJson(again);
    expect(await signatureRow(await sigOf(claim))).toMatchObject({ count: 1, installs: 1 });
    expect((await env.DB.prepare("SELECT scope, n FROM rate_counters ORDER BY scope").all()).results).toEqual(
      counters.results,
    );
  });

  it("refuses a report_id already used by another installation", async () => {
    const claim = haltClaim();
    await call(claimRequest(claim));
    const res = await call(claimRequest({ ...claim, install_id: installId() }));
    expect(res.status).toBe(400);
    expect(await signedJson(res)).toMatchObject({ error: "invalid_payload" });
  });

  it("gives exactly one upload decision to 30 simultaneous claims of a new signature", async () => {
    const claims = Array.from({ length: 30 }, () => haltClaim());
    const responses = await Promise.all(claims.map((c) => call(claimRequest(c))));
    const decisions = await Promise.all(responses.map((r) => signedJson(r)));
    expect(responses.map((r) => r.status)).toEqual(Array(30).fill(200));
    expect(decisions.filter((d) => d.action === "upload")).toHaveLength(1);
    expect(decisions.filter((d) => d.action === "count_only")).toHaveLength(29);
    const winner = decisions.find((d) => d.action === "upload")!;
    expect(await signatureRow(await sigOf(claims[0]!))).toMatchObject({
      count: 30,
      installs: 30,
      sample_state: "leased",
      lease_report: winner.report_id,
    });
    const actions = await env.DB.prepare("SELECT action, COUNT(*) AS n FROM reports GROUP BY action ORDER BY action").all();
    expect(actions.results).toEqual([
      { action: "count_only", n: 29 },
      { action: "upload", n: 1 },
    ]);
  });

  it("hands the lease to the next report once it expired without complete", async () => {
    const first = haltClaim();
    await call(claimRequest(first));
    const early = await signedJson(await call(claimRequest(haltClaim()), NOW + 1800));
    expect(early.action).toBe("count_only");
    const late = haltClaim();
    const decision = await signedJson(await call(claimRequest(late), NOW + 1801));
    expect(decision.action).toBe("upload");
    expect(decision.upload.expires_unix).toBe(NOW + 1801 + 1800);
    expect(await signatureRow(decision.signature)).toMatchObject({ lease_report: late.report_id, count: 3 });
  });

  it("does not lease when the console has no piece to send", async () => {
    const decision = await signedJson(await call(claimRequest(haltClaim({ artifacts: [] }))));
    expect(decision.action).toBe("count_only");
    expect(await signatureRow(decision.signature)).toMatchObject({ count: 1, sample_state: "none", lease_report: null });
  });

  it("reopens a fixed signature as regressed when the version is >= fixed_in_version", async () => {
    const sig = await sigOf(haltClaim());
    await call(claimRequest(haltClaim()));
    await env.DB.prepare(
      `UPDATE signatures SET status = 'fixed', fixed_in_version = '0.2.0', sample_state = 'stored',
         sample_report = lease_report, lease_report = NULL, lease_expires = NULL WHERE id = ?1`,
    )
      .bind(sig)
      .run();

    const old = await signedJson(await call(claimRequest(haltClaim())));
    expect(old.action).toBe("count_only");
    expect(await signatureRow(sig)).toMatchObject({ status: "fixed", sample_state: "stored" });

    await registerBuild("0.2.0+0123456789ab");
    const regressed = haltClaim({ build_id: "0.2.0+0123456789ab" });
    const decision = await signedJson(await call(claimRequest(regressed), NOW + 100));
    expect(decision.action).toBe("upload");
    expect(await signatureRow(sig)).toMatchObject({
      status: "regressed",
      status_changed_at: NOW + 100,
      sample_state: "leased",
      lease_report: regressed.report_id,
      count: 3,
    });
  });

  it("compares versions numerically, not as text", async () => {
    const sig = await sigOf(haltClaim());
    await call(claimRequest(haltClaim({ artifacts: [] })));
    await env.DB.prepare("UPDATE signatures SET status = 'fixed', fixed_in_version = '0.10.0' WHERE id = ?1").bind(sig).run();
    await registerBuild("0.9.0+0123456789ab");
    await call(claimRequest(haltClaim({ build_id: "0.9.0+0123456789ab" })));
    expect(await signatureRow(sig)).toMatchObject({ status: "fixed" });
    await registerBuild("0.10.0+0123456789ab");
    await call(claimRequest(haltClaim({ build_id: "0.10.0+0123456789ab" })));
    expect(await signatureRow(sig)).toMatchObject({ status: "regressed" });
  });

  it("counts claims of a merged signature on its root", async () => {
    const childClaim = haltClaim({ features: { code: 904, location: "Codec.cpp:1377", frames: [] } });
    const child = await sigOf(childClaim);
    const root = await sigOf(haltClaim());
    await call(claimRequest(haltClaim()));
    await call(claimRequest(childClaim));
    await env.DB.prepare("UPDATE signatures SET merged_into = ?1 WHERE id = ?2").bind(root, child).run();

    const next = haltClaim({ features: { code: 904, location: "Codec.cpp:1377", frames: [] } });
    const decision = await signedJson(await call(claimRequest(next)));
    expect(decision.signature).toBe(root);
    expect(await signatureRow(root)).toMatchObject({ count: 2 });
    expect(await signatureRow(child)).toMatchObject({ count: 1 });
    const report = await env.DB.prepare("SELECT signature, raw_signature FROM reports WHERE report_id = ?1")
      .bind(next.report_id)
      .first();
    expect(report).toEqual({ signature: root, raw_signature: child });
    const builds = await env.DB.prepare("SELECT signature, count FROM signature_builds ORDER BY signature").all();
    expect(builds.results).toContainEqual({ signature: root, count: 2 });
  });

  it("is wired to the Worker fetch handler", async () => {
    const claim = haltClaim({ report_id: ulid() });
    const res = await exports.default.fetch(claimRequest(claim));
    expect(res.status).toBe(200);
    expect(await signedJson(res)).toMatchObject({ report_id: claim.report_id, action: "upload" });
  });
});

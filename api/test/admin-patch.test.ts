import { env } from "cloudflare:workers";
import { beforeEach, describe, expect, it } from "vitest";
import { admin, adminRequest, sendClaim, sigOf } from "./admin-helpers";
import { haltClaim, hostFaultClaim } from "./fixtures";
import { NOW, call, registerBuild, resetDatabase, signatureRow } from "./helpers";

const A = () => haltClaim();
const B = () => hostFaultClaim();
const C = () => haltClaim({ features: { code: 904, location: "Codec.cpp:1377", frames: [] } });

let a: string;
let b: string;
let c: string;

beforeEach(async () => {
  await resetDatabase();
  await registerBuild();
  await sendClaim(A());
  await sendClaim(A());
  await sendClaim(B());
  await sendClaim(C());
  a = await sigOf(A());
  b = await sigOf(B());
  c = await sigOf(C());
});

const patch = (id: string, body: unknown, now = NOW + 500) => admin("PATCH", `/v1/admin/signatures/${id}`, body, now);

describe("PATCH /v1/admin/signatures/{id}", () => {
  it("marks a signature fixed in a version", async () => {
    const res = await patch(a, { status: "fixed", fixed_in_version: "0.2.0" });
    expect(res.status).toBe(200);
    expect(res.body.signature).toMatchObject({ id: a, status: "fixed", fixed_in_version: "0.2.0", status_changed_at: NOW + 500 });
    expect(await signatureRow(a)).toMatchObject({ status: "fixed", fixed_in_version: "0.2.0" });
  });

  it("requires a fixed_in_version for status fixed", async () => {
    const res = await patch(a, { status: "fixed" });
    expect(res.status).toBe(400);
    expect(res.body).toMatchObject({ error: "invalid_payload" });
    expect((await patch(a, { status: "fixed", fixed_in_version: null })).status).toBe(400);
    await patch(a, { fixed_in_version: "0.3.0" });
    expect((await patch(a, { status: "fixed" })).status).toBe(200);
    expect((await patch(a, { status: "ignored" })).body.signature).toMatchObject({ status: "ignored", fixed_in_version: "0.3.0" });
  });

  it("refuses clearing fixed_in_version while the signature stays fixed", async () => {
    await patch(a, { status: "fixed", fixed_in_version: "0.2.0" });
    const res = await patch(a, { fixed_in_version: null });
    expect(res.status).toBe(400);
    expect(await signatureRow(a)).toMatchObject({ status: "fixed", fixed_in_version: "0.2.0" });
    expect((await patch(a, { status: "open", fixed_in_version: null })).status).toBe(200);
  });

  it("refuses status regressed, which only the server sets", async () => {
    expect((await patch(a, { status: "regressed" })).status).toBe(400);
  });

  it("sets and clears issue_url and note", async () => {
    const url = "https://github.com/Franckrst/D2Vita/issues/42";
    expect((await patch(a, { issue_url: url, note: "dynarec family" })).body.signature).toMatchObject({
      issue_url: url,
      note: "dynarec family",
    });
    expect((await patch(a, { issue_url: null, note: null })).body.signature).toMatchObject({ issue_url: null, note: null });
  });

  it("merges into a root, and later claims count on the root", async () => {
    const res = await patch(c, { merged_into: a });
    expect(res.status).toBe(200);
    expect(res.body.signature).toMatchObject({ id: c, merged_into: a });
    const root = await admin("GET", `/v1/admin/signatures/${a}`);
    expect(root.body.signature.merged_from).toEqual([{ id: c, count: 1 }]);
    expect(root.body.signature.total_count).toBe(3);
    const decision = await sendClaim(C());
    expect(decision.signature).toBe(a);
    expect(await signatureRow(a)).toMatchObject({ count: 3 });
  });

  it("resolves a merged target to its root and flattens children", async () => {
    await patch(c, { merged_into: b });
    await patch(a, { merged_into: c }); // c is merged into b: a goes to b
    expect(await signatureRow(a)).toMatchObject({ merged_into: b });
    const third = haltClaim({ features: { code: 1, frames: [] } });
    await sendClaim(third);
    const d = await sigOf(third);
    await patch(b, { merged_into: d }); // b's children follow b to d
    expect(await signatureRow(a)).toMatchObject({ merged_into: d });
    expect(await signatureRow(c)).toMatchObject({ merged_into: d });
    expect(await signatureRow(b)).toMatchObject({ merged_into: d });
  });

  it("refuses a merge into itself, into an unknown signature, or creating a cycle", async () => {
    expect((await patch(a, { merged_into: a })).status).toBe(400);
    expect((await patch(a, { merged_into: "SAAAAAAAAAAAAAAA" })).status).toBe(400);
    await patch(c, { merged_into: a });
    const cycle = await patch(a, { merged_into: c });
    expect(cycle.status).toBe(400);
    expect(cycle.body).toMatchObject({ error: "invalid_payload" });
    expect(await signatureRow(a)).toMatchObject({ merged_into: null });
  });

  it("unmerges with merged_into null", async () => {
    await patch(c, { merged_into: a });
    expect((await patch(c, { merged_into: null })).body.signature).toMatchObject({ merged_into: null });
    expect((await sendClaim(C())).signature).toBe(c);
  });

  it("resample asks the next report for a new sample", async () => {
    await env.DB.prepare(
      "UPDATE signatures SET sample_state = 'stored', sample_report = lease_report, lease_report = NULL, lease_expires = NULL WHERE id = ?1",
    )
      .bind(a)
      .run();
    const before = await signatureRow(a);
    expect((await sendClaim(A())).action).toBe("count_only");
    const res = await patch(a, { resample: true });
    expect(res.body.signature).toMatchObject({ sample_state: "none", sample_report: before!.sample_report });
    expect((await sendClaim(A())).action).toBe("upload");
  });

  it("answers 404 for an unknown signature and 400/413 for bad bodies", async () => {
    expect((await patch("SAAAAAAAAAAAAAAA", { note: "x" })).status).toBe(404);
    expect((await patch(a, { count: 1 })).status).toBe(400);
    expect((await patch(a, {})).status).toBe(400);
    const noLength = adminRequest("PATCH", `/v1/admin/signatures/${a}`, { note: "x" });
    noLength.headers.delete("content-length");
    expect((await call(noLength)).status).toBe(413);
  });
});

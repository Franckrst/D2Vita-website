import { env } from "cloudflare:workers";
import { beforeEach, describe, expect, it } from "vitest";
import { sha256, toHex } from "../src/crypto";
import { admin, adminRequest, sendClaim } from "./admin-helpers";
import { haltClaim, ulid } from "./fixtures";
import { NOW, call, registerBuild, resetDatabase, storeSample } from "./helpers";

beforeEach(async () => {
  await resetDatabase();
  await registerBuild();
});

describe("GET /v1/admin/reports/{id}", () => {
  it("returns the claim as received and what happened to it", async () => {
    const claim = haltClaim({ redactions: 2 });
    const decision = await sendClaim(claim);
    const res = await admin("GET", `/v1/admin/reports/${claim.report_id}`);
    expect(res.status).toBe(200);
    // admin.v1#ReportDetail: the claim must still validate against claim.v1,
    // so it is kept whole, install_id included; every counter and every link
    // uses the install_hash pseudonym instead.
    expect(res.body).toEqual({
      v: 1,
      report_id: claim.report_id,
      signature: decision.signature,
      install_hash: expect.stringMatching(/^[0-9a-f]{64}$/),
      received_unix: NOW,
      rules_version: 1,
      action: "upload",
      completed_unix: null,
      claim,
      artifacts: [],
    });
  });

  it("lists the stored pieces of a completed report", async () => {
    const { decision, pieces } = await storeSample(haltClaim());
    const res = await admin("GET", `/v1/admin/reports/${decision.report_id}`);
    expect(res.body.completed_unix).toBe(NOW);
    expect(res.body.artifacts).toContainEqual({
      name: "crash_log",
      bytes: pieces.crash_log!.byteLength,
      sha256: toHex(await sha256(pieces.crash_log!)),
      stored_unix: NOW,
    });
  });

  it("answers 404 for an unknown or malformed id", async () => {
    expect((await admin("GET", `/v1/admin/reports/${ulid()}`)).status).toBe(404);
    expect((await admin("GET", "/v1/admin/reports/nope")).status).toBe(404);
  });
});

describe("GET /v1/admin/artifacts/{report_id}/{name}", () => {
  it("streams the sealed bytes with their size and hash", async () => {
    const { decision, pieces } = await storeSample(haltClaim());
    const res = await call(adminRequest("GET", `/v1/admin/artifacts/${decision.report_id}/crash_log`));
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toBe("application/octet-stream");
    expect(res.headers.get("content-length")).toBe("300");
    expect(res.headers.get("x-d2v-sha256")).toBe(toHex(await sha256(pieces.crash_log!)));
    expect(new Uint8Array(await res.arrayBuffer())).toEqual(pieces.crash_log);
  });

  it("answers 404 for a piece not stored, an unknown name or an unknown report", async () => {
    const { decision } = await storeSample(haltClaim());
    expect((await call(adminRequest("GET", `/v1/admin/artifacts/${decision.report_id}/dump`))).status).toBe(404);
    expect((await call(adminRequest("GET", `/v1/admin/artifacts/${decision.report_id}/savegame`))).status).toBe(404);
    expect((await call(adminRequest("GET", `/v1/admin/artifacts/${ulid()}/crash_log`))).status).toBe(404);
  });

  it("requires the admin token", async () => {
    const { decision } = await storeSample(haltClaim());
    expect((await call(adminRequest("GET", `/v1/admin/artifacts/${decision.report_id}/crash_log`, undefined, null))).status).toBe(
      401,
    );
  });
});

describe("admin bugs", () => {
  async function seedBugs() {
    const insert = (id: string, created: number, status: string) =>
      env.DB.prepare(
        `INSERT INTO bugs (id, title, description, version, contact, lang, status, created_at, updated_at)
         VALUES (?1, ?2, 'desc', '0.1.0', NULL, 'fr', ?3, ?4, ?4)`,
      ).bind(id, `title ${id}`, status, created);
    await env.DB.batch([
      insert("BAAAAAAAAAAAAAAAA", NOW - 300, "open"),
      insert("BBBBBBBBBBBBBBBBB", NOW - 100, "fixed"),
      insert("BCCCCCCCCCCCCCCCC", NOW - 200, "open"),
    ]);
  }

  it("lists bugs newest first, filtered and paginated", async () => {
    await seedBugs();
    const all = await admin("GET", "/v1/admin/bugs");
    expect(all.status).toBe(200);
    expect(all.body.items.map((b: any) => b.id)).toEqual(["BBBBBBBBBBBBBBBBB", "BCCCCCCCCCCCCCCCC", "BAAAAAAAAAAAAAAAA"]);
    expect(all.body.items[0]).toEqual({
      id: "BBBBBBBBBBBBBBBBB",
      title: "title BBBBBBBBBBBBBBBBB",
      description: "desc",
      version: "0.1.0",
      contact: null,
      lang: "fr",
      status: "fixed",
      issue_url: null,
      created_unix: NOW - 100,
    });
    const open = await admin("GET", "/v1/admin/bugs?status=open&limit=1");
    expect(open.body.items.map((b: any) => b.id)).toEqual(["BCCCCCCCCCCCCCCCC"]);
    const next = await admin("GET", `/v1/admin/bugs?status=open&limit=1&cursor=${open.body.next_cursor}`);
    expect(next.body.items.map((b: any) => b.id)).toEqual(["BAAAAAAAAAAAAAAAA"]);
    expect(next.body.next_cursor).toBeNull();
    expect((await admin("GET", "/v1/admin/bugs?status=done")).status).toBe(400);
  });

  it("returns and patches one bug", async () => {
    await seedBugs();
    const one = await admin("GET", "/v1/admin/bugs/BAAAAAAAAAAAAAAAA");
    expect(one.status).toBe(200);
    expect(one.body).toMatchObject({ id: "BAAAAAAAAAAAAAAAA", status: "open" });

    const url = "https://github.com/Franckrst/D2Vita/issues/7";
    const patched = await admin("PATCH", "/v1/admin/bugs/BAAAAAAAAAAAAAAAA", { status: "fixed", issue_url: url }, NOW + 5);
    expect(patched.status).toBe(200);
    expect(patched.body).toMatchObject({ status: "fixed", issue_url: url });
    expect((await admin("PATCH", "/v1/admin/bugs/BAAAAAAAAAAAAAAAA", { title: "x" })).status).toBe(400);
    expect((await admin("GET", "/v1/admin/bugs/BZZZZZZZZZZZZZZZZ")).status).toBe(404);
    expect((await admin("PATCH", "/v1/admin/bugs/BZZZZZZZZZZZZZZZZ", { status: "fixed" })).status).toBe(404);
  });
});

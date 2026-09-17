import { createExecutionContext } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { beforeEach, describe, expect, it } from "vitest";
import { handle } from "../src/router";
import { admin, adminRequest, sendClaim, sigOf } from "./admin-helpers";
import { BUILD_ID, haltClaim, haltFeatures, hostFaultClaim, installId } from "./fixtures";
import { NOW, call, registerBuild, resetDatabase } from "./helpers";

const OTHER_BUILD = "0.2.0+0123456789ab";

const A = () => haltClaim(); // halt 1420
const B = () => hostFaultClaim(); // host_fault eboot
const C = () => haltClaim({ features: haltFeatures({ code: 904, location: "Codec.cpp:1377", frames: ["Game+0x1"] }) });

beforeEach(async () => {
  await resetDatabase();
  await registerBuild();
  await registerBuild(OTHER_BUILD);
});

async function seed() {
  const install = installId();
  await sendClaim({ ...A(), install_id: install }, NOW + 10);
  await sendClaim({ ...A(), install_id: install }, NOW + 20);
  await sendClaim(A(), NOW + 30);
  await sendClaim(B(), NOW + 100);
  await sendClaim(C(), NOW + 40);
  await sendClaim({ ...C(), build_id: OTHER_BUILD }, NOW + 50);
  return { a: await sigOf(A()), b: await sigOf(B()), c: await sigOf(C()) };
}

describe("admin authentication", () => {
  it("answers 401 without a token, with a wrong token, and hides unknown admin routes", async () => {
    for (const token of [null, "wrong-token", `${env.TEST_ADMIN_TOKEN}x`]) {
      const res = await call(adminRequest("GET", "/v1/admin/signatures", undefined, token));
      expect(res.status, String(token)).toBe(401);
      expect(res.headers.get("www-authenticate")).toBe("Bearer");
      expect(await res.json()).toMatchObject({ v: 1, error: "unauthorized" });
    }
    expect((await call(adminRequest("GET", "/v1/admin/nope", undefined, null))).status).toBe(401);
    expect((await call(adminRequest("GET", "/v1/admin/nope"))).status).toBe(404);
  });

  it("accepts the right token and fails closed when ADMIN_TOKEN_SHA256 is not configured", async () => {
    expect((await call(adminRequest("GET", "/v1/admin/signatures"))).status).toBe(200);
    const res = await handle(
      adminRequest("GET", "/v1/admin/signatures"),
      { ...env, ADMIN_TOKEN_SHA256: undefined },
      createExecutionContext(),
      NOW,
    );
    expect(res.status).toBe(401);
  });
});

describe("GET /v1/admin/signatures", () => {
  it("lists signatures sorted by count, then by last_seen", async () => {
    const { a, b, c } = await seed();
    const byCount = await admin("GET", "/v1/admin/signatures?sort=count");
    expect(byCount.status).toBe(200);
    expect(byCount.body.items.map((s: any) => s.id)).toEqual([a, c, b]);
    expect(byCount.body.next_cursor).toBeNull();
    expect(byCount.body.items[0]).toEqual({
      id: a,
      kind: "halt",
      canon: "halt|1420|-|Game+0x1fedf4,Game+0x451c23,Game+0x44f570",
      status: "open",
      count: 3,
      installs: 2,
      first_seen_unix: NOW + 10,
      last_seen_unix: NOW + 30,
      sample_state: "leased",
      fixed_in_version: null,
      merged_into: null,
      issue_url: null,
    });

    const byLastSeen = await admin("GET", "/v1/admin/signatures?sort=last_seen");
    expect(byLastSeen.body.items.map((s: any) => s.id)).toEqual([b, c, a]);
    const byDefault = await admin("GET", "/v1/admin/signatures");
    expect(byDefault.body.items.map((s: any) => s.id)).toEqual([a, c, b]);
  });

  it("paginates with an opaque cursor", async () => {
    const { a, b, c } = await seed();
    const first = await admin("GET", "/v1/admin/signatures?sort=count&limit=2");
    expect(first.body.items.map((s: any) => s.id)).toEqual([a, c]);
    expect(first.body.next_cursor).toEqual(expect.any(String));
    const second = await admin("GET", `/v1/admin/signatures?sort=count&limit=2&cursor=${first.body.next_cursor}`);
    expect(second.body.items.map((s: any) => s.id)).toEqual([b]);
    expect(second.body.next_cursor).toBeNull();
  });

  it("keeps a stable order for equal sort keys across pages", async () => {
    const ids: string[] = [];
    for (let i = 0; i < 5; i++) {
      const claim = haltClaim({ features: haltFeatures({ code: 100 + i, frames: [] }) });
      await sendClaim(claim, NOW);
      ids.push(await sigOf(claim));
    }
    const seen: string[] = [];
    let cursor: string | null = null;
    do {
      const page: { body: any } = await admin("GET", `/v1/admin/signatures?limit=2${cursor ? `&cursor=${cursor}` : ""}`);
      seen.push(...page.body.items.map((s: any) => s.id));
      cursor = page.body.next_cursor;
    } while (cursor);
    expect(seen).toEqual([...ids].sort());
  });

  it("filters by status, kind and build", async () => {
    const { a, b, c } = await seed();
    await env.DB.prepare("UPDATE signatures SET status = 'fixed' WHERE id = ?1").bind(c).run();
    expect((await admin("GET", "/v1/admin/signatures?kind=host_fault")).body.items.map((s: any) => s.id)).toEqual([b]);
    expect((await admin("GET", "/v1/admin/signatures?status=fixed")).body.items.map((s: any) => s.id)).toEqual([c]);
    expect((await admin("GET", `/v1/admin/signatures?build=${encodeURIComponent(OTHER_BUILD)}`)).body.items.map((s: any) => s.id)).toEqual([c]);
    expect(
      (await admin("GET", `/v1/admin/signatures?status=open&kind=halt&build=${encodeURIComponent(BUILD_ID)}`)).body.items.map(
        (s: any) => s.id,
      ),
    ).toEqual([a]);
  });

  it.each(["status=closed", "kind=meteor", "sort=random", "limit=0", "limit=500", "cursor=%%%", "build=nope", "extra=1"])(
    "answers 400 for the invalid query %s",
    async (query) => {
      const res = await admin("GET", `/v1/admin/signatures?${query}`);
      expect(res.status).toBe(400);
      expect(res.body).toMatchObject({ error: "invalid_payload" });
    },
  );
});

describe("GET /v1/admin/signatures/{id}", () => {
  it("returns per-build counters, distinct consoles, the sample and recent reports", async () => {
    const { c } = await seed();
    const res = await admin("GET", `/v1/admin/signatures/${c}`);
    expect(res.status).toBe(200);
    const s = res.body;
    expect(s).toMatchObject({ id: c, count: 2, installs: 2, rules_version: 1, note: null });
    expect(s.builds).toEqual([
      { build_id: OTHER_BUILD, count: 1, first_seen_unix: NOW + 50, last_seen_unix: NOW + 50 },
      { build_id: BUILD_ID, count: 1, first_seen_unix: NOW + 40, last_seen_unix: NOW + 40 },
    ]);
    expect(s.recent_reports.map((r: any) => r.received_unix)).toEqual([NOW + 50, NOW + 40]);
    expect(s.recent_reports[0]).toMatchObject({ build_id: OTHER_BUILD, action: "count_only" });
    expect(s.recent_reports[1]).toMatchObject({ build_id: BUILD_ID, action: "upload" });
    // Nothing is stored yet: the lease is named apart from the sample.
    expect(s).toMatchObject({ sample_state: "leased", sample_report: null, sample_artifacts: [] });
    expect(s.lease_report).toBe(s.recent_reports[1].report_id);
    expect(s.lease_expires_unix).toBe(NOW + 40 + 1800);
  });

  it("answers 404 for an unknown signature", async () => {
    const res = await admin("GET", "/v1/admin/signatures/SAAAAAAAAAAAAAAA");
    expect(res.status).toBe(404);
    expect(res.body).toMatchObject({ error: "not_found" });
  });
});

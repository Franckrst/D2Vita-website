import { env, exports } from "cloudflare:workers";
import { describe, expect, it } from "vitest";

const TABLES = [
  "builds",
  "signatures",
  "signature_builds",
  "signature_installs",
  "reports",
  "bugs",
  "rate_counters",
  "settings",
];

describe("D1 migrations", () => {
  it("creates every table of spec section 5.6", async () => {
    const { results } = await env.DB.prepare(
      "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name",
    ).all<{ name: string }>();
    const names = results.map((r) => r.name);
    for (const table of TABLES) expect(names).toContain(table);
  });

  it("enforces the signature status and sample_state enums", async () => {
    await env.DB.prepare(
      `INSERT INTO signatures (id, kind, canon, rules_version, first_seen, last_seen)
       VALUES ('SBBBBBBBBBBBBBBB', 'hang', 'hang|-', 1, 0, 0)`,
    ).run();
    const row = await env.DB.prepare(
      "SELECT status, sample_state, count FROM signatures WHERE id = 'SBBBBBBBBBBBBBBB'",
    ).first();
    expect(row).toEqual({ status: "open", sample_state: "none", count: 0 });
    await expect(
      env.DB.prepare(
        `INSERT INTO signatures (id, kind, canon, rules_version, first_seen, last_seen, status)
         VALUES ('SAAAAAAAAAAAAAAA', 'hang', 'hang|-', 1, 0, 0, 'bogus')`,
      ).run(),
    ).rejects.toThrow();
    await expect(
      env.DB.prepare(
        `INSERT INTO signatures (id, kind, canon, rules_version, first_seen, last_seen, sample_state)
         VALUES ('SAAAAAAAAAAAAAAA', 'hang', 'hang|-', 1, 0, 0, 'bogus')`,
      ).run(),
    ).rejects.toThrow();
  });
});

describe("worker entry point", () => {
  it("answers unknown routes with a v1 JSON 404", async () => {
    const res = await exports.default.fetch("https://api.test/nope");
    expect(res.status).toBe(404);
    expect(res.headers.get("content-type")).toContain("application/json");
    expect(await res.json()).toMatchObject({ v: 1, error: "not_found" });
  });
});

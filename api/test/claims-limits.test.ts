import { env } from "cloudflare:workers";
import { beforeEach, describe, expect, it } from "vitest";
import { secondsUntilNextUtcDay } from "../src/limits";
import { haltClaim, hostFaultClaim, installId } from "./fixtures";
import { NOW, call, claimRequest, registerBuild, resetDatabase, signedJson } from "./helpers";

const DEV_BUILD = "0.1.0+ab12cd34ef56-dirty";

async function setCap(name: string, value: number) {
  await env.DB.prepare("INSERT INTO settings (key, value) VALUES (?1, ?2) ON CONFLICT (key) DO UPDATE SET value = excluded.value")
    .bind(`cap:${name}`, String(value))
    .run();
}

async function reportCount(): Promise<number> {
  return ((await env.DB.prepare("SELECT COUNT(*) AS n FROM reports").first<{ n: number }>())?.n) ?? -1;
}

beforeEach(async () => {
  await resetDatabase();
  await registerBuild();
});

describe("claim rate limits (spec section 5.5)", () => {
  it("allows 3 claims per installation per UTC day, the 4th gets a signed 429 with retry_after_s", async () => {
    const install = installId();
    for (let i = 0; i < 3; i++) {
      expect((await call(claimRequest(haltClaim({ install_id: install })))).status).toBe(200);
    }
    const refused = await call(claimRequest(haltClaim({ install_id: install })));
    expect(refused.status).toBe(429);
    expect(await signedJson(refused)).toMatchObject({
      v: 1,
      error: "rate_limited",
      retry_after_s: secondsUntilNextUtcDay(NOW),
    });
    expect(await reportCount()).toBe(3);

    const tomorrow = NOW + secondsUntilNextUtcDay(NOW);
    expect((await call(claimRequest(haltClaim({ install_id: install })), tomorrow)).status).toBe(200);
  });

  it("raises the installation cap for dev and test builds, and still enforces it", async () => {
    await registerBuild(DEV_BUILD, "dev");
    await setCap("install_claims_dev", 5);
    const install = installId();
    const devClaim = () => claimRequest(haltClaim({ install_id: install, build_id: DEV_BUILD, channel: "dev" }));
    for (let i = 0; i < 5; i++) expect((await call(devClaim())).status).toBe(200);
    expect((await call(devClaim())).status).toBe(429);
  });

  it("uses the registered channel, not the one claimed", async () => {
    const install = installId();
    for (let i = 0; i < 3; i++) await call(claimRequest(haltClaim({ install_id: install, channel: "dev" })));
    expect((await call(claimRequest(haltClaim({ install_id: install, channel: "dev" })))).status).toBe(429);
  });

  it("allows 10 claims per IP per day", async () => {
    const ip = "198.51.100.23";
    for (let i = 0; i < 10; i++) expect((await call(claimRequest(haltClaim(), { ip }))).status).toBe(200);
    const refused = await call(claimRequest(haltClaim(), { ip }));
    expect(refused.status).toBe(429);
    expect(await signedJson(refused)).toMatchObject({ error: "rate_limited" });
  });

  it("applies the global daily claim cap", async () => {
    await setCap("global_claims", 2);
    expect((await call(claimRequest(haltClaim()))).status).toBe(200);
    expect((await call(claimRequest(haltClaim()))).status).toBe(200);
    expect((await call(claimRequest(haltClaim()))).status).toBe(429);
  });

  it("applies the global cap on new signatures but still counts known ones", async () => {
    await setCap("global_new_signatures", 1);
    expect((await call(claimRequest(haltClaim()))).status).toBe(200);
    const refused = await call(claimRequest(hostFaultClaim()));
    expect(refused.status).toBe(429);
    expect(await signedJson(refused)).toMatchObject({ error: "rate_limited" });
    expect((await call(claimRequest(haltClaim()))).status).toBe(200);
    const sigs = await env.DB.prepare("SELECT COUNT(*) AS n, SUM(count) AS total FROM signatures").first();
    expect(sigs).toEqual({ n: 1, total: 2 });
  });

  it("does not consume the IP or global budget once the installation is blocked", async () => {
    const install = installId();
    const ip = "198.51.100.99";
    for (let i = 0; i < 3; i++) await call(claimRequest(haltClaim({ install_id: install }), { ip }));
    for (let i = 0; i < 5; i++) await call(claimRequest(haltClaim({ install_id: install }), { ip }));
    const counters = await env.DB.prepare("SELECT scope, n FROM rate_counters ORDER BY scope").all();
    expect(counters.results).toEqual([
      { scope: "claims:global", n: 3 },
      { scope: "claims:install", n: 3 },
      { scope: "claims:ip", n: 3 },
      { scope: "new_signatures:global", n: 1 },
    ]);
  });
});

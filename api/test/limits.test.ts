import { env } from "cloudflare:workers";
import { beforeEach, describe, expect, it } from "vitest";
import {
  CAP_NAMES,
  DEFAULT_CAPS,
  consume,
  consumeAll,
  consumeAllOrNothing,
  hasRoom,
  installCaps,
  ipHash,
  loadSettings,
  networkKey,
  rateLimited,
  saveSettings,
  secondsUntilNextUtcDay,
  utcDay,
} from "../src/limits";
import { resetDatabase } from "./helpers";

const T = 1789284000; // 2026-09-13T07:20:00Z
const MiB = 1024 * 1024;

beforeEach(async () => {
  await resetDatabase();
});

describe("UTC day window", () => {
  it("formats the UTC day and rolls over at midnight", () => {
    expect(utcDay(T)).toBe("2026-09-13");
    expect(utcDay(1789343999)).toBe("2026-09-13");
    expect(utcDay(1789344000)).toBe("2026-09-14");
  });

  it("counts the seconds until the next UTC midnight", () => {
    expect(secondsUntilNextUtcDay(T)).toBe(60000);
    expect(secondsUntilNextUtcDay(1789343999)).toBe(1);
    expect(secondsUntilNextUtcDay(1789344000)).toBe(86400);
  });
});

describe("consume (atomic conditional counter)", () => {
  it("allows exactly the cap, then refuses", async () => {
    const day = utcDay(T);
    const results = [];
    for (let i = 0; i < 4; i++) results.push(await consume(env.DB, "claims:install", "abc", day, 1, 3));
    expect(results).toEqual([true, true, true, false]);
    const row = await env.DB.prepare("SELECT n FROM rate_counters WHERE scope = 'claims:install' AND subject = 'abc'").first();
    expect(row).toEqual({ n: 3 });
  });

  it("keeps subjects and days independent", async () => {
    const day = utcDay(T);
    for (let i = 0; i < 3; i++) await consume(env.DB, "claims:install", "a", day, 1, 3);
    expect(await consume(env.DB, "claims:install", "a", day, 1, 3)).toBe(false);
    expect(await consume(env.DB, "claims:install", "b", day, 1, 3)).toBe(true);
    expect(await consume(env.DB, "claims:install", "a", utcDay(T + 86400), 1, 3)).toBe(true);
  });

  it("counts amounts (bytes) and refuses a single amount above the cap", async () => {
    const day = utcDay(T);
    expect(await consume(env.DB, "bytes:install", "a", day, 2 * MiB, 3 * MiB)).toBe(true);
    expect(await consume(env.DB, "bytes:install", "a", day, MiB, 3 * MiB)).toBe(true);
    expect(await consume(env.DB, "bytes:install", "a", day, 1, 3 * MiB)).toBe(false);
    expect(await consume(env.DB, "bytes:install", "b", day, 3 * MiB + 1, 3 * MiB)).toBe(false);
  });

  it("never exceeds the cap under concurrency", async () => {
    const day = utcDay(T);
    const results = await Promise.all(
      Array.from({ length: 20 }, () => consume(env.DB, "claims:global", "*", day, 1, 5)),
    );
    expect(results.filter(Boolean)).toHaveLength(5);
  });

  it("consumeAll stops at the first refused counter and reports it", async () => {
    const day = utcDay(T);
    await consume(env.DB, "claims:ip", "ip1", day, 1, 1);
    const refused = await consumeAll(env.DB, day, [
      { scope: "claims:install", subject: "i1", amount: 1, cap: 3 },
      { scope: "claims:ip", subject: "ip1", amount: 1, cap: 1 },
      { scope: "claims:global", subject: "*", amount: 1, cap: 2000 },
    ]);
    expect(refused?.scope).toBe("claims:ip");
    const global = await env.DB.prepare("SELECT n FROM rate_counters WHERE scope = 'claims:global'").first();
    expect(global).toBeNull();
    expect(await consumeAll(env.DB, day, [{ scope: "claims:install", subject: "i2", amount: 1, cap: 3 }])).toBeNull();
  });

  it("consumeAllOrNothing gives back what it took when a later counter refuses", async () => {
    const day = utcDay(T);
    await consume(env.DB, "bytes:global", "*", day, 900, 1000);
    const checks = [
      { scope: "bytes:install", subject: "i1", amount: 600, cap: 3 * MiB },
      { scope: "bytes:global", subject: "*", amount: 600, cap: 1000 },
    ];
    expect((await consumeAllOrNothing(env.DB, day, checks))?.scope).toBe("bytes:global");
    const rows = await env.DB.prepare("SELECT scope, n FROM rate_counters ORDER BY scope").all();
    expect(rows.results).toEqual([
      { scope: "bytes:global", n: 900 },
      { scope: "bytes:install", n: 0 },
    ]);
    expect(await consumeAllOrNothing(env.DB, day, [{ ...checks[0]!, amount: 100 }, { ...checks[1]!, amount: 100 }])).toBeNull();
    const after = await env.DB.prepare("SELECT scope, n FROM rate_counters ORDER BY scope").all();
    expect(after.results).toEqual([
      { scope: "bytes:global", n: 1000 },
      { scope: "bytes:install", n: 100 },
    ]);
  });

  it("hasRoom tells whether every counter can take its amount, without writing", async () => {
    const day = utcDay(T);
    await consume(env.DB, "bytes:install", "i1", day, 2 * MiB, 3 * MiB);
    const install = { scope: "bytes:install", subject: "i1", amount: MiB, cap: 3 * MiB };
    const global = { scope: "bytes:global", subject: "*", amount: MiB, cap: 300 * MiB };
    expect(await hasRoom(env.DB, day, [install, global])).toBe(true);
    expect(await hasRoom(env.DB, day, [{ ...install, amount: MiB + 1 }, global])).toBe(false);
    expect(await hasRoom(env.DB, day, [install, { ...global, cap: MiB - 1 }])).toBe(false);
    const rows = await env.DB.prepare("SELECT scope, n FROM rate_counters").all();
    expect(rows.results).toEqual([{ scope: "bytes:install", n: 2 * MiB }]);
  });
});

describe("429 response", () => {
  it("carries retry_after_s until the next UTC day and a Retry-After header", async () => {
    const res = rateLimited(T);
    expect(res.status).toBe(429);
    expect(res.headers.get("retry-after")).toBe("60000");
    expect(await res.json()).toMatchObject({ v: 1, error: "rate_limited", retry_after_s: 60000 });
  });
});

describe("settings", () => {
  it("defaults to accepting with the spec caps", async () => {
    const settings = await loadSettings(env.DB);
    expect(settings.accepting).toBe(true);
    expect(settings.disable_until_unix).toBeNull();
    expect(settings.caps).toEqual(DEFAULT_CAPS);
    expect(settings.caps).toMatchObject({
      install_claims_per_day: 3,
      install_artifact_bytes_per_day: 3 * MiB,
      ip_claims_per_day: 10,
      ip_bugs_per_day: 3,
      global_claims_per_day: 2000,
      global_artifact_bytes_per_day: 300 * MiB,
      global_new_signatures_per_day: 200,
      global_bugs_per_day: 100,
    });
  });

  it("persists the kill switch and cap overrides", async () => {
    await saveSettings(env.DB, { accepting: false, disable_until_unix: T + 3600, caps: { install_claims_per_day: 7 } });
    const settings = await loadSettings(env.DB);
    expect(settings.accepting).toBe(false);
    expect(settings.disable_until_unix).toBe(T + 3600);
    expect(settings.caps.install_claims_per_day).toBe(7);
    expect(settings.caps.ip_claims_per_day).toBe(10);
    await saveSettings(env.DB, { accepting: true, disable_until_unix: null });
    const again = await loadSettings(env.DB);
    expect(again.accepting).toBe(true);
    expect(again.disable_until_unix).toBeNull();
    expect(again.caps.install_claims_per_day).toBe(7);
  });

  it("takes over the caps a wave-1 database stored under the old names", async () => {
    // The caps were renamed to the names of admin.v1#Caps. loadSettings
    // ignores a `cap:` key it does not know, so without migration 0003 a
    // database carried over from wave 1 would silently go back to the compiled
    // defaults. The migration is replayed here over rows written the old way.
    const OLD: Array<[string, number]> = [
      ["cap:install_claims", 7],
      ["cap:install_artifact_bytes", 1234],
      ["cap:install_claims_dev", 77],
      ["cap:install_artifact_bytes_dev", 12345],
      ["cap:ip_claims", 5],
      ["cap:ip_bugs", 2],
      ["cap:global_claims", 500],
      ["cap:global_artifact_bytes", 4321],
      ["cap:global_new_signatures", 50],
      ["cap:global_bugs", 20],
    ];
    await env.DB.batch(
      OLD.map(([key, value]) =>
        env.DB.prepare("INSERT INTO settings (key, value) VALUES (?1, ?2)").bind(key, String(value)),
      ),
    );
    // A cap already set under its new name keeps the value set there.
    await saveSettings(env.DB, { caps: { ip_bugs_per_day: 3 } });

    const migration = env.TEST_MIGRATIONS.find((m) => m.name.includes("rename_cap_settings"));
    expect(migration, "migration 0003_rename_cap_settings").toBeDefined();
    for (const query of migration!.queries) await env.DB.prepare(query).run();

    const settings = await loadSettings(env.DB);
    expect(settings.caps).toEqual({
      ...DEFAULT_CAPS,
      install_claims_per_day: 7,
      install_artifact_bytes_per_day: 1234,
      prerelease_install_claims_per_day: 77,
      prerelease_install_artifact_bytes_per_day: 12345,
      ip_claims_per_day: 5,
      ip_bugs_per_day: 3,
      global_claims_per_day: 500,
      global_artifact_bytes_per_day: 4321,
      global_new_signatures_per_day: 50,
      global_bugs_per_day: 20,
    });
    const { results } = await env.DB.prepare("SELECT key FROM settings WHERE key LIKE 'cap:%'").all<{ key: string }>();
    expect(results.map((r) => r.key).filter((key) => !CAP_NAMES.includes(key.slice(4) as never))).toEqual([]);
  });

  it("raises the installation caps for dev and test builds only", () => {
    expect(installCaps(DEFAULT_CAPS, "release")).toEqual({ claims: 3, bytes: 3 * MiB });
    for (const channel of ["dev", "test"] as const) {
      const caps = installCaps(DEFAULT_CAPS, channel);
      expect(caps.claims).toBe(DEFAULT_CAPS.prerelease_install_claims_per_day);
      expect(caps.bytes).toBe(DEFAULT_CAPS.prerelease_install_artifact_bytes_per_day);
      expect(caps.claims).toBeGreaterThan(3);
      expect(caps.bytes).toBeGreaterThan(3 * MiB);
    }
  });
});

describe("network keys for the per-IP caps", () => {
  it("keeps IPv4 addresses and counts IPv4-mapped IPv6 as its IPv4 address", () => {
    for (const prefix of [48, 64] as const) {
      expect(networkKey("203.0.113.7", prefix)).toBe("203.0.113.7");
      expect(networkKey("::ffff:203.0.113.7", prefix)).toBe("203.0.113.7");
      expect(networkKey("::FFFF:cb00:7107", prefix)).toBe("203.0.113.7");
      expect(networkKey("0:0:0:0:0:ffff:203.0.113.7", prefix)).toBe("203.0.113.7");
    }
  });

  it("reduces IPv6 to its /48 or /64 prefix, whatever the spelling", () => {
    for (const spelling of [
      "2001:db8:1234:5678::1",
      "2001:0DB8:1234:5678:0000:0000:0000:0001",
      "2001:db8:1234:5678:0:0:0:1%eth0",
      "2001:db8:1234:5678::0.0.0.1",
    ]) {
      expect(networkKey(spelling, 64)).toBe("2001:db8:1234:5678::/64");
      expect(networkKey(spelling, 48)).toBe("2001:db8:1234::/48");
    }
    expect(networkKey("2001:db8:1234:ffff:abcd::9", 64)).toBe("2001:db8:1234:ffff::/64");
    expect(networkKey("2001:db8:1234:ffff:abcd::9", 48)).toBe("2001:db8:1234::/48");
    expect(networkKey("2001:db8::", 48)).toBe("2001:db8:0::/48");
    expect(networkKey("::", 64)).toBe("0:0:0:0::/64");
  });

  it("never throws on a missing or malformed address", () => {
    expect(networkKey(null, 48)).toBe("unknown");
    expect(networkKey("", 64)).toBe("unknown");
    for (const bad of ["1.2.3", "300.1.1.1", "1::2::3", "2001:db8:::1", "zzzz::", "1:2:3:4:5:6:7:8:9", ":1:2:3:4:5:6:7", "1.2.3.4::"]) {
      const key = networkKey(bad, 48);
      expect(key, bad).toMatch(/^other:/);
      expect(networkKey(bad, 64), bad).toBe(key);
    }
  });
});

describe("IP pseudonymisation", () => {
  it("is stable within a day, changes across days and never contains the IP", async () => {
    const ip = "203.0.113.77";
    const day = utcDay(T);
    const a = await ipHash(env, env.DB, ip, day);
    const b = await ipHash(env, env.DB, ip, day);
    const other = await ipHash(env, env.DB, "203.0.113.78", day);
    const tomorrow = await ipHash(env, env.DB, ip, utcDay(T + 86400));
    expect(a).toMatch(/^[0-9a-f]{64}$/);
    expect(b).toBe(a);
    expect(other).not.toBe(a);
    expect(tomorrow).not.toBe(a);
  });

  it("uses one random salt per day, even when first requested concurrently", async () => {
    const day = utcDay(T);
    const hashes = await Promise.all(Array.from({ length: 10 }, () => ipHash(env, env.DB, "198.51.100.1", day)));
    expect(new Set(hashes).size).toBe(1);
    const salts = await env.DB.prepare("SELECT key, value FROM settings WHERE key LIKE 'ip_salt:%'").all();
    expect(salts.results).toHaveLength(1);
    expect(salts.results[0]).toMatchObject({ key: `ip_salt:${day}` });
  });

  it("stores only the keyed hash in rate_counters", async () => {
    const ip = "192.0.2.10";
    const day = utcDay(T);
    await consume(env.DB, "claims:ip", await ipHash(env, env.DB, ip, day), day, 1, 10);
    const dump = JSON.stringify((await env.DB.prepare("SELECT * FROM rate_counters").all()).results);
    expect(dump).not.toContain(ip);
    expect(dump).toMatch(/"subject":"[0-9a-f]{64}"/);
  });
});

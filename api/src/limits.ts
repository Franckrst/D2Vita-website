// Rate limits (spec section 5.5): exact daily counters in D1, window = UTC day.
// Every counter is moved by one atomic conditional upsert, so concurrent
// requests can never push a counter above its cap.

import { hmacSha256, toHex, utf8 } from "./crypto";
import { requireSecret } from "./env";
import { json } from "./http";
import type { Channel } from "./types";
import type { SettingsPatch } from "./validate";

const MiB = 1024 * 1024;

// Initial values of the adjustable caps (PUT /v1/admin/settings overrides them).
export const DEFAULT_CAPS = {
  install_claims: 3,
  install_artifact_bytes: 3 * MiB,
  // dev/test builds are not distributed: raised caps.
  install_claims_dev: 50,
  install_artifact_bytes_dev: 64 * MiB,
  ip_claims: 10,
  ip_bugs: 3,
  global_claims: 2000,
  global_artifact_bytes: 300 * MiB,
  global_new_signatures: 200,
  global_bugs: 100,
} as const;

export type CapName = keyof typeof DEFAULT_CAPS;
export type Caps = Record<CapName, number>;

export const CAP_NAMES = Object.keys(DEFAULT_CAPS) as CapName[];

// Counter scopes (rate_counters.scope). Global counters use subject "*".
export const SCOPE = {
  installClaims: "claims:install",
  installBytes: "bytes:install",
  ipClaims: "claims:ip",
  ipBugs: "bugs:ip",
  globalClaims: "claims:global",
  globalBytes: "bytes:global",
  globalNewSignatures: "new_signatures:global",
  globalBugs: "bugs:global",
} as const;

export function utcDay(nowUnix: number): string {
  return new Date(nowUnix * 1000).toISOString().slice(0, 10);
}

export function secondsUntilNextUtcDay(nowUnix: number): number {
  return 86400 - (nowUnix % 86400);
}

export function rateLimited(nowUnix: number): Response {
  const retry = secondsUntilNextUtcDay(nowUnix);
  return json(
    { error: "rate_limited", message: "Daily limit reached", retry_after_s: retry },
    429,
    { "retry-after": String(retry) },
  );
}

// Adds `amount` to a counter unless that would exceed `cap`. Returns false (and
// changes nothing) when refused.
export async function consume(
  db: D1Database,
  scope: string,
  subject: string,
  day: string,
  amount: number,
  cap: number,
): Promise<boolean> {
  const result = await db
    .prepare(
      `INSERT INTO rate_counters (scope, subject, day, n)
       SELECT ?1, ?2, ?3, ?4 WHERE ?4 <= ?5
       ON CONFLICT (scope, subject, day) DO UPDATE SET n = n + excluded.n
       WHERE rate_counters.n + excluded.n <= ?5`,
    )
    .bind(scope, subject, day, amount, cap)
    .run();
  return result.meta.changes > 0;
}

export interface LimitCheck {
  scope: string;
  subject: string;
  amount: number;
  cap: number;
}

// Consumes the counters in order (most specific first) and stops at the first
// refusal, so a client blocked by its own cap does not eat the global budget.
export async function consumeAll(db: D1Database, day: string, checks: LimitCheck[]): Promise<LimitCheck | null> {
  for (const check of checks) {
    if (!(await consume(db, check.scope, check.subject, day, check.amount, check.cap))) return check;
  }
  return null;
}

export function installCaps(caps: Caps, channel: Channel): { claims: number; bytes: number } {
  return channel === "release"
    ? { claims: caps.install_claims, bytes: caps.install_artifact_bytes }
    : { claims: caps.install_claims_dev, bytes: caps.install_artifact_bytes_dev };
}

// ---------------------------------------------------------------------------
// Settings (kill switch, caps) and daily IP salts, all in the settings table.

export interface Settings {
  accepting: boolean;
  disable_until_unix: number | null;
  caps: Caps;
  salts: Map<string, string>; // UTC day -> salt (hex)
}

export async function loadSettings(db: D1Database): Promise<Settings> {
  const { results } = await db.prepare("SELECT key, value FROM settings").all<{ key: string; value: string }>();
  const settings: Settings = { accepting: true, disable_until_unix: null, caps: { ...DEFAULT_CAPS }, salts: new Map() };
  for (const { key, value } of results) {
    if (key === "accepting") settings.accepting = value === "true";
    else if (key === "disable_until_unix") settings.disable_until_unix = value === "null" ? null : Number(value);
    else if (key.startsWith("cap:")) {
      const name = key.slice(4) as CapName;
      if (CAP_NAMES.includes(name)) settings.caps[name] = Number(value);
    } else if (key.startsWith("ip_salt:")) settings.salts.set(key.slice(8), value);
  }
  return settings;
}

export async function saveSettings(db: D1Database, patch: SettingsPatch): Promise<void> {
  const entries: Array<[string, string]> = [];
  if (patch.accepting !== undefined) entries.push(["accepting", String(patch.accepting)]);
  if (patch.disable_until_unix !== undefined) entries.push(["disable_until_unix", String(patch.disable_until_unix)]);
  for (const [name, value] of Object.entries(patch.caps ?? {})) entries.push([`cap:${name}`, String(value)]);
  if (entries.length === 0) return;
  await db.batch(
    entries.map(([key, value]) =>
      db
        .prepare("INSERT INTO settings (key, value) VALUES (?1, ?2) ON CONFLICT (key) DO UPDATE SET value = excluded.value")
        .bind(key, value),
    ),
  );
}

// ---------------------------------------------------------------------------
// IP pseudonyms: HMAC with a random salt of the day. The salt is deleted by
// the cron two days later, after which old hashes can no longer be linked to
// an address, even with the Worker secret.

async function dailySalt(db: D1Database, day: string): Promise<string> {
  const key = `ip_salt:${day}`;
  const fresh = toHex(crypto.getRandomValues(new Uint8Array(32)));
  const [, selected] = await db.batch<{ value: string }>([
    db.prepare("INSERT INTO settings (key, value) VALUES (?1, ?2) ON CONFLICT (key) DO NOTHING").bind(key, fresh),
    db.prepare("SELECT value FROM settings WHERE key = ?1").bind(key),
  ]);
  const value = selected?.results[0]?.value;
  if (!value) throw new Error("daily salt unavailable");
  return value;
}

export async function ipHash(
  env: { INSTALL_HASH_KEY?: string },
  db: D1Database,
  ip: string,
  day: string,
  knownSalts?: Map<string, string>,
): Promise<string> {
  const secret = requireSecret(env.INSTALL_HASH_KEY, "INSTALL_HASH_KEY");
  const salt = knownSalts?.get(day) ?? (await dailySalt(db, day));
  const key = await hmacSha256(utf8(secret), utf8(`d2v-ip|${day}|${salt}`));
  return toHex(await hmacSha256(key, utf8(ip)));
}

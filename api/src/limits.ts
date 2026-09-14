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
// Counters already taken stay taken: a refusal writes nothing more.
export async function consumeAll(db: D1Database, day: string, checks: LimitCheck[]): Promise<LimitCheck | null> {
  for (const check of checks) {
    if (!(await consume(db, check.scope, check.subject, day, check.amount, check.cap))) return check;
  }
  return null;
}

// Gives back an amount taken by consume (never below zero).
export async function release(db: D1Database, scope: string, subject: string, day: string, amount: number): Promise<void> {
  await db
    .prepare("UPDATE rate_counters SET n = n - ?4 WHERE scope = ?1 AND subject = ?2 AND day = ?3 AND n >= ?4")
    .bind(scope, subject, day, amount)
    .run();
}

// Like consumeAll, but a refusal gives back the counters already taken, so a
// refused request is charged nothing. A refusal costs extra writes: use it only
// where it cannot be repeated cheaply (after a stored upload).
export async function consumeAllOrNothing(db: D1Database, day: string, checks: LimitCheck[]): Promise<LimitCheck | null> {
  const taken: LimitCheck[] = [];
  for (const check of checks) {
    if (!(await consume(db, check.scope, check.subject, day, check.amount, check.cap))) {
      for (const t of taken) await release(db, t.scope, t.subject, day, t.amount);
      return check;
    }
    taken.push(check);
  }
  return null;
}

// Read-only: whether every counter could still take its amount. Lets a route
// refuse before reading a body; the atomic consume still decides afterwards.
export async function hasRoom(db: D1Database, day: string, checks: LimitCheck[]): Promise<boolean> {
  if (checks.length === 0) return true;
  const results = await db.batch<{ n: number }>(
    checks.map((c) =>
      db.prepare("SELECT n FROM rate_counters WHERE scope = ?1 AND subject = ?2 AND day = ?3").bind(c.scope, c.subject, day),
    ),
  );
  return checks.every((c, i) => (results[i]?.results[0]?.n ?? 0) + c.amount <= c.cap);
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
// Network keys for the per-IP caps. CF-Connecting-IP is a single address, but
// an IPv6 host controls a whole prefix (a VPS gets a /64, a free tunnel broker
// a /48), so counting full addresses would let one machine bypass the caps.
// IPv4 addresses, and IPv4-mapped IPv6, are counted as they are. IPv6 is
// counted per prefix:
//  - /48 for claims: the console network stack is IPv4-only (VitaSDK has no
//    AF_INET6), so real players never share a /48 counter;
//  - /64 for bug reports: browsers on home IPv6, where an ISP packs many
//    customers into one /48.

export type Ipv6Prefix = 48 | 64;

export function networkKey(ip: string | null, v6Prefix: Ipv6Prefix): string {
  if (!ip) return "unknown";
  const v4 = parseIpv4(ip);
  if (v4) return v4.join(".");
  const groups = parseIpv6(ip);
  if (!groups) return `other:${ip.slice(0, 64).toLowerCase()}`;
  if (groups.slice(0, 5).every((g) => g === 0) && groups[5] === 0xffff) {
    const [hi, lo] = [groups[6]!, groups[7]!];
    return [hi >> 8, hi & 0xff, lo >> 8, lo & 0xff].join(".");
  }
  return `${groups
    .slice(0, v6Prefix / 16)
    .map((g) => g.toString(16))
    .join(":")}::/${v6Prefix}`;
}

function parseIpv4(text: string): number[] | null {
  const match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(text);
  if (!match) return null;
  const octets = match.slice(1).map(Number);
  return octets.every((o) => o <= 255) ? octets : null;
}

// The eight 16-bit groups of an IPv6 address, or null. Accepts "::"
// compression, a dotted IPv4 tail and a zone suffix ("%eth0").
function parseIpv6(text: string): number[] | null {
  const address = text.split("%", 1)[0]!.toLowerCase();
  if (!/^[0-9a-f:.]{2,45}$/.test(address)) return null;
  const halves = address.split("::");
  if (halves.length > 2) return null;
  const groups = (part: string, dottedTail: boolean): number[] | null => {
    if (part === "") return [];
    const items = part.split(":");
    const out: number[] = [];
    for (const [i, item] of items.entries()) {
      if (dottedTail && i === items.length - 1 && item.includes(".")) {
        const v4 = parseIpv4(item);
        if (!v4) return null;
        out.push((v4[0]! << 8) | v4[1]!, (v4[2]! << 8) | v4[3]!);
      } else if (/^[0-9a-f]{1,4}$/.test(item)) {
        out.push(parseInt(item, 16));
      } else {
        return null;
      }
    }
    return out;
  };
  if (halves.length === 1) {
    const all = groups(address, true);
    return all?.length === 8 ? all : null;
  }
  const head = groups(halves[0]!, false);
  const tail = groups(halves[1]!, true);
  if (!head || !tail) return null;
  const zeros = 8 - head.length - tail.length;
  return zeros >= 1 ? [...head, ...new Array<number>(zeros).fill(0), ...tail] : null;
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

// Pseudonym of a network key (see networkKey) for the given UTC day.
export async function ipHash(
  env: { INSTALL_HASH_KEY?: string },
  db: D1Database,
  network: string,
  day: string,
  knownSalts?: Map<string, string>,
): Promise<string> {
  const secret = requireSecret(env.INSTALL_HASH_KEY, "INSTALL_HASH_KEY");
  const salt = knownSalts?.get(day) ?? (await dailySalt(db, day));
  const key = await hmacSha256(utf8(secret), utf8(`d2v-ip|${day}|${salt}`));
  return toHex(await hmacSha256(key, utf8(network)));
}

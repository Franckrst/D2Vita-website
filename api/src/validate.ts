// Strict validation of every JSON payload the API accepts. Unknown fields are
// rejected everywhere ("champ inconnu = 400"). Errors carry the JSON path.

import { CAP_NAMES } from "./limits";
import { ARTIFACT_NAMES, CHANNELS, KINDS, REGIONS, type Claim, type Kind } from "./types";

export type Validation<T> = { ok: true; value: T } | { ok: false; error: string };

class Invalid extends Error {}

function fail(path: string, message: string): never {
  throw new Invalid(`${path}: ${message}`);
}

function run<T>(fn: () => T): Validation<T> {
  try {
    return { ok: true, value: fn() };
  } catch (e) {
    if (e instanceof Invalid) return { ok: false, error: e.message };
    throw e;
  }
}

function child(path: string, key: string | number): string {
  if (typeof key === "number") return `${path}[${key}]`;
  return path ? `${path}.${key}` : key;
}

type Check = (value: unknown, path: string) => void;

function object(value: unknown, path: string, required: readonly string[], optional: readonly string[] = []) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    fail(path || "body", "must be an object");
  }
  const o = value as Record<string, unknown>;
  for (const key of Object.keys(o)) {
    if (!required.includes(key) && !optional.includes(key)) fail(child(path, key), "unknown field");
  }
  for (const key of required) {
    if (!(key in o)) fail(child(path, key), "is required");
  }
  return o;
}

function pattern(re: RegExp, what: string): Check {
  return (value, path) => {
    if (typeof value !== "string" || !re.test(value)) fail(path, `must be ${what}`);
  };
}

function oneOf(values: readonly string[]): Check {
  return (value, path) => {
    if (typeof value !== "string" || !values.includes(value)) fail(path, `must be one of ${values.join(", ")}`);
  };
}

function integer(min: number, max: number): Check {
  return (value, path) => {
    if (typeof value !== "number" || !Number.isInteger(value) || value < min || value > max) {
      fail(path, `must be an integer in [${min}, ${max}]`);
    }
  };
}

function boolean(value: unknown, path: string): void {
  if (typeof value !== "boolean") fail(path, "must be a boolean");
}

function nullable(check: Check): Check {
  return (value, path) => {
    if (value !== null) check(value, path);
  };
}

function array(maxItems: number, item: Check): Check {
  return (value, path) => {
    if (!Array.isArray(value)) fail(path, "must be an array");
    if (value.length > maxItems) fail(path, `too many items (max ${maxItems})`);
    value.forEach((v, i) => item(v, child(path, i)));
  };
}

function charCount(text: string): number {
  let n = 0;
  for (const _ of text) n++;
  return n;
}

// Free text: code point count in [min, max]; `blankOk` allows whitespace-only.
function text(min: number, max: number, blankOk = false): Check {
  return (value, path) => {
    if (typeof value !== "string") fail(path, "must be a string");
    const n = charCount(value);
    if (n < min || n > max) fail(path, `length must be in [${min}, ${max}] characters`);
    if (!blankOk && min > 0 && value.trim() === "") fail(path, "must not be blank");
  };
}

// ---------------------------------------------------------------------------
// Claim v1 (spec section 4.4).

const ULID = /^[0-9A-HJKMNP-TV-Z]{26}$/;
const INSTALL_ID = /^[0-9a-f]{32}$/;
const BUILD_ID = /^[0-9]+\.[0-9]+\.[0-9]+\+[0-9a-f]{12}(-dirty)?$/;
const VERSION = /^[0-9]+\.[0-9]+\.[0-9]+$/;
const ADDRESS = /^[A-Za-z0-9_.]{1,32}\+0x[0-9a-f]{1,8}$/;
const OFFSET = /^0x[0-9a-f]{1,8}$/;
const MODULE = /^[A-Za-z0-9_.]{1,32}$/;
const PLATFORM_FIELD = /^[A-Za-z0-9_.-]{1,32}$/;
const SIGNATURE_ID = /^S[A-Z2-7]{15}$/;

// Printable ASCII without "|" (the canon separator).
function safeText(max: number): Check {
  return pattern(new RegExp(`^[\\x20-\\x7b\\x7d\\x7e]{1,${max}}$`), `printable ASCII without '|' (1-${max} chars)`);
}

const address = pattern(ADDRESS, "an address '<module>+0x<hex>'");

function buildId(value: unknown, path: string): void {
  pattern(BUILD_ID, "a build id '<major>.<minor>.<patch>+<12 hex>[-dirty]'")(value, path);
  if ((value as string).length > 64) fail(path, "is too long");
}

const codeLocation: Check = (value, path) => {
  const o = object(value, path, ["region", "module", "offset"]);
  oneOf(REGIONS)(o.region, child(path, "region"));
  nullable(pattern(MODULE, "a module name"))(o.module, child(path, "module"));
  pattern(OFFSET, "a lower-case hex offset '0x…'")(o.offset, child(path, "offset"));
};

const FEATURES: Record<Kind, Record<string, Check>> = {
  halt: {
    code: nullable(integer(0, 0xffffffff)),
    location: nullable(safeText(128)),
    frames: array(16, address),
  },
  guest_fault: {
    exception: nullable(safeText(64)),
    thread: nullable(oneOf(["main", "worker"])),
    eip: nullable(address),
    frames: array(16, address),
  },
  host_fault: {
    stop_reason: nullable(safeText(64)),
    thread_name: nullable(safeText(64)),
    pc: nullable(codeLocation),
    lr: nullable(codeLocation),
    guest_frames: array(8, address),
    redaction: nullable(oneOf(["clean", "withheld"])),
  },
  abnormal_exit: {
    reason: nullable(safeText(64)),
    code: nullable(integer(-0x80000000, 0xffffffff)),
    import: nullable(safeText(128)),
    frames: array(16, address),
  },
  hang: {
    stalled_beats: nullable(integer(0, 1_000_000)),
    eip: nullable(address),
    runner_state: nullable(safeText(64)),
  },
};

const CLAIM_FIELDS = [
  "v",
  "report_id",
  "install_id",
  "build_id",
  "channel",
  "platform",
  "session",
  "kind",
  "features",
  "hints",
  "artifacts",
] as const;

export function validateClaim(input: unknown): Validation<Claim> {
  return run(() => {
    if (typeof input !== "object" || input === null || Array.isArray(input)) fail("claim", "must be an object");
    const c = object(input, "", CLAIM_FIELDS, ["redactions"]);
    if (c.v !== 1) fail("v", "must be 1");
    pattern(ULID, "a 26-character Crockford ULID")(c.report_id, "report_id");
    pattern(INSTALL_ID, "32 lower-case hex characters")(c.install_id, "install_id");
    buildId(c.build_id, "build_id");
    oneOf(CHANNELS)(c.channel, "channel");

    const platform = object(c.platform, "platform", ["model", "fw"]);
    pattern(PLATFORM_FIELD, "a short identifier")(platform.model, "platform.model");
    pattern(PLATFORM_FIELD, "a short identifier")(platform.fw, "platform.fw");

    const session = object(c.session, "session", ["started_unix", "uptime_s", "online"]);
    integer(0, Number.MAX_SAFE_INTEGER)(session.started_unix, "session.started_unix");
    integer(0, Number.MAX_SAFE_INTEGER)(session.uptime_s, "session.uptime_s");
    boolean(session.online, "session.online");

    oneOf(KINDS)(c.kind, "kind");
    const rules = FEATURES[c.kind as Kind];
    const features = object(c.features, "features", [], Object.keys(rules));
    for (const [key, check] of Object.entries(rules)) {
      if (key in features) check(features[key], child("features", key));
    }

    array(KINDS.length, oneOf(KINDS))(c.hints, "hints");

    array(ARTIFACT_NAMES.length, (item, path) => {
      const a = object(item, path, ["name", "bytes"]);
      oneOf(ARTIFACT_NAMES)(a.name, child(path, "name"));
      integer(0, 0x7fffffff)(a.bytes, child(path, "bytes"));
    })(c.artifacts, "artifacts");
    const names = (c.artifacts as Array<{ name: string }>).map((a) => a.name);
    if (new Set(names).size !== names.length) fail("artifacts", "duplicate artifact name");

    if ("redactions" in c) integer(0, 1_000_000)(c.redactions, "redactions");
    return input as Claim;
  });
}

// ---------------------------------------------------------------------------
// POST /v1/reports/{id}/complete: {"v":1,"artifacts":[…]}. The spec does not
// fix the item shape: names ("crash_txt") and {name, bytes} objects are both
// accepted. Every name must have been requested by the upload token.

export function validateComplete(input: unknown, requested: readonly string[]): Validation<string[]> {
  return run(() => {
    const body = object(input, "", ["v", "artifacts"]);
    if (body.v !== 1) fail("v", "must be 1");
    const names: string[] = [];
    array(ARTIFACT_NAMES.length, (item, path) => {
      let name: unknown = item;
      if (typeof item === "object" && item !== null) {
        const o = object(item, path, ["name"], ["bytes"]);
        if ("bytes" in o) integer(0, 0x7fffffff)(o.bytes, child(path, "bytes"));
        name = o.name;
        path = child(path, "name");
      }
      oneOf(requested)(name, path);
      names.push(name as string);
    })(body.artifacts, "artifacts");
    if (new Set(names).size !== names.length) fail("artifacts", "duplicate artifact name");
    return names;
  });
}

// ---------------------------------------------------------------------------
// Public bug report (POST /v1/bugs).

export interface BugInput {
  title: string;
  description: string;
  version: string;
  contact?: string | null;
  lang: "fr" | "en";
  turnstile_token: string;
}

export const BUG_LANGS = ["fr", "en"] as const;

export function validateBug(input: unknown): Validation<BugInput> {
  return run(() => {
    const b = object(input, "", ["title", "description", "version", "lang", "turnstile_token"], ["contact"]);
    text(1, 120)(b.title, "title");
    text(1, 4000)(b.description, "description");
    text(1, 40)(b.version, "version");
    if ("contact" in b) nullable(text(0, 120, true))(b.contact, "contact");
    oneOf(BUG_LANGS)(b.lang, "lang");
    text(1, 2048)(b.turnstile_token, "turnstile_token");
    return input as BugInput;
  });
}

// ---------------------------------------------------------------------------
// Admin payloads.

function httpsUrl(value: unknown, path: string): void {
  if (typeof value !== "string" || value.length > 512) fail(path, "must be an https URL (max 512 chars)");
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    fail(path, "must be an https URL");
  }
  if (url.protocol !== "https:") fail(path, "must be an https URL");
}

function requireNonEmpty(o: Record<string, unknown>): void {
  if (Object.keys(o).length === 0) fail("body", "empty patch");
}

export interface SignaturePatch {
  status?: "open" | "fixed" | "ignored";
  fixed_in_version?: string | null;
  merged_into?: string | null;
  issue_url?: string | null;
  note?: string | null;
  resample?: true;
}

export function validateSignaturePatch(input: unknown): Validation<SignaturePatch> {
  return run(() => {
    const p = object(input, "", [], ["status", "fixed_in_version", "merged_into", "issue_url", "note", "resample"]);
    requireNonEmpty(p);
    if ("status" in p) oneOf(["open", "fixed", "ignored"])(p.status, "status");
    if ("fixed_in_version" in p) nullable(pattern(VERSION, "a version 'X.Y.Z'"))(p.fixed_in_version, "fixed_in_version");
    if ("merged_into" in p) nullable(pattern(SIGNATURE_ID, "a signature id"))(p.merged_into, "merged_into");
    if ("issue_url" in p) nullable(httpsUrl)(p.issue_url, "issue_url");
    if ("note" in p) nullable(text(0, 4000, true))(p.note, "note");
    if ("resample" in p && p.resample !== true) fail("resample", "must be true");
    return input as SignaturePatch;
  });
}

export interface BugPatch {
  status?: "open" | "fixed" | "ignored";
  issue_url?: string | null;
  note?: string | null;
}

export function validateBugPatch(input: unknown): Validation<BugPatch> {
  return run(() => {
    const p = object(input, "", [], ["status", "issue_url", "note"]);
    requireNonEmpty(p);
    if ("status" in p) oneOf(["open", "fixed", "ignored"])(p.status, "status");
    if ("issue_url" in p) nullable(httpsUrl)(p.issue_url, "issue_url");
    if ("note" in p) nullable(text(0, 4000, true))(p.note, "note");
    return input as BugPatch;
  });
}

export interface BuildRegistration {
  build_id: string;
  version: string;
  channel: "release" | "dev" | "test";
}

export function validateBuildRegistration(input: unknown): Validation<BuildRegistration> {
  return run(() => {
    const b = object(input, "", ["build_id", "version", "channel"]);
    buildId(b.build_id, "build_id");
    pattern(VERSION, "a version 'X.Y.Z'")(b.version, "version");
    if ((b.build_id as string).split("+")[0] !== b.version) fail("version", "must be the version part of build_id");
    oneOf(CHANNELS)(b.channel, "channel");
    return input as BuildRegistration;
  });
}

export interface SettingsPatch {
  accepting?: boolean;
  disable_until_unix?: number | null;
  caps?: Partial<Record<(typeof CAP_NAMES)[number], number>>;
}

export function validateSettingsPatch(input: unknown): Validation<SettingsPatch> {
  return run(() => {
    const s = object(input, "", [], ["accepting", "disable_until_unix", "caps"]);
    requireNonEmpty(s);
    if ("accepting" in s) boolean(s.accepting, "accepting");
    if ("disable_until_unix" in s) nullable(integer(0, Number.MAX_SAFE_INTEGER))(s.disable_until_unix, "disable_until_unix");
    if ("caps" in s) {
      const caps = object(s.caps, "caps", [], CAP_NAMES);
      for (const [key, value] of Object.entries(caps)) integer(0, Number.MAX_SAFE_INTEGER)(value, child("caps", key));
    }
    return input as SettingsPatch;
  });
}

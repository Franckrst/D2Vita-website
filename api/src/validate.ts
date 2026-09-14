// Strict validation of every JSON payload the API accepts. Unknown fields are
// rejected everywhere ("champ inconnu = 400"). Errors carry the JSON path.

import { CAP_NAMES } from "./limits";
import {
  ARTIFACT_MAX_BYTES,
  ARTIFACT_NAMES,
  CHANNELS,
  EXIT_REASONS,
  KINDS,
  PLATFORM_MODELS,
  REGIONS,
  SEALED_MIN_BYTES,
  type ArtifactName,
  type Claim,
  type Kind,
} from "./types";

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

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
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
// Claim v1: contract/schemas/claim.v1.schema.json (design section 4.4).
//
// The Worker validates without a schema library, so every rule of that schema
// is written out here. test/contract-claims.test.ts holds this code against the
// schema itself: the 26 valid and 70 invalid contract vectors, a mutation sweep
// comparing both on every mutant of every vector, and an equality check between
// the patterns below and the patterns of the schema.

const VERSION = /^[0-9]+\.[0-9]+\.[0-9]+$/;
const SIGNATURE_ID = /^S[A-Z2-7]{15}$/;

// Copied character for character from the schema; never edit one alone.
export const CLAIM_PATTERNS = {
  ReportId: /^[0-7][0-9A-HJKMNP-TV-Z]{25}$/,
  InstallId: /^[0-9a-f]{32}$/,
  BuildId: /^[0-9]+\.[0-9]+\.[0-9]+\+[0-9a-f]{12}(-dirty)?$/,
  Hex32: /^0x(0|[1-9a-f][0-9a-f]{0,7})$/,
  ModuleName: /^[A-Za-z0-9_.]{1,32}$/,
  Address: /^(Game|ABS|(?!(game|abs)\+)[a-z0-9_]{1,32})\+0x(0|[1-9a-f][0-9a-f]{0,7})$/,
  SourceLocation: /^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}:(0|[1-9][0-9]{0,9})$/,
  ThreadName: /^[ -~]{0,32}$/,
  ImportName: /^[A-Za-z0-9_.!@?$#]{1,128}$/,
  RunnerState: /^[A-Za-z0-9_.-]{1,32}$/,
  PlatformFw: /^([0-9]{1,2}\.[0-9]{2}|unknown)$/,
} as const;

const U32_MAX = 4294967295;
const u32 = integer(0, U32_MAX);
const address = pattern(CLAIM_PATTERNS.Address, "an address '<module>+0x<hex>'");
const hex32 = pattern(CLAIM_PATTERNS.Hex32, "a 32-bit value '0x<lower-case hex>'");

function buildId(value: unknown, path: string): void {
  pattern(CLAIM_PATTERNS.BuildId, "a build id '<major>.<minor>.<patch>+<12 hex>[-dirty]'")(value, path);
  if (charCount(value as string) > 64) fail(path, "is too long");
}

function frames(maxItems: number): Check {
  return array(maxItems, address);
}

// Host address: the module of a known region is the region name itself.
const hostAddress: Check = (value, path) => {
  const o = object(value, path, ["region", "module", "offset"]);
  oneOf(REGIONS)(o.region, child(path, "region"));
  pattern(CLAIM_PATTERNS.ModuleName, "a module name")(o.module, child(path, "module"));
  hex32(o.offset, child(path, "offset"));
  if (o.region !== "sysmodule" && o.module !== o.region) {
    fail(child(path, "module"), `must be '${String(o.region)}' for that region`);
  }
};

// Every key is required (null means unknown).
const FEATURES: Record<Kind, Record<string, Check>> = {
  halt: {
    code: u32,
    location: nullable(pattern(CLAIM_PATTERNS.SourceLocation, "a source location 'File.cpp:line'")),
    frames: frames(16),
  },
  guest_fault: {
    exception: nullable(hex32),
    thread: oneOf(["main", "worker"]),
    eip: address,
    frames: frames(16),
  },
  host_fault: {
    stop_reason: nullable(hex32),
    thread_name: nullable(pattern(CLAIM_PATTERNS.ThreadName, "at most 32 printable ASCII characters")),
    pc: hostAddress,
    lr: hostAddress,
    guest_frames: frames(8),
    redaction: oneOf(["clean", "withheld"]),
  },
  abnormal_exit: {
    reason: oneOf(EXIT_REASONS),
    code: nullable(u32),
    import: nullable(pattern(CLAIM_PATTERNS.ImportName, "an import name")),
    frames: frames(16),
  },
  hang: {
    stalled_beats: integer(2, 1_000_000),
    eip: nullable(address),
    runner_state: nullable(pattern(CLAIM_PATTERNS.RunnerState, "a runner state")),
  },
};

// A hint is another kind of evidence found for the same run, always strictly
// less severe than the kind itself (host_fault > halt > abnormal_exit >
// guest_fault > hang).
const HINTS: Record<Kind, readonly Kind[]> = {
  host_fault: ["halt", "abnormal_exit", "guest_fault", "hang"],
  halt: ["abnormal_exit", "guest_fault", "hang"],
  abnormal_exit: ["guest_fault", "hang"],
  guest_fault: ["hang"],
  hang: [],
};

const MAX_HINTS = 4;

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
    if (!isObject(input)) fail("claim", "must be an object");
    const c = object(input, "", CLAIM_FIELDS, ["redactions"]);
    if (c.v !== 1) fail("v", "must be 1");
    pattern(CLAIM_PATTERNS.ReportId, "a 26-character Crockford ULID")(c.report_id, "report_id");
    pattern(CLAIM_PATTERNS.InstallId, "32 lower-case hex characters")(c.install_id, "install_id");
    buildId(c.build_id, "build_id");
    oneOf(CHANNELS)(c.channel, "channel");

    const platform = object(c.platform, "platform", ["model", "fw"]);
    oneOf(PLATFORM_MODELS)(platform.model, "platform.model");
    pattern(CLAIM_PATTERNS.PlatformFw, "a firmware 'X.YY' or 'unknown'")(platform.fw, "platform.fw");

    const session = object(c.session, "session", ["started_unix", "uptime_s", "online"]);
    u32(session.started_unix, "session.started_unix");
    nullable(u32)(session.uptime_s, "session.uptime_s");
    boolean(session.online, "session.online");

    oneOf(KINDS)(c.kind, "kind");
    const kind = c.kind as Kind;
    const rules = FEATURES[kind];
    const features = object(c.features, "features", Object.keys(rules));
    for (const [key, check] of Object.entries(rules)) check(features[key], child("features", key));

    array(MAX_HINTS, oneOf(HINTS[kind]))(c.hints, "hints");
    const hints = c.hints as string[];
    if (new Set(hints).size !== hints.length) fail("hints", "duplicate hint");

    array(ARTIFACT_NAMES.length, (item, path) => {
      const a = object(item, path, ["name", "bytes"]);
      oneOf(ARTIFACT_NAMES)(a.name, child(path, "name"));
      integer(SEALED_MIN_BYTES, ARTIFACT_MAX_BYTES[a.name as ArtifactName])(a.bytes, child(path, "bytes"));
    })(c.artifacts, "artifacts");
    const names = (c.artifacts as Array<{ name: string }>).map((a) => a.name);
    if (new Set(names).size !== names.length) fail("artifacts", "duplicate artifact name");
    // Only a host_fault whose dump held no secret may offer it (section 4.5).
    if (names.includes("dump") && !(kind === "host_fault" && features.redaction === "clean")) {
      fail("artifacts", "only a host_fault with a clean dump may offer one");
    }

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

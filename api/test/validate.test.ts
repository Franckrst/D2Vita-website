import { describe, expect, it } from "vitest";
import {
  validateBug,
  validateBugPatch,
  validateBuildRegistration,
  validateClaim,
  validateSettingsPatch,
  validateSignaturePatch,
} from "../src/validate";
import { BUILD_ID, bugBody, haltClaim, hostFaultClaim } from "./fixtures";

function expectInvalid(result: { ok: boolean; error?: string }, fragment: string) {
  expect(result.ok).toBe(false);
  expect(result.error).toContain(fragment);
}

describe("validateClaim", () => {
  it("accepts the spec example claim", () => {
    const claim = haltClaim();
    const result = validateClaim(claim);
    expect(result).toEqual({ ok: true, value: claim });
  });

  it("accepts every kind with its features", () => {
    const cases: Array<[string, Record<string, unknown>]> = [
      ["guest_fault", { exception: "ACCESS_VIOLATION", thread: "worker", eip: "Game+0x1", frames: ["Fog+0x2"] }],
      [
        "host_fault",
        {
          stop_reason: "PREFETCH_ABORT",
          thread_name: "d2main",
          pc: { region: "jit", module: null, offset: "0x80001000" },
          lr: null,
          guest_frames: [],
          redaction: "withheld",
        },
      ],
      ["abnormal_exit", { reason: "ExitProcess", code: -1, import: null, frames: [] }],
      ["hang", { stalled_beats: 3, eip: "Game+0x5000", runner_state: "running" }],
    ];
    for (const [kind, features] of cases) {
      const result = validateClaim(haltClaim({ kind, features }));
      expect(result, kind).toMatchObject({ ok: true });
    }
  });

  it("accepts missing optional feature fields and an optional redaction count", () => {
    expect(validateClaim(haltClaim({ features: { code: 904 }, redactions: 2 })).ok).toBe(true);
  });

  it("rejects a non-object body", () => {
    expectInvalid(validateClaim([]), "claim");
    expectInvalid(validateClaim(null), "claim");
  });

  it("rejects an unknown top-level field", () => {
    expectInvalid(validateClaim(haltClaim({ extra: 1 })), "extra");
  });

  it("rejects an unknown feature field", () => {
    expectInvalid(validateClaim(haltClaim({ features: { code: 1, eip: "Game+0x1" } })), "features.eip");
  });

  it("rejects a missing required field", () => {
    const claim = haltClaim();
    delete claim.session;
    expectInvalid(validateClaim(claim), "session");
  });

  it("rejects an unknown kind", () => {
    expectInvalid(validateClaim(haltClaim({ kind: "oops" })), "kind");
  });

  it("rejects a wrong version", () => {
    expectInvalid(validateClaim(haltClaim({ v: 2 })), "v");
  });

  it.each(["Game+1fedf4", "Game+0x1FEDF4", "+0x10", "Game+0x123456789", "Ga me+0x1", "Game|x+0x1"])(
    "rejects the malformed address %j",
    (addr) => {
      expectInvalid(validateClaim(haltClaim({ features: { code: 1, frames: [addr] } })), "features.frames");
    },
  );

  it("rejects more than 16 frames", () => {
    const frames = Array.from({ length: 17 }, (_, i) => `Game+0x${i.toString(16)}`);
    expectInvalid(validateClaim(haltClaim({ features: { code: 1, frames } })), "features.frames");
    expect(validateClaim(haltClaim({ features: { code: 1, frames: frames.slice(0, 16) } })).ok).toBe(true);
  });

  it("rejects more than 8 guest frames on host_fault", () => {
    const guest_frames = Array.from({ length: 9 }, (_, i) => `Game+0x${i + 1}`);
    const claim = hostFaultClaim();
    (claim.features as Record<string, unknown>).guest_frames = guest_frames;
    expectInvalid(validateClaim(claim), "features.guest_frames");
  });

  it.each([
    ["report_id", "01J9Z6T4Q8M3K7V2B5N0XWAYC"], // 25 chars
    ["report_id", "01J9Z6T4Q8M3K7V2B5N0XWAYCI"], // I is not Crockford
    ["install_id", "4F3C9A0E8B7D6C5A4F3E2D1C0B9A8F7E"], // upper case
    ["build_id", "0.1+ab12cd34ef56"],
    ["build_id", "0.1.0+ab12cd34ef5"],
    ["channel", "beta"],
  ])("rejects %s = %j", (field, value) => {
    expectInvalid(validateClaim(haltClaim({ [field]: value })), field);
  });

  it("accepts a dirty build id", () => {
    expect(validateClaim(haltClaim({ build_id: `${BUILD_ID}-dirty` })).ok).toBe(true);
  });

  it("rejects a text field containing the canon separator", () => {
    expectInvalid(validateClaim(haltClaim({ features: { code: 1, location: "a|b.cpp:1" } })), "features.location");
  });

  it("rejects an unknown pc region and a malformed offset", () => {
    const bad = hostFaultClaim();
    (bad.features as Record<string, unknown>).pc = { region: "kernel", module: null, offset: "0x1" };
    expectInvalid(validateClaim(bad), "features.pc.region");
    const bad2 = hostFaultClaim();
    (bad2.features as Record<string, unknown>).lr = { region: "eboot", module: "eboot.bin", offset: "1a" };
    expectInvalid(validateClaim(bad2), "features.lr.offset");
  });

  it("rejects duplicate or unknown artifact names and bad sizes", () => {
    expectInvalid(
      validateClaim(haltClaim({ artifacts: [{ name: "crash_log", bytes: 1 }, { name: "crash_log", bytes: 2 }] })),
      "artifacts",
    );
    expectInvalid(validateClaim(haltClaim({ artifacts: [{ name: "savegame", bytes: 1 }] })), "artifacts[0].name");
    expectInvalid(validateClaim(haltClaim({ artifacts: [{ name: "dump", bytes: -1 }] })), "artifacts[0].bytes");
    expectInvalid(validateClaim(haltClaim({ artifacts: [{ name: "dump", bytes: 1.5 }] })), "artifacts[0].bytes");
  });

  it("rejects unknown hints", () => {
    expectInvalid(validateClaim(haltClaim({ hints: ["meteor"] })), "hints[0]");
  });

  it("rejects non-boolean session.online", () => {
    expectInvalid(
      validateClaim(haltClaim({ session: { started_unix: 1, uptime_s: 1, online: "no" } })),
      "session.online",
    );
  });
});

describe("validateBug", () => {
  it("accepts a bug with and without contact", () => {
    expect(validateBug(bugBody()).ok).toBe(true);
    const noContact = bugBody();
    delete noContact.contact;
    expect(validateBug(noContact).ok).toBe(true);
    expect(validateBug(bugBody({ contact: "" })).ok).toBe(true);
    expect(validateBug(bugBody({ contact: null })).ok).toBe(true);
  });

  it("enforces the length limits, counted in characters", () => {
    expect(validateBug(bugBody({ title: "é".repeat(120) })).ok).toBe(true);
    expectInvalid(validateBug(bugBody({ title: "x".repeat(121) })), "title");
    expect(validateBug(bugBody({ description: "x".repeat(4000) })).ok).toBe(true);
    expectInvalid(validateBug(bugBody({ description: "x".repeat(4001) })), "description");
    expectInvalid(validateBug(bugBody({ version: "x".repeat(41) })), "version");
    expectInvalid(validateBug(bugBody({ contact: "x".repeat(121) })), "contact");
  });

  it("rejects empty required text, unknown lang, unknown fields and a missing token", () => {
    expectInvalid(validateBug(bugBody({ title: "   " })), "title");
    expectInvalid(validateBug(bugBody({ lang: "de" })), "lang");
    expectInvalid(validateBug(bugBody({ admin: true })), "admin");
    const noToken = bugBody();
    delete noToken.turnstile_token;
    expectInvalid(validateBug(noToken), "turnstile_token");
  });
});

describe("admin payloads", () => {
  it("validates a signature patch", () => {
    expect(validateSignaturePatch({ status: "fixed", fixed_in_version: "0.2.0" }).ok).toBe(true);
    expect(validateSignaturePatch({ merged_into: "SZYGIRBIXGHOM3AH", note: "same root cause" }).ok).toBe(true);
    expect(validateSignaturePatch({ merged_into: null, issue_url: null, resample: true }).ok).toBe(true);
    expect(validateSignaturePatch({ issue_url: "https://github.com/Franckrst/D2Vita/issues/1" }).ok).toBe(true);
    expectInvalid(validateSignaturePatch({ status: "regressed" }), "status");
    expectInvalid(validateSignaturePatch({ status: "fixed", fixed_in_version: "0.2" }), "fixed_in_version");
    expectInvalid(validateSignaturePatch({ merged_into: "S123" }), "merged_into");
    expectInvalid(validateSignaturePatch({ issue_url: "javascript:alert(1)" }), "issue_url");
    expectInvalid(validateSignaturePatch({ resample: false }), "resample");
    expectInvalid(validateSignaturePatch({ count: 0 }), "count");
    expectInvalid(validateSignaturePatch({}), "empty");
  });

  it("validates a bug patch", () => {
    expect(validateBugPatch({ status: "fixed", issue_url: "https://github.com/Franckrst/D2Vita/issues/2" }).ok).toBe(
      true,
    );
    expectInvalid(validateBugPatch({ status: "done" }), "status");
    expectInvalid(validateBugPatch({ title: "x" }), "title");
  });

  it("validates a build registration", () => {
    expect(validateBuildRegistration({ build_id: BUILD_ID, version: "0.1.0", channel: "test" }).ok).toBe(true);
    expectInvalid(validateBuildRegistration({ build_id: BUILD_ID, version: "0.2.0", channel: "dev" }), "version");
    expectInvalid(validateBuildRegistration({ build_id: "nope", version: "0.1.0", channel: "dev" }), "build_id");
    expectInvalid(validateBuildRegistration({ build_id: BUILD_ID, version: "0.1.0" }), "channel");
  });

  it("validates a settings patch", () => {
    expect(validateSettingsPatch({ accepting: false, disable_until_unix: 1789290000 }).ok).toBe(true);
    expect(validateSettingsPatch({ caps: { install_claims: 5, global_bugs: 0 } }).ok).toBe(true);
    expectInvalid(validateSettingsPatch({ accepting: "no" }), "accepting");
    expectInvalid(validateSettingsPatch({ caps: { install_claims: -1 } }), "caps.install_claims");
    expectInvalid(validateSettingsPatch({ caps: { made_up: 1 } }), "caps.made_up");
    expectInvalid(validateSettingsPatch({ ip_salt: "x" }), "ip_salt");
  });
});

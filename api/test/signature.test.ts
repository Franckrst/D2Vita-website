// Cases written from the spec section 5.3 table. The official vectors of
// contract/vectors/signatures.v1.json are plugged in during wave 2.
// Expected ids were computed independently with Python:
//   "S" + base64.b32encode(hashlib.sha256(canon.encode()).digest()).decode()[:15]
import { describe, expect, it } from "vitest";
import { canon, RULES_VERSION, signatureId, type SignatureInput } from "../src/signature";

const BUILD = "0.1.0+ab12cd34ef56";

function input(kind: SignatureInput["kind"], features: Record<string, unknown>): SignatureInput {
  return { kind, build_id: BUILD, features } as SignatureInput;
}

describe("canon (rules v1)", () => {
  it("is rules version 1", () => {
    expect(RULES_VERSION).toBe(1);
  });

  it("halt: code, null location as '-', first 3 frames joined by ','", () => {
    const c = canon(
      input("halt", {
        code: 1420,
        location: null,
        frames: ["Game+0x1fedf4", "Game+0x451c23", "Game+0x44f570", "Game+0x1"],
      }),
    );
    expect(c).toBe("halt|1420|-|Game+0x1fedf4,Game+0x451c23,Game+0x44f570");
  });

  it("halt: location kept, no frames gives '-'", () => {
    expect(canon(input("halt", { code: 904, location: "Codec.cpp:1377", frames: [] }))).toBe(
      "halt|904|Codec.cpp:1377|-",
    );
  });

  it("halt: missing fields are '-'", () => {
    expect(canon(input("halt", {}))).toBe("halt|-|-|-");
  });

  it("guest_fault: exception, eip, first 2 frames", () => {
    const c = canon(
      input("guest_fault", {
        exception: "ACCESS_VIOLATION",
        thread: "main",
        eip: "Game+0x12ab",
        frames: ["Game+0x1", "Game+0x2", "Game+0x3"],
      }),
    );
    expect(c).toBe("gfault|ACCESS_VIOLATION|Game+0x12ab|Game+0x1,Game+0x2");
  });

  it("guest_fault: fewer frames than asked keeps the ones present", () => {
    expect(canon(input("guest_fault", { exception: "X", eip: "Game+0x1", frames: ["Fog+0x9"] }))).toBe(
      "gfault|X|Game+0x1|Fog+0x9",
    );
  });

  it("host_fault in the JIT: stop_reason and first 3 guest frames", () => {
    const c = canon(
      input("host_fault", {
        stop_reason: "PREFETCH_ABORT",
        thread_name: "d2main",
        pc: { region: "jit", module: null, offset: "0x1000" },
        lr: { region: "jit", module: null, offset: "0x2000" },
        guest_frames: ["Game+0x10", "D2Common+0x20", "Fog+0x30", "Game+0x40"],
        redaction: "clean",
      }),
    );
    expect(c).toBe("hfault_jit|PREFETCH_ABORT|Game+0x10,D2Common+0x20,Fog+0x30");
  });

  it("host_fault in the eboot: per build, pc and lr offsets", () => {
    const c = canon(
      input("host_fault", {
        stop_reason: "DATA_ABORT",
        pc: { region: "eboot", module: "eboot.bin", offset: "0x1a2b" },
        lr: { region: "eboot", module: "eboot.bin", offset: "0x3c4d" },
        guest_frames: ["Game+0x10"],
      }),
    );
    expect(c).toBe(`hfault|${BUILD}|0x1a2b|0x3c4d`);
  });

  it("host_fault in the eboot with no lr", () => {
    const c = canon(input("host_fault", { pc: { region: "eboot", module: "eboot.bin", offset: "0x10" }, lr: null }));
    expect(c).toBe(`hfault|${BUILD}|0x10|-`);
  });

  it("host_fault in a system module: module and pc offset", () => {
    const c = canon(
      input("host_fault", {
        pc: { region: "sysmodule", module: "SceLibKernel", offset: "0x42" },
        lr: { region: "eboot", module: "eboot.bin", offset: "0x99" },
      }),
    );
    expect(c).toBe("hfault_sys|SceLibKernel|0x42");
  });

  it("host_fault with an unknown region (not in the spec table): per build, like the eboot rule", () => {
    const c = canon(input("host_fault", { pc: { region: "unknown", module: null, offset: "0xdead" }, lr: null }));
    expect(c).toBe(`hfault_unknown|${BUILD}|0xdead|-`);
  });

  it("host_fault without pc counts as the unknown region", () => {
    expect(canon(input("host_fault", {}))).toBe(`hfault_unknown|${BUILD}|-|-`);
  });

  it("abnormal_exit: reason, import, first frame", () => {
    const c = canon(
      input("abnormal_exit", {
        reason: "unshimmed_import",
        code: null,
        import: "KERNEL32.dll!GetTickCount64",
        frames: ["Game+0x77", "Game+0x88"],
      }),
    );
    expect(c).toBe("exit|unshimmed_import|KERNEL32.dll!GetTickCount64|Game+0x77");
  });

  it("abnormal_exit: code in decimal when there is no import", () => {
    expect(canon(input("abnormal_exit", { reason: "ExitProcess", code: 3, import: null, frames: [] }))).toBe(
      "exit|ExitProcess|3|-",
    );
  });

  it("hang: eip only", () => {
    expect(canon(input("hang", { stalled_beats: 3, eip: "Game+0x5000", runner_state: "running" }))).toBe(
      "hang|Game+0x5000",
    );
    expect(canon(input("hang", { stalled_beats: 3, eip: null }))).toBe("hang|-");
  });
});

describe("signatureId", () => {
  it.each([
    ["halt|1420|-|Game+0x1fedf4,Game+0x451c23,Game+0x44f570", "SZYGIRBIXGHOM3AH"],
    ["halt|904|Codec.cpp:1377|-", "S646AYC2PDRQYKFU"],
    ["gfault|ACCESS_VIOLATION|Game+0x12ab|Game+0x1,Game+0x2", "SXHORBZDAKEXTDHM"],
    ["hfault_jit|PREFETCH_ABORT|Game+0x10,D2Common+0x20,Fog+0x30", "SWGCLUSWDNUFSGKP"],
    ["hfault|0.1.0+ab12cd34ef56|0x1a2b|0x3c4d", "SU5CS374HSZKGIHH"],
    ["hfault_sys|SceLibKernel|0x42", "SGJQW45Z3EIO2XYZ"],
    ["exit|unshimmed_import|KERNEL32.dll!GetTickCount64|Game+0x77", "SKRNGNKMD5FFRAQ5"],
    ["hang|Game+0x5000", "SDD265C4OC7DEE2C"],
    ["hang|-", "SDCQKIRCQBPDNL4Q"],
  ])("%s -> %s", async (c, expected) => {
    expect(await signatureId(c)).toBe(expected);
  });

  it("is 'S' followed by 15 RFC 4648 base32 characters", async () => {
    expect(await signatureId("anything")).toMatch(/^S[A-Z2-7]{15}$/);
  });
});

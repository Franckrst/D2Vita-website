// Signature rules v1 (spec section 5.3). Everything that decides how a claim
// maps to a signature lives in this file, so the official contract vectors can
// be plugged in without touching the rest of the API.
//
//   signature = "S" + base32(sha256(canon))[0:15]
//
// Canon construction: fields joined by "|", absent fields (null or missing)
// written "-", addresses kept as received, "first N frames" = the frames that
// exist among the first N joined by "," ("-" when there are none), integers in
// decimal.

import { base32, sha256, utf8 } from "./crypto";
import type { KindFeatures } from "./types";

export const RULES_VERSION = 1;

export type SignatureInput = { build_id: string } & KindFeatures;

const ABSENT = "-";

function field(value: string | number | null | undefined): string {
  return value === null || value === undefined ? ABSENT : String(value);
}

function firstFrames(frames: readonly string[] | undefined, n: number): string {
  const kept = (frames ?? []).slice(0, n);
  return kept.length > 0 ? kept.join(",") : ABSENT;
}

export function canon(input: SignatureInput): string {
  switch (input.kind) {
    case "halt": {
      const f = input.features;
      return ["halt", field(f.code), field(f.location), firstFrames(f.frames, 3)].join("|");
    }
    case "guest_fault": {
      const f = input.features;
      return ["gfault", field(f.exception), field(f.eip), firstFrames(f.frames, 2)].join("|");
    }
    case "host_fault": {
      const f = input.features;
      const region = f.pc?.region ?? "unknown";
      if (region === "jit") {
        return ["hfault_jit", field(f.stop_reason), firstFrames(f.guest_frames, 3)].join("|");
      }
      if (region === "sysmodule") {
        return ["hfault_sys", field(f.pc?.module), field(f.pc?.offset)].join("|");
      }
      // "eboot" is the spec rule. "unknown" is not in the spec table: it is
      // grouped per build like the eboot rule, under its own prefix
      // (provisional until the contract rules are frozen).
      const prefix = region === "eboot" ? "hfault" : "hfault_unknown";
      return [prefix, input.build_id, field(f.pc?.offset), field(f.lr?.offset)].join("|");
    }
    case "abnormal_exit": {
      const f = input.features;
      const importOrCode = f.import !== null && f.import !== undefined ? f.import : f.code;
      return ["exit", field(f.reason), field(importOrCode), firstFrames(f.frames, 1)].join("|");
    }
    case "hang":
      return ["hang", field(input.features.eip)].join("|");
  }
}

export async function signatureId(canonText: string): Promise<string> {
  return "S" + base32(await sha256(utf8(canonText))).slice(0, 15);
}

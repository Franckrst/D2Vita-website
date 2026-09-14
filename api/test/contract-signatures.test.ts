// Signature rules v1 against the official vectors: every canon and every
// signature id of contract/vectors/signatures.v1.json must come out of
// src/signature.ts unchanged (contract/signature-rules.v1.md section 2).
import { describe, expect, it } from "vitest";
import { RULES_VERSION, canon, signatureId } from "../src/signature";
import type { Claim } from "../src/types";
import { SIGNATURE_VECTORS, contractErrors } from "./contract";

describe("contract vectors: signatures.v1.json", () => {
  it("covers every kind and every host_fault region", () => {
    expect(SIGNATURE_VECTORS).toHaveLength(26);
    expect(RULES_VERSION).toBe(1);
    const kinds = new Set(SIGNATURE_VECTORS.map((v) => v.claim.kind));
    expect([...kinds].sort()).toEqual(["abnormal_exit", "guest_fault", "halt", "hang", "host_fault"]);
    const regions = SIGNATURE_VECTORS.filter((v) => v.claim.kind === "host_fault").map(
      (v) => (v.claim.features as { pc: { region: string } }).pc.region,
    );
    expect(new Set(regions)).toEqual(new Set(["eboot", "jit", "sysmodule", "unknown"]));
  });

  it.each(SIGNATURE_VECTORS.map((v) => [v.name, v] as const))("%s", (_name, vector) => {
    // The vectors are only defined for claims that pass validation, so the
    // claim itself is checked against the schema first.
    expect(contractErrors("claim.v1", vector.claim)).toBeNull();
    expect(canon(vector.claim as unknown as Claim)).toBe(vector.canon);
  });

  it.each(SIGNATURE_VECTORS.map((v) => [v.name, v] as const))("%s: signature id", async (_name, vector) => {
    expect(await signatureId(vector.canon)).toBe(vector.signature);
    expect(await signatureId(canon(vector.claim as unknown as Claim))).toBe(vector.signature);
  });

  it("gives one signature per canon and nothing else", async () => {
    const byCanon = new Map<string, string>();
    for (const vector of SIGNATURE_VECTORS) {
      const seen = byCanon.get(vector.canon);
      if (seen) expect(seen).toBe(vector.signature);
      byCanon.set(vector.canon, vector.signature);
      expect(vector.signature).toMatch(/^S[A-Z2-7]{15}$/);
    }
    // Two vectors share a canon on purpose (same bug, other details).
    expect(byCanon.size).toBeLessThan(SIGNATURE_VECTORS.length);
  });
});

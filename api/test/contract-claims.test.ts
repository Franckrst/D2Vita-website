// Claim validation against the contract: the 26 valid vectors are accepted,
// the 70 vectors of contract/vectors/claims-invalid.v1.json are refused, and a
// mutation sweep compares src/validate.ts with Ajv on the schema itself, so the
// two cannot drift apart silently.
import { describe, expect, it } from "vitest";
import { CLAIM_PATTERNS, validateClaim } from "../src/validate";
import {
  INVALID_CLAIM_VECTORS,
  SCHEMAS,
  SIGNATURE_VECTORS,
  contractErrors,
  contractValidator,
  matchesContract,
} from "./contract";

const claimSchema = SCHEMAS["claim.v1"] as unknown as {
  $defs: Record<string, { pattern?: string }>;
  properties: Record<string, { pattern?: string; properties?: Record<string, { pattern?: string }> }>;
};

describe("claim patterns", () => {
  // Every regular expression of the validator is the schema's, character for
  // character: a change to one without the other fails here.
  it.each([
    ["ReportId", claimSchema.$defs.ReportId!.pattern],
    ["InstallId", claimSchema.$defs.InstallId!.pattern],
    ["BuildId", claimSchema.$defs.BuildId!.pattern],
    ["Hex32", claimSchema.$defs.Hex32!.pattern],
    ["ModuleName", claimSchema.$defs.ModuleName!.pattern],
    ["Address", claimSchema.$defs.Address!.pattern],
    ["SourceLocation", claimSchema.$defs.SourceLocation!.pattern],
  ])("%s is the pattern of the schema", (name, pattern) => {
    expect(CLAIM_PATTERNS[name as keyof typeof CLAIM_PATTERNS]!.source).toBe(pattern);
  });

  it("uses the schema patterns of the feature and platform strings too", () => {
    const features = (kind: string, key: string) =>
      (claimSchema.$defs[kind] as { properties: Record<string, { anyOf?: Array<{ pattern?: string }> }> }).properties[
        key
      ]!.anyOf![0]!.pattern;
    expect(CLAIM_PATTERNS.ThreadName.source).toBe(features("HostFaultFeatures", "thread_name"));
    expect(CLAIM_PATTERNS.ImportName.source).toBe(features("AbnormalExitFeatures", "import"));
    expect(CLAIM_PATTERNS.RunnerState.source).toBe(features("HangFeatures", "runner_state"));
    expect(CLAIM_PATTERNS.PlatformFw.source).toBe(claimSchema.properties.platform!.properties!.fw!.pattern);
  });
});

describe("contract vectors: valid claims", () => {
  it.each(SIGNATURE_VECTORS.map((v) => [v.name, v.claim] as const))("accepts %s", (_name, claim) => {
    expect(contractErrors("claim.v1", claim)).toBeNull();
    const result = validateClaim(claim);
    expect(result.ok ? null : result.error).toBeNull();
  });
});

describe("contract vectors: claims-invalid.v1.json", () => {
  it("covers 70 cases, each derived from a valid vector", () => {
    expect(INVALID_CLAIM_VECTORS).toHaveLength(70);
    const names = new Set(SIGNATURE_VECTORS.map((v) => v.name));
    for (const vector of INVALID_CLAIM_VECTORS) expect(names.has(vector.base), vector.name).toBe(true);
  });

  it.each(INVALID_CLAIM_VECTORS.map((v) => [v.name, v] as const))("refuses %s", (_name, vector) => {
    // The schema refuses it where the vector says, and so does the validator.
    const validate = contractValidator("claim.v1");
    expect(validate(vector.claim)).toBe(false);
    expect((validate.errors ?? []).map((e) => e.instancePath)).toContain(vector.invalid_at);
    const result = validateClaim(vector.claim);
    expect(result.ok, `expected a refusal, got ${JSON.stringify(result)}`).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Mutation sweep: the validator and the schema must agree on every mutant of
// every vector claim, not only on the cases the contract wrote down.

const VALUES: unknown[] = [
  null,
  true,
  0,
  1,
  -1,
  1.5,
  2,
  87,
  88,
  4294967296,
  "",
  "x",
  "0x1",
  "0x01",
  "Game+0x1",
  "game+0x1",
  "Game+0x1FEDF4",
  "dump",
  "halt",
  "eboot",
  "Codec.cpp:1377",
  "a".repeat(200),
  [],
  {},
];

type Mutant = { what: string; claim: unknown };

function paths(value: unknown, prefix = ""): string[] {
  if (Array.isArray(value)) {
    return value.flatMap((item, i) => [`${prefix}/${i}`, ...paths(item, `${prefix}/${i}`)]);
  }
  if (typeof value === "object" && value !== null) {
    return Object.keys(value).flatMap((key) => [
      `${prefix}/${key}`,
      ...paths((value as Record<string, unknown>)[key], `${prefix}/${key}`),
    ]);
  }
  return [];
}

function at(root: unknown, path: string): { parent: any; key: string | number } {
  const parts = path.split("/").slice(1);
  let parent: any = root;
  for (const part of parts.slice(0, -1)) parent = Array.isArray(parent) ? parent[Number(part)] : parent[part];
  const last = parts[parts.length - 1]!;
  return { parent, key: Array.isArray(parent) ? Number(last) : last };
}

function* mutants(claim: Record<string, unknown>): Generator<Mutant> {
  for (const path of paths(claim)) {
    for (const value of VALUES) {
      const copy = structuredClone(claim);
      const { parent, key } = at(copy, path);
      parent[key] = value;
      yield { what: `set ${path} = ${JSON.stringify(value) ?? "undefined"}`, claim: copy };
    }
    const removed = structuredClone(claim);
    const { parent, key } = at(removed, path);
    if (Array.isArray(parent)) parent.splice(key as number, 1);
    else delete parent[key];
    yield { what: `remove ${path}`, claim: removed };

    // An unknown key in every object of the claim.
    const { parent: target } = at(structuredClone(claim), `${path}/x`);
    if (target !== undefined && !Array.isArray(target) && typeof target === "object" && target !== null) {
      const extra = structuredClone(claim);
      (at(extra, `${path}/x`).parent as Record<string, unknown>).unexpected = 1;
      yield { what: `add ${path}/unexpected`, claim: extra };
    }
  }
  const extra = structuredClone(claim);
  extra.unexpected = 1;
  yield { what: "add /unexpected", claim: extra };
}

describe("claim validation follows the schema on mutated vectors", () => {
  it("agrees with Ajv on every mutant of every valid vector", () => {
    const disagreements: string[] = [];
    let checked = 0;
    for (const vector of SIGNATURE_VECTORS) {
      for (const mutant of mutants(vector.claim)) {
        checked++;
        const schemaSays = matchesContract("claim.v1", mutant.claim);
        const apiSays = validateClaim(mutant.claim).ok;
        if (schemaSays !== apiSays && disagreements.length < 20) {
          disagreements.push(
            `${vector.name}: ${mutant.what} -> schema ${schemaSays ? "accepts" : "refuses"}, API ${apiSays ? "accepts" : "refuses"}`,
          );
        }
      }
    }
    expect(checked).toBeGreaterThan(5000);
    expect(disagreements).toEqual([]);
  });
});

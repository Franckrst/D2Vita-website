// Claim validation against the contract: the 26 valid vectors are accepted,
// the 70 vectors of contract/vectors/claims-invalid.v1.json are refused, and a
// mutation sweep compares src/validate.ts with Ajv on the schema itself, so the
// two cannot drift apart silently. The last block sends every vector through
// POST /v1/claims.
import { env } from "cloudflare:workers";
import { beforeAll, describe, expect, it } from "vitest";
import { CLAIM_PATTERNS, validateClaim } from "../src/validate";
import {
  INVALID_CLAIM_VECTORS,
  SCHEMAS,
  SIGNATURE_VECTORS,
  contractErrors,
  contractValidator,
  matchesContract,
} from "./contract";
import { call, claimRequest, registerBuild, resetDatabase, signedJson } from "./helpers";
import { mutants } from "./mutate";

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

// ---------------------------------------------------------------------------
// The same vectors through the route, where a claim also has to be signed for,
// counted and answered.

describe("POST /v1/claims with the contract vectors", () => {
  beforeAll(async () => {
    await resetDatabase();
    for (const build of new Set(SIGNATURE_VECTORS.map((v) => v.claim.build_id as string))) {
      await registerBuild(build, build.includes("dirty") ? "test" : "release");
    }
  });

  it.each(SIGNATURE_VECTORS.map((v) => [v.name, v] as const))(
    "%s: 200 with the signature of the vector",
    async (_name, vector) => {
      const response = await call(claimRequest(vector.claim));
      expect(response.status).toBe(200);
      const decision = await signedJson(response);
      expect(decision.report_id).toBe(vector.claim.report_id);
      expect(decision.signature).toBe(vector.signature);
      const row = await env.DB.prepare("SELECT canon, rules_version FROM signatures WHERE id = ?1")
        .bind(vector.signature)
        .first();
      expect(row).toEqual({ canon: vector.canon, rules_version: 1 });
    },
  );

  it("reads an integer written with a fraction as the contract says", async () => {
    // JSON "1420.0" is the integer 1420: the signature is the vector's.
    const vector = SIGNATURE_VECTORS.find((v) => v.name === "halt_code_written_as_float")!;
    const body = JSON.stringify(vector.claim).replace('"code":1420', '"code":1420.0');
    expect(body).toContain('"code":1420.0');
    const request = new Request("https://api.test/v1/claims", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "content-length": String(new TextEncoder().encode(body).byteLength),
        "x-d2v-client": `d2vita/${vector.claim.build_id as string}`,
        "x-d2v-install": vector.claim.install_id as string,
        "cf-connecting-ip": "198.51.100.77",
      },
      body,
    });
    const decision = await signedJson(await call(request));
    expect(decision.signature).toBe(vector.signature);
  });

  it.each(INVALID_CLAIM_VECTORS.map((v) => [v.name, v] as const))(
    "%s: signed 400 invalid_payload",
    async (_name, vector) => {
      const response = await call(claimRequest(vector.claim as Record<string, unknown>));
      expect(response.status).toBe(400);
      const body = await signedJson(response);
      expect(body).toMatchObject({ v: 1, error: "invalid_payload" });
      // Nothing of a claim the API did not read is echoed back.
      expect(body.report_id).toBeUndefined();
    },
  );

  it("counted every valid vector once and no invalid one", async () => {
    const counted = await env.DB.prepare("SELECT COUNT(*) AS n, SUM(count) AS total FROM signatures").first();
    const distinct = new Set(SIGNATURE_VECTORS.map((v) => v.signature)).size;
    expect(counted).toEqual({ n: distinct, total: SIGNATURE_VECTORS.length });
  });
});

describe("claim validation follows the schema on mutated vectors", () => {
  it("agrees with Ajv on every mutant of every valid vector", () => {
    const disagreements: string[] = [];
    let checked = 0;
    for (const vector of SIGNATURE_VECTORS) {
      for (const mutant of mutants(vector.claim, VALUES)) {
        checked++;
        const schemaSays = matchesContract("claim.v1", mutant.value);
        const apiSays = validateClaim(mutant.value).ok;
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

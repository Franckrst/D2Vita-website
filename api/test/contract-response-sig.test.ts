// Response signatures against the official vectors
// (contract/vectors/response-sig.v1.json): Ed25519 as in RFC 8032, over the
// exact bytes of the body, base64 with padding in X-D2V-Signature.
import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { ed25519Sign, fromBase64, fromHex, utf8 } from "../src/crypto";
import { signResponse } from "../src/http";
import { handle } from "../src/router";
import { RESPONSE_SIG_NEGATIVES, RESPONSE_SIG_VECTORS, contractErrors } from "./contract";
import { NOW, claimRequest } from "./helpers";
import { haltClaim } from "./fixtures";

async function verifies(publicKeyHex: string, signatureB64: string, body: string): Promise<boolean> {
  const key = await crypto.subtle.importKey("raw", fromHex(publicKeyHex), { name: "Ed25519" }, false, ["verify"]);
  return crypto.subtle.verify("Ed25519", key, fromBase64(signatureB64), utf8(body));
}

describe("contract vectors: response-sig.v1.json", () => {
  it("covers a decision, an error, an empty body and a non-BMP body", () => {
    expect(RESPONSE_SIG_VECTORS.length).toBeGreaterThanOrEqual(3);
    const names = RESPONSE_SIG_VECTORS.map((v) => v.name);
    expect(names).toContain("empty_body");
    expect(names).toContain("error_non_ascii_message");
    expect(RESPONSE_SIG_NEGATIVES.length).toBeGreaterThanOrEqual(5);
  });

  it.each(RESPONSE_SIG_VECTORS.map((v) => [v.name, v] as const))("%s: signs to the vector", async (_name, vector) => {
    // Ed25519 is deterministic: the same seed and body give the same 64 bytes.
    expect(await ed25519Sign(vector.seed_hex, utf8(vector.body_utf8))).toBe(vector.signature_b64);
    expect(vector.signature_b64).toHaveLength(88);
    expect(await verifies(vector.public_key_hex, vector.signature_b64, vector.body_utf8)).toBe(true);
  });

  it.each(RESPONSE_SIG_VECTORS.map((v) => [v.name, v] as const))(
    "%s: X-D2V-Signature carries it",
    async (_name, vector) => {
      const signed = await signResponse(
        { RESPONSE_SIGNING_KEY: vector.seed_hex } as never,
        new Response(vector.body_utf8),
      );
      expect(signed.headers.get("x-d2v-signature")).toBe(vector.signature_b64);
      expect(await signed.text()).toBe(vector.body_utf8);
    },
  );

  it.each(RESPONSE_SIG_NEGATIVES.map((v) => [v.name, v] as const))("%s does not verify", async (_name, vector) => {
    expect(vector.expect).toBe("invalid");
    expect(await verifies(vector.public_key_hex, vector.signature_b64, vector.body_utf8)).toBe(false);
  });
});

// The one case where a console answer cannot be signed: the signing key is
// missing or malformed. The contract says every answer is signed, so there is
// nothing honest left to send; the API answers an unsigned 500 and the console
// treats it like a broken connection (README, "Console").
describe("when the signing key is unusable", () => {
  it.each([
    ["missing", undefined],
    ["not hex", "not-a-key"],
    ["too short", "00112233"],
  ])("answers an unsigned 500 internal_error when the key is %s", async (_name, key) => {
    const request = claimRequest(haltClaim({ kind: "nonsense" }));
    const ctx = createExecutionContext();
    const response = await handle(request, { ...env, RESPONSE_SIGNING_KEY: key } as never, ctx, NOW);
    await waitOnExecutionContext(ctx);
    // Without the failure this would be the signed 400 of an invalid claim.
    expect(response.status).toBe(500);
    expect(response.headers.get("x-d2v-signature")).toBeNull();
    const body = await response.json();
    expect(body).toEqual({ v: 1, error: "internal_error", message: "Internal error" });
    expect(contractErrors("admin.v1#ErrorBody", body)).toBeNull();
  });

  it("signs that same claim when the key is there", async () => {
    const request = claimRequest(haltClaim({ kind: "nonsense" }));
    const ctx = createExecutionContext();
    const response = await handle(request, env, ctx, NOW);
    await waitOnExecutionContext(ctx);
    expect(response.status).toBe(400);
    expect(response.headers.get("x-d2v-signature")).toHaveLength(88);
  });
});

import { describe, expect, it } from "vitest";
import { readBoundedJson } from "../src/http";

function post(body: string, headers: Record<string, string>): Request {
  return new Request("https://api.test/v1/claims", { method: "POST", body, headers });
}

describe("readBoundedJson", () => {
  it("parses a body within the limit", async () => {
    const body = JSON.stringify({ a: 1 });
    const result = await readBoundedJson(post(body, { "content-length": String(body.length) }), 16384);
    expect(result).toEqual({ ok: true, value: { a: 1 } });
  });

  it("rejects a missing Content-Length with 413 before reading", async () => {
    const result = await readBoundedJson(post("{}", {}), 16384);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.response.status).toBe(413);
      expect(await result.response.json()).toMatchObject({ v: 1, error: "length_required" });
    }
  });

  it("rejects a declared length above the limit with 413", async () => {
    const body = "x".repeat(16385);
    const result = await readBoundedJson(post(body, { "content-length": "16385" }), 16384);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.response.status).toBe(413);
      expect(await result.response.json()).toMatchObject({ error: "payload_too_large" });
    }
  });

  it("rejects malformed JSON with 400 invalid_payload", async () => {
    const result = await readBoundedJson(post("{nope", { "content-length": "5" }), 16384);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.response.status).toBe(400);
      expect(await result.response.json()).toMatchObject({ error: "invalid_payload" });
    }
  });
});

import { describe, expect, it } from "vitest";
import { fromBase64Url, toBase64Url, utf8 } from "../src/crypto";
import { createUploadToken, verifyUploadToken, type UploadGrant } from "../src/token";

const KEY = "0f".repeat(32);
const GRANT: UploadGrant = {
  report_id: "01J9Z6T4Q8M3K7V2B5N0XWAYCD",
  signature: "SZYGIRBIXGHOM3AH",
  artifacts: [
    { name: "crash_txt", max_bytes: 65536 },
    { name: "crash_log", max_bytes: 65536 },
  ],
  expires_unix: 1789286000,
};

describe("upload token", () => {
  it("round-trips the grant while not expired", async () => {
    const token = await createUploadToken(KEY, GRANT);
    expect(await verifyUploadToken(KEY, token, GRANT.expires_unix)).toEqual({ ok: true, grant: GRANT });
  });

  it("starts like the spec example (base64url of {\"r\":\")", async () => {
    expect(await createUploadToken(KEY, GRANT)).toMatch(/^eyJyIjoi[A-Za-z0-9_-]*\.[A-Za-z0-9_-]{43}$/);
  });

  it("is refused once expired", async () => {
    const token = await createUploadToken(KEY, GRANT);
    expect(await verifyUploadToken(KEY, token, GRANT.expires_unix + 1)).toEqual({ ok: false, reason: "expired" });
  });

  it("is refused with another key", async () => {
    const token = await createUploadToken(KEY, GRANT);
    expect(await verifyUploadToken("1e".repeat(32), token, 0)).toEqual({ ok: false, reason: "invalid" });
  });

  it("is refused when the payload is altered (bigger size, longer expiry)", async () => {
    const token = await createUploadToken(KEY, GRANT);
    const [payload, mac] = token.split(".");
    const decoded = JSON.parse(new TextDecoder().decode(fromBase64Url(payload!)));
    decoded.a[0][1] = 10_000_000;
    decoded.e = 9_999_999_999;
    const forged = `${toBase64Url(utf8(JSON.stringify(decoded)))}.${mac}`;
    expect(await verifyUploadToken(KEY, forged, 0)).toEqual({ ok: false, reason: "invalid" });
  });

  it.each(["", "abc", "abc.def", "a.b.c", "!!!.???", `${toBase64Url(utf8("[]"))}.xyz`])(
    "is refused when malformed: %j",
    async (token) => {
      expect(await verifyUploadToken(KEY, token, 0)).toEqual({ ok: false, reason: "invalid" });
    },
  );
});

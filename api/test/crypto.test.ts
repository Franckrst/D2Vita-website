import { describe, expect, it } from "vitest";
import { base32, fromHex, hmacSha256, sha256, timingSafeEqual, toHex, utf8 } from "../src/crypto";

describe("hmacSha256", () => {
  it("matches RFC 4231 test case 2", async () => {
    const mac = await hmacSha256(utf8("Jefe"), utf8("what do ya want for nothing?"));
    expect(toHex(mac)).toBe("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
  });
});

describe("timingSafeEqual", () => {
  it("compares byte arrays", () => {
    expect(timingSafeEqual(fromHex("0102"), fromHex("0102"))).toBe(true);
    expect(timingSafeEqual(fromHex("0102"), fromHex("0103"))).toBe(false);
    expect(timingSafeEqual(fromHex("0102"), fromHex("010203"))).toBe(false);
  });
});

describe("base32 (RFC 4648, upper case, no padding)", () => {
  it.each([
    ["", ""],
    ["f", "MY"],
    ["fo", "MZXQ"],
    ["foo", "MZXW6"],
    ["foob", "MZXW6YQ"],
    ["fooba", "MZXW6YTB"],
    ["foobar", "MZXW6YTBOI"],
  ])("encodes %j as %j", (input, expected) => {
    expect(base32(utf8(input))).toBe(expected);
  });
});

describe("hex and sha256", () => {
  it("hashes 'abc' to the FIPS 180-2 vector", async () => {
    expect(toHex(await sha256(utf8("abc")))).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });

  it("round-trips hex", () => {
    expect(toHex(fromHex("00ff10ab"))).toBe("00ff10ab");
  });

  it("rejects malformed hex", () => {
    expect(() => fromHex("abc")).toThrow();
    expect(() => fromHex("zz")).toThrow();
  });
});

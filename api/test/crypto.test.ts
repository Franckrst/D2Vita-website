import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import {
  base32,
  ed25519Sign,
  fromBase64,
  fromBase64Url,
  fromHex,
  hmacSha256,
  installHash,
  sha256,
  timingSafeEqual,
  toBase64,
  toBase64Url,
  toHex,
  utf8,
} from "../src/crypto";

describe("Ed25519 through WebCrypto in workerd", () => {
  it("reproduces RFC 8032 test vector 1 from a 32-byte hex seed", async () => {
    const seed = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    expect(await ed25519Sign(seed, new Uint8Array(0))).toBe(
      "5VZDAMNgrHKQhuLMgG6CioSHfx645dl02HPgZSJJAVVfuIIVkKM7rMYeOXAc+bRr0lv18FlbviRlUUFDjnoQCw==",
    );
  });

  it("signs with RESPONSE_SIGNING_KEY; the test public key verifies it", async () => {
    const message = utf8('{"v":1}');
    const signature = await ed25519Sign(env.RESPONSE_SIGNING_KEY!, message);
    const publicKey = await crypto.subtle.importKey(
      "raw",
      fromHex(env.TEST_RESPONSE_PUBLIC_KEY),
      { name: "Ed25519" },
      false,
      ["verify"],
    );
    expect(await crypto.subtle.verify("Ed25519", publicKey, fromBase64(signature), message)).toBe(true);
    expect(await crypto.subtle.verify("Ed25519", publicKey, fromBase64(signature), utf8('{"v":2}'))).toBe(false);
  });

  it("rejects a malformed seed", async () => {
    await expect(ed25519Sign("abcd", utf8("x"))).rejects.toThrow();
  });
});

describe("base64", () => {
  it("encodes standard and URL-safe alphabets", () => {
    const bytes = new Uint8Array([0xfb, 0xff, 0xfe]);
    expect(toBase64(bytes)).toBe("+//+");
    expect(toBase64Url(bytes)).toBe("-__-");
    expect(fromBase64("+//+")).toEqual(bytes);
    expect(fromBase64Url("-__-")).toEqual(bytes);
  });
});

describe("installHash", () => {
  it("is HMAC-SHA256(key, install_id) in hex", async () => {
    expect(await installHash("k".repeat(32), "4f3c9a0e8b7d6c5a4f3e2d1c0b9a8f7e")).toBe(
      "11b60af7955069bc0cb82c6e1b15b6c38454758971e206292ea91f183be1086b",
    );
  });
});

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

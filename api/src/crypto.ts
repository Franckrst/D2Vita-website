// Small crypto helpers on top of WebCrypto (no dependency).

const encoder = new TextEncoder();

export function utf8(text: string): Uint8Array {
  return encoder.encode(text);
}

export function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

export function fromHex(hex: string): Uint8Array {
  if (hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) throw new Error("malformed hex");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

// RFC 4648 base32, upper case, without padding.
export function base32(bytes: Uint8Array): string {
  let out = "";
  let buffer = 0;
  let bits = 0;
  for (const b of bytes) {
    buffer = (buffer << 8) | b;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += BASE32_ALPHABET[(buffer >>> bits) & 31];
    }
    buffer &= (1 << bits) - 1;
  }
  if (bits > 0) out += BASE32_ALPHABET[(buffer << (5 - bits)) & 31];
  return out;
}

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", data));
}

export async function hmacSha256(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const k = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", k, data));
}

export function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

export function fromBase64(text: string): Uint8Array {
  const binary = atob(text);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

export function toBase64Url(bytes: Uint8Array): string {
  return toBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function fromBase64Url(text: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(text)) throw new Error("malformed base64url");
  const padded = text.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (text.length % 4)) % 4);
  return fromBase64(padded);
}

// install_hash = HMAC(INSTALL_HASH_KEY, install_id), hex (spec section 5.6).
export async function installHash(key: string, installId: string): Promise<string> {
  return toHex(await hmacSha256(utf8(key), utf8(installId)));
}

// Ed25519 (RFC 8032, SHA-512) signing from a 32-byte seed given in hex, the
// format of RESPONSE_SIGNING_KEY. WebCrypto only imports private Ed25519 keys
// as PKCS#8, whose DER encoding is a fixed 16-byte prefix followed by the seed.
const PKCS8_ED25519_PREFIX = fromHex("302e020100300506032b657004220420");
const signingKeys = new Map<string, Promise<CryptoKey>>();

function signingKey(seedHex: string): Promise<CryptoKey> {
  let key = signingKeys.get(seedHex);
  if (!key) {
    if (!/^[0-9a-fA-F]{64}$/.test(seedHex)) return Promise.reject(new Error("Ed25519 seed must be 64 hex chars"));
    const pkcs8 = new Uint8Array(48);
    pkcs8.set(PKCS8_ED25519_PREFIX, 0);
    pkcs8.set(fromHex(seedHex), 16);
    key = crypto.subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, false, ["sign"]);
    signingKeys.set(seedHex, key);
    key.catch(() => signingKeys.delete(seedHex));
  }
  return key;
}

// Returns the standard base64 signature of `message`.
export async function ed25519Sign(seedHex: string, message: Uint8Array): Promise<string> {
  const signature = await crypto.subtle.sign({ name: "Ed25519" }, await signingKey(seedHex), message);
  return toBase64(new Uint8Array(signature));
}

// Constant time for equal lengths (lengths are public: digests and MACs).
export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

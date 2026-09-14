// Upload token (spec section 5.5): HMAC-SHA256(UPLOAD_TOKEN_KEY) over the
// report id, the signature it is counted on, the requested pieces with their
// maximum sizes, and the expiry. Format: base64url(payload JSON) "." base64url(MAC).

import { fromBase64Url, hmacSha256, timingSafeEqual, toBase64Url, utf8 } from "./crypto";
import { ARTIFACT_NAMES, type ArtifactName } from "./types";

export interface RequestedArtifact {
  name: ArtifactName;
  max_bytes: number;
}

export interface UploadGrant {
  report_id: string;
  signature: string;
  artifacts: RequestedArtifact[];
  expires_unix: number;
}

const MAC_CONTEXT = "d2v-upload-v1.";

async function mac(key: string, payload: string): Promise<Uint8Array> {
  return hmacSha256(utf8(key), utf8(MAC_CONTEXT + payload));
}

export async function createUploadToken(key: string, grant: UploadGrant): Promise<string> {
  const payload = toBase64Url(
    utf8(
      JSON.stringify({
        r: grant.report_id,
        s: grant.signature,
        a: grant.artifacts.map((a) => [a.name, a.max_bytes]),
        e: grant.expires_unix,
      }),
    ),
  );
  return `${payload}.${toBase64Url(await mac(key, payload))}`;
}

export type TokenCheck = { ok: true; grant: UploadGrant } | { ok: false; reason: "invalid" | "expired" };

const INVALID: TokenCheck = { ok: false, reason: "invalid" };

export async function verifyUploadToken(key: string, token: string, nowUnix: number): Promise<TokenCheck> {
  const parts = token.split(".");
  if (parts.length !== 2) return INVALID;
  const [payload, signature] = parts as [string, string];
  let given: Uint8Array;
  try {
    given = fromBase64Url(signature);
  } catch {
    return INVALID;
  }
  if (!timingSafeEqual(given, await mac(key, payload))) return INVALID;

  let decoded: unknown;
  try {
    decoded = JSON.parse(new TextDecoder().decode(fromBase64Url(payload)));
  } catch {
    return INVALID;
  }
  const p = decoded as { r?: unknown; s?: unknown; a?: unknown; e?: unknown };
  if (typeof p !== "object" || p === null || typeof p.r !== "string" || typeof p.s !== "string") return INVALID;
  if (typeof p.e !== "number" || !Array.isArray(p.a)) return INVALID;
  const artifacts: RequestedArtifact[] = [];
  for (const item of p.a) {
    if (!Array.isArray(item) || item.length !== 2) return INVALID;
    const [name, maxBytes] = item as [unknown, unknown];
    if (!ARTIFACT_NAMES.includes(name as ArtifactName) || typeof maxBytes !== "number") return INVALID;
    artifacts.push({ name: name as ArtifactName, max_bytes: maxBytes });
  }
  if (nowUnix > p.e) return { ok: false, reason: "expired" };
  return { ok: true, grant: { report_id: p.r, signature: p.s, artifacts, expires_unix: p.e } };
}

// HTTP helpers: v1 JSON bodies, error bodies, response signing, body limits.

import { ed25519Sign } from "./crypto";
import { requireSecret, type Env } from "./env";

export const API_VERSION = 1;

// Console responses carry X-D2V-Signature: base64 Ed25519 of the exact body.
export async function signResponse(env: Env, response: Response): Promise<Response> {
  const body = new Uint8Array(await response.arrayBuffer());
  const headers = new Headers(response.headers);
  headers.set("x-d2v-signature", await ed25519Sign(requireSecret(env.RESPONSE_SIGNING_KEY, "RESPONSE_SIGNING_KEY"), body));
  return new Response(body, { status: response.status, headers });
}

export function jsonText(text: string, status = 200): Response {
  return new Response(text, { status, headers: { "content-type": "application/json; charset=utf-8" } });
}

export function json(body: Record<string, unknown>, status = 200, headers?: HeadersInit): Response {
  const h = new Headers(headers);
  h.set("content-type", "application/json; charset=utf-8");
  return new Response(JSON.stringify({ v: API_VERSION, ...body }), { status, headers: h });
}

export function error(status: number, code: string, message: string, extra?: Record<string, unknown>): Response {
  return json({ error: code, message, ...extra }, status);
}

// Declared Content-Length, or null when absent or malformed.
export function declaredLength(request: Request): number | null {
  const header = request.headers.get("content-length");
  if (header === null || !/^[0-9]{1,15}$/.test(header)) return null;
  return Number(header);
}

export type BodyResult = { ok: true; value: unknown } | { ok: false; response: Response };

// Size is checked from Content-Length BEFORE the body is read. A missing
// Content-Length is answered 413 (length_required), like artifact uploads.
export async function readBoundedJson(request: Request, maxBytes: number): Promise<BodyResult> {
  const declared = declaredLength(request);
  if (declared === null) {
    return { ok: false, response: error(413, "length_required", "Content-Length is required") };
  }
  if (declared > maxBytes) {
    return { ok: false, response: error(413, "payload_too_large", `Body is limited to ${maxBytes} bytes`) };
  }
  const bytes = new Uint8Array(await request.arrayBuffer());
  if (bytes.byteLength > maxBytes) {
    return { ok: false, response: error(413, "payload_too_large", `Body is limited to ${maxBytes} bytes`) };
  }
  try {
    return { ok: true, value: JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(bytes)) };
  } catch {
    return { ok: false, response: error(400, "invalid_payload", "Body is not valid UTF-8 JSON") };
  }
}

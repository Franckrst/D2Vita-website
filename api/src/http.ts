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

// The error codes of the contract (admin.v1#ErrorBody) and their status. No
// other code or status exists: a body that is not one of these is refused by
// a console and by the local admin tool.
export const ERROR_STATUS = {
  invalid_payload: 400,
  unauthorized: 401,
  unknown_build: 403,
  bad_token: 403,
  turnstile: 403,
  not_found: 404,
  method_not_allowed: 405,
  exists: 409,
  incomplete: 409,
  payload_too_large: 413,
  rate_limited: 429,
  internal_error: 500,
  not_accepting: 503,
} as const;

export type ErrorCode = keyof typeof ERROR_STATUS;

// `extra` names the request an answer is about: report_id, artifact, and the
// retry_after_s / disable_until_unix the contract requires on 429 and 503.
export function error(code: ErrorCode, message: string, extra?: Record<string, unknown>): Response {
  // ErrorBody.message is at most 500 characters.
  const short = message.length > 500 ? `${message.slice(0, 497)}...` : message;
  return json({ error: code, message: short, ...extra }, ERROR_STATUS[code]);
}

// CORS is offered on /v1/bugs only, to the public site origin.
export const DEFAULT_ALLOWED_ORIGIN = "https://franckrst.github.io";

export function allowedOrigin(env: Env): string {
  return env.ALLOWED_ORIGIN || DEFAULT_ALLOWED_ORIGIN;
}

export function withCors(response: Response, origin: string): Response {
  const headers = new Headers(response.headers);
  headers.set("access-control-allow-origin", origin);
  headers.append("vary", "Origin");
  return new Response(response.body, { status: response.status, headers });
}

// Declared Content-Length, or null when absent or malformed.
export function declaredLength(request: Request): number | null {
  const header = request.headers.get("content-length");
  if (header === null || !/^[0-9]{1,15}$/.test(header)) return null;
  return Number(header);
}

export type BodyResult = { ok: true; value: unknown } | { ok: false; response: Response };

// Size is checked from Content-Length BEFORE the body is read. A missing
// Content-Length is answered 413 payload_too_large, the code the contract gives
// that case. `bound` fields are added to error bodies (see rateLimited).
export async function readBoundedJson(
  request: Request,
  maxBytes: number,
  bound?: Record<string, unknown>,
): Promise<BodyResult> {
  const declared = declaredLength(request);
  if (declared === null) {
    return { ok: false, response: error("payload_too_large", "Content-Length is required", bound) };
  }
  if (declared > maxBytes) {
    return { ok: false, response: error("payload_too_large", `Body is limited to ${maxBytes} bytes`, bound) };
  }
  const bytes = new Uint8Array(await request.arrayBuffer());
  if (bytes.byteLength > maxBytes) {
    return { ok: false, response: error("payload_too_large", `Body is limited to ${maxBytes} bytes`, bound) };
  }
  try {
    return { ok: true, value: JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(bytes)) };
  } catch {
    return { ok: false, response: error("invalid_payload", "Body is not valid UTF-8 JSON", bound) };
  }
}

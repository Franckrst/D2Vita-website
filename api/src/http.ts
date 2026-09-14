// HTTP helpers: v1 JSON bodies and error bodies.

export const API_VERSION = 1;

export function json(body: Record<string, unknown>, status = 200, headers?: HeadersInit): Response {
  const h = new Headers(headers);
  h.set("content-type", "application/json; charset=utf-8");
  return new Response(JSON.stringify({ v: API_VERSION, ...body }), { status, headers: h });
}

export function error(status: number, code: string, message: string, extra?: Record<string, unknown>): Response {
  return json({ error: code, message, ...extra }, status);
}

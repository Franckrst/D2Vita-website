// POST /v1/bugs (spec sections 5.2, 5.5, 7): bug reports from the public site,
// protected by Turnstile and the IP/global daily caps. CORS: site origin only.

import { base32 } from "./crypto";
import { requireSecret, type Env } from "./env";
import { allowedOrigin, error, json, readBoundedJson, withCors } from "./http";
import { SCOPE, consumeAll, ipHash, loadSettings, networkKey, rateLimited, utcDay } from "./limits";
import { validateBug } from "./validate";

export const SITEVERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify";
const BUG_MAX_BYTES = 32 * 1024;

export async function verifyTurnstile(env: Env, token: string, ip: string | null): Promise<boolean> {
  const form = new URLSearchParams({ secret: requireSecret(env.TURNSTILE_SECRET, "TURNSTILE_SECRET"), response: token });
  if (ip) form.set("remoteip", ip);
  try {
    const res = await fetch(SITEVERIFY_URL, { method: "POST", body: form });
    if (!res.ok) return false;
    const outcome = (await res.json()) as { success?: unknown };
    return outcome.success === true;
  } catch {
    return false;
  }
}

export async function handleBugPreflight(request: Request, env: Env): Promise<Response> {
  const origin = request.headers.get("origin");
  if (origin !== allowedOrigin(env)) return new Response(null, { status: 403 });
  return withCors(
    new Response(null, {
      status: 204,
      headers: {
        "access-control-allow-methods": "POST, OPTIONS",
        "access-control-allow-headers": "Content-Type",
        "access-control-max-age": "86400",
      },
    }),
    origin,
  );
}

export async function handleBug(request: Request, env: Env, _ctx: ExecutionContext, now: number): Promise<Response> {
  const origin = request.headers.get("origin");
  if (origin === null) return createBug(request, env, now);
  if (origin !== allowedOrigin(env)) return error(403, "origin_not_allowed", "Origin not allowed");
  return withCors(await createBug(request, env, now), origin);
}

async function createBug(request: Request, env: Env, now: number): Promise<Response> {
  const body = await readBoundedJson(request, BUG_MAX_BYTES);
  if (!body.ok) return body.response;
  const validation = validateBug(body.value);
  if (!validation.ok) return error(400, "invalid_payload", validation.error);
  const bug = validation.value;

  // Turnstile first: failed attempts must not eat the IP or global budget.
  const ip = request.headers.get("cf-connecting-ip");
  if (!(await verifyTurnstile(env, bug.turnstile_token, ip))) {
    return error(403, "turnstile", "Turnstile verification failed");
  }

  const settings = await loadSettings(env.DB);
  const day = utcDay(now);
  const ipSubject = await ipHash(env, env.DB, networkKey(ip, 64), day, settings.salts);
  const refused = await consumeAll(env.DB, day, [
    { scope: SCOPE.ipBugs, subject: ipSubject, amount: 1, cap: settings.caps.ip_bugs },
    { scope: SCOPE.globalBugs, subject: "*", amount: 1, cap: settings.caps.global_bugs },
  ]);
  if (refused) return rateLimited(now);

  const id = "B" + base32(crypto.getRandomValues(new Uint8Array(10)));
  await env.DB.prepare(
    `INSERT INTO bugs (id, title, description, version, contact, lang, status, created_at, updated_at)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'open', ?7, ?7)`,
  )
    .bind(id, bug.title, bug.description, bug.version, bug.contact ? bug.contact : null, bug.lang, now)
    .run();
  return json({ id }, 201);
}

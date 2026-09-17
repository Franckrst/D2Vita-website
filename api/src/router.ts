// Minimal router. `now` (Unix seconds) is injected so tests control the clock.

import {
  deleteInstall,
  getArtifact,
  getBug,
  getReport,
  getSignature,
  getStats,
  isAdmin,
  listBugs,
  listSignatures,
  patchBug,
  patchSignature,
  postBuild,
  putSettings,
  unauthorized,
} from "./admin";
import { handleBug, handleBugPreflight } from "./bugs";
import { handleClaim } from "./claims";
import type { Env } from "./env";
import { error, signResponse } from "./http";
import { handleComplete, handleUpload, pathBinding } from "./uploads";

export type Handler = (
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  now: number,
  params: string[],
) => Promise<Response>;

interface Route {
  method: string;
  pattern: RegExp;
  handler: Handler;
}

const routes: Route[] = [
  // Console
  { method: "POST", pattern: /^\/v1\/claims$/, handler: handleClaim },
  { method: "PUT", pattern: /^\/v1\/reports\/([^/]+)\/artifacts\/([^/]+)$/, handler: handleUpload },
  { method: "POST", pattern: /^\/v1\/reports\/([^/]+)\/complete$/, handler: handleComplete },
  // Public site
  { method: "POST", pattern: /^\/v1\/bugs$/, handler: handleBug },
  { method: "OPTIONS", pattern: /^\/v1\/bugs$/, handler: handleBugPreflight },
  // Admin (authorization checked in handle() before dispatch)
  { method: "GET", pattern: /^\/v1\/admin\/signatures$/, handler: listSignatures },
  { method: "GET", pattern: /^\/v1\/admin\/signatures\/([^/]+)$/, handler: getSignature },
  { method: "PATCH", pattern: /^\/v1\/admin\/signatures\/([^/]+)$/, handler: patchSignature },
  { method: "GET", pattern: /^\/v1\/admin\/reports\/([^/]+)$/, handler: getReport },
  { method: "GET", pattern: /^\/v1\/admin\/artifacts\/([^/]+)\/([^/]+)$/, handler: getArtifact },
  { method: "GET", pattern: /^\/v1\/admin\/bugs$/, handler: listBugs },
  { method: "GET", pattern: /^\/v1\/admin\/bugs\/([^/]+)$/, handler: getBug },
  { method: "PATCH", pattern: /^\/v1\/admin\/bugs\/([^/]+)$/, handler: patchBug },
  { method: "POST", pattern: /^\/v1\/admin\/builds$/, handler: postBuild },
  { method: "DELETE", pattern: /^\/v1\/admin\/installs\/([^/]+)$/, handler: deleteInstall },
  { method: "GET", pattern: /^\/v1\/admin\/stats$/, handler: getStats },
  { method: "PUT", pattern: /^\/v1\/admin\/settings$/, handler: putSettings },
];

// Responses to the console are signed, errors included, so a hostile network
// can neither forge a disable_until_unix nor trigger uploads.
function isConsolePath(path: string): boolean {
  return path === "/v1/claims" || path.startsWith("/v1/reports/");
}

async function dispatch(request: Request, env: Env, ctx: ExecutionContext, now: number, path: string) {
  const allowed: string[] = [];
  for (const route of routes) {
    const match = route.pattern.exec(path);
    if (!match) continue;
    if (route.method === request.method) return route.handler(request, env, ctx, now, match.slice(1));
    allowed.push(route.method);
  }
  if (allowed.length > 0) {
    const response = error("method_not_allowed", "Method not allowed");
    response.headers.set("allow", allowed.join(", "));
    return response;
  }
  return error("not_found", "No such route");
}

export async function handle(request: Request, env: Env, ctx: ExecutionContext, now: number): Promise<Response> {
  const path = new URL(request.url).pathname;
  let response: Response;
  try {
    if (path.startsWith("/v1/admin/") && !(await isAdmin(request, env))) return unauthorized();
    response = await dispatch(request, env, ctx, now, path);
  } catch (e) {
    console.error("unhandled error:", e instanceof Error ? e.message : String(e));
    // Even an unexpected failure on a piece route names the report it answers.
    response = error("internal_error", "Internal error", pathBinding(path));
  }
  if (!isConsolePath(path)) return response;
  try {
    return await signResponse(env, response);
  } catch (e) {
    console.error("response signing failed:", e instanceof Error ? e.message : String(e));
    return error("internal_error", "Internal error");
  }
}

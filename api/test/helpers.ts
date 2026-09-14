// Shared test helpers.
import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { expect } from "vitest";
import { fromBase64, fromHex, utf8 } from "../src/crypto";
import { handle } from "../src/router";
import { contractResponseProblems } from "./contract";
import { BUILD_ID } from "./fixtures";

// 2026-09-13T07:20:00Z, the started_unix of the spec example.
export const NOW = 1789284000;

const TABLES = [
  "builds",
  "signatures",
  "signature_builds",
  "signature_installs",
  "reports",
  "bugs",
  "rate_counters",
  "settings",
];

// Storage is isolated per test file only: wipe rows (not the schema) between tests.
export async function resetDatabase(): Promise<void> {
  await env.DB.batch(TABLES.map((t) => env.DB.prepare(`DELETE FROM ${t}`)));
  let cursor: string | undefined;
  do {
    const listing = await env.ARTIFACTS.list({ cursor });
    if (listing.objects.length > 0) await env.ARTIFACTS.delete(listing.objects.map((o) => o.key));
    cursor = listing.truncated ? listing.cursor : undefined;
  } while (cursor);
}

// Runs the Worker router with an injected clock and waits for waitUntil work.
// Every answer is held against the contract on the way out, so no test can see
// a body the contract would refuse (test/contract.ts).
export async function call(request: Request, now = NOW, bindings: Cloudflare.Env = env): Promise<Response> {
  const ctx = createExecutionContext();
  const response = await handle(request, bindings, ctx, now);
  await waitOnExecutionContext(ctx);
  return expectContractResponse(request, response);
}

export async function expectContractResponse(request: Request, response: Response): Promise<Response> {
  const problems = await contractResponseProblems(request, response);
  expect(problems.map((p) => `${p.where}: ${p.detail}`)).toEqual([]);
  return response;
}

export function randomIp(): string {
  const b = crypto.getRandomValues(new Uint8Array(3));
  return `10.${b[0]}.${b[1]}.${b[2]}`;
}

export interface ConsoleRequestOptions {
  ip?: string;
  headers?: Record<string, string | null>;
}

function withHeaders(base: Record<string, string>, options: ConsoleRequestOptions): Headers {
  const headers = new Headers(base);
  headers.set("cf-connecting-ip", options.ip ?? randomIp());
  for (const [name, value] of Object.entries(options.headers ?? {})) {
    if (value === null) headers.delete(name);
    else headers.set(name, value);
  }
  return headers;
}

export function claimRequest(claim: Record<string, unknown>, options: ConsoleRequestOptions = {}): Request {
  const body = JSON.stringify(claim);
  const headers = withHeaders(
    {
      "content-type": "application/json",
      "content-length": String(utf8(body).byteLength),
      "x-d2v-client": `d2vita/${String(claim.build_id)}`,
      "x-d2v-install": String(claim.install_id),
    },
    options,
  );
  return new Request("https://api.test/v1/claims", { method: "POST", headers, body });
}

export async function registerBuild(buildId = BUILD_ID, channel: "release" | "dev" | "test" = "release") {
  await env.DB.prepare(
    "INSERT INTO builds (build_id, version, channel, registered_at) VALUES (?1, ?2, ?3, ?4) ON CONFLICT DO NOTHING",
  )
    .bind(buildId, buildId.split("+")[0], channel, NOW)
    .run();
}

// Asserts that X-D2V-Signature is a valid Ed25519 signature of the exact body
// bytes under the test public key, then returns the parsed body.
export async function signedJson<T = Record<string, any>>(response: Response): Promise<T> {
  const bytes = new Uint8Array(await response.arrayBuffer());
  const signature = response.headers.get("x-d2v-signature");
  expect(signature, "X-D2V-Signature header").toBeTruthy();
  const key = await crypto.subtle.importKey(
    "raw",
    fromHex(env.TEST_RESPONSE_PUBLIC_KEY),
    { name: "Ed25519" },
    false,
    ["verify"],
  );
  expect(await crypto.subtle.verify("Ed25519", key, fromBase64(signature!), bytes), "signature verifies").toBe(true);
  return JSON.parse(new TextDecoder().decode(bytes)) as T;
}

export function bytesOf(n: number, seed = 7): Uint8Array {
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i++) out[i] = (i * 31 + seed) & 0xff;
  return out;
}

export function putRequest(
  reportId: string,
  name: string,
  body: Uint8Array,
  token: string | null,
  headers: Record<string, string | null> = {},
): Request {
  const h = new Headers({ "content-length": String(body.byteLength), "content-type": "application/octet-stream" });
  if (token !== null) h.set("authorization", `D2V-Upload ${token}`);
  for (const [k, v] of Object.entries(headers)) {
    if (v === null) h.delete(k);
    else h.set(k, v);
  }
  return new Request(`https://api.test/v1/reports/${reportId}/artifacts/${name}`, { method: "PUT", headers: h, body });
}

export function completeRequest(reportId: string, token: string | null, body: unknown = { v: 1, artifacts: [] }): Request {
  const text = JSON.stringify(body);
  const h = new Headers({ "content-type": "application/json", "content-length": String(text.length) });
  if (token !== null) h.set("authorization", `D2V-Upload ${token}`);
  return new Request(`https://api.test/v1/reports/${reportId}/complete`, { method: "POST", headers: h, body: text });
}

// Claims a new signature, uploads every requested piece and completes it.
export async function storeSample(claim: Record<string, unknown>, now = NOW): Promise<{ decision: Record<string, any>; pieces: Record<string, Uint8Array> }> {
  const decision = await signedJson(await call(claimRequest(claim), now));
  expect(decision.action).toBe("upload");
  const pieces: Record<string, Uint8Array> = {};
  for (const { name } of decision.upload.artifacts as Array<{ name: string }>) {
    pieces[name] = bytesOf(300, name.length);
    const res = await call(putRequest(decision.report_id, name, pieces[name]!, decision.upload.token), now);
    expect(res.status).toBe(201);
  }
  const done = await call(completeRequest(decision.report_id, decision.upload.token, { v: 1, artifacts: Object.keys(pieces) }), now);
  expect(done.status).toBe(200);
  return { decision, pieces };
}

export async function signatureRow(id: string): Promise<Record<string, any> | null> {
  return env.DB.prepare("SELECT * FROM signatures WHERE id = ?1").bind(id).first();
}

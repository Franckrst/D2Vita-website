import { env } from "cloudflare:workers";
import { expect } from "vitest";
import { canon, signatureId } from "../src/signature";
import type { Claim } from "../src/types";
import { call, claimRequest, NOW, signedJson } from "./helpers";

export function adminRequest(
  method: string,
  path: string,
  body?: unknown,
  token: string | null = env.TEST_ADMIN_TOKEN,
): Request {
  const headers = new Headers();
  if (token !== null) headers.set("authorization", `Bearer ${token}`);
  let text: string | undefined;
  if (body !== undefined) {
    text = JSON.stringify(body);
    headers.set("content-type", "application/json");
    headers.set("content-length", String(new TextEncoder().encode(text).byteLength));
  }
  return new Request(`https://api.test${path}`, { method, headers, body: text });
}

export async function admin<T = Record<string, any>>(
  method: string,
  path: string,
  body?: unknown,
  now = NOW,
): Promise<{ status: number; body: T }> {
  const res = await call(adminRequest(method, path, body), now);
  const text = await res.text();
  return { status: res.status, body: (text ? JSON.parse(text) : null) as T };
}

export async function sigOf(claim: Record<string, unknown>): Promise<string> {
  return signatureId(canon(claim as unknown as Claim));
}

// Sends a claim and returns its signed decision.
export async function sendClaim(claim: Record<string, unknown>, now = NOW): Promise<Record<string, any>> {
  const res = await call(claimRequest(claim), now);
  expect(res.status).toBe(200);
  return signedJson(res);
}

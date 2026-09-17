#!/usr/bin/env node
// Local smoke test against `wrangler dev --local` using .dev.client.json from
// scripts/dev-secrets.mjs: registers a test build, sends a claim of a new
// signature, verifies X-D2V-Signature, uploads the requested pieces, completes
// the report, reads a piece back through the admin API, and checks that a
// replay of the claim returns the identical signed decision.
//
// Usage: node scripts/smoke.mjs [base_url]   (default http://127.0.0.1:8787)

import { createPublicKey, randomBytes, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const base = (process.argv[2] ?? "http://127.0.0.1:8787").replace(/\/$/, "");
const client = JSON.parse(readFileSync(path.join(root, ".dev.client.json"), "utf8"));

// SPKI DER of an Ed25519 public key = fixed 12-byte prefix + raw key.
const publicKey = createPublicKey({
  key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(client.response_public_key_hex, "hex")]),
  format: "der",
  type: "spki",
});

const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const ulid = () => "01" + Array.from(randomBytes(24), (b) => CROCKFORD[b % 32]).join("");
const BUILD = "0.0.1+000000000000";

async function send(method, pathname, body, headers = {}) {
  const raw = body instanceof Uint8Array;
  const res = await fetch(base + pathname, {
    method,
    headers: { "content-type": raw ? "application/octet-stream" : "application/json", ...headers },
    body: body === undefined ? undefined : raw ? body : JSON.stringify(body),
  });
  const bytes = Buffer.from(await res.arrayBuffer());
  return { status: res.status, headers: res.headers, bytes, json: bytes.length ? JSON.parse(bytes) : null };
}

function checkSignature(res) {
  const sig = res.headers.get("x-d2v-signature");
  if (!sig || !verify(null, res.bytes, publicKey, Buffer.from(sig, "base64"))) {
    throw new Error("X-D2V-Signature missing or invalid");
  }
}

const build = await send(
  "POST",
  "/v1/admin/builds",
  { build_id: BUILD, version: "0.0.1", channel: "test" },
  { authorization: `Bearer ${client.admin_token}` },
);
if (build.status !== 200 && build.status !== 201) throw new Error(`build registration failed: ${build.status}`);

const installId = randomBytes(16).toString("hex");
const claim = {
  v: 1,
  report_id: ulid(),
  install_id: installId,
  build_id: BUILD,
  channel: "test",
  platform: { model: "vita", fw: "3.65" },
  session: { started_unix: Math.floor(Date.now() / 1000) - 60, uptime_s: 60, online: false },
  kind: "hang",
  // Random EIP: a new signature on every run, so an upload is requested. The
  // contract wants lower-case hex without leading zeros.
  features: {
    stalled_beats: 3,
    eip: `Game+0x${(parseInt(randomBytes(3).toString("hex"), 16) || 1).toString(16)}`,
    runner_state: "running",
  },
  hints: [],
  artifacts: [
    { name: "crash_log", bytes: 3000 },
    { name: "boot_progress", bytes: 70000 },
  ],
};
const headers = { "x-d2v-client": `d2vita/${BUILD}`, "x-d2v-install": installId };

const first = await send("POST", "/v1/claims", claim, headers);
checkSignature(first);
console.log("claim ->", first.status, first.json.action, first.json.signature);
if (first.json.action !== "upload") throw new Error("expected an upload decision for a new signature");

const pieces = {};
for (const { name } of first.json.upload.artifacts) {
  pieces[name] = randomBytes(claim.artifacts.find((a) => a.name === name).bytes);
  const put = await send("PUT", `/v1/reports/${claim.report_id}/artifacts/${name}`, pieces[name], {
    authorization: `D2V-Upload ${first.json.upload.token}`,
  });
  checkSignature(put);
  if (put.status !== 201) throw new Error(`upload of ${name} failed: ${put.status} ${put.bytes}`);
  console.log(`put ${name} ->`, put.status, put.json.bytes, "bytes");
}
const done = await send(
  "POST",
  `/v1/reports/${claim.report_id}/complete`,
  { v: 1, artifacts: Object.keys(pieces) },
  { authorization: `D2V-Upload ${first.json.upload.token}` },
);
checkSignature(done);
if (!done.json?.sample_stored) throw new Error(`complete did not store the sample: ${done.status} ${done.bytes}`);
console.log("complete ->", done.status, done.bytes.toString());

const back = await fetch(`${base}/v1/admin/artifacts/${claim.report_id}/boot_progress`, {
  headers: { authorization: `Bearer ${client.admin_token}` },
});
if (!Buffer.from(await back.arrayBuffer()).equals(pieces.boot_progress)) throw new Error("piece read back differs");
console.log("admin read-back -> identical bytes, sha256", back.headers.get("x-d2v-sha256"));

const replay = await send("POST", "/v1/claims", claim, headers);
checkSignature(replay);
if (!replay.bytes.equals(first.bytes)) throw new Error("replay returned a different decision");
console.log("replay -> identical signed decision");

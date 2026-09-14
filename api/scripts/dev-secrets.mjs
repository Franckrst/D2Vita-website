#!/usr/bin/env node
// Generates THROWAWAY secrets for local development with `wrangler dev --local`.
// Never use these values in staging or production.
//
//   .dev.vars          secrets read by wrangler dev (gitignored)
//   .dev.client.json   what a local client needs: admin token, response public key (gitignored)
//
// Usage: node scripts/dev-secrets.mjs [--force]

import { createHash, generateKeyPairSync, randomBytes } from "node:crypto";
import { existsSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const varsPath = path.join(root, ".dev.vars");
const clientPath = path.join(root, ".dev.client.json");

if (!process.argv.includes("--force") && (existsSync(varsPath) || existsSync(clientPath))) {
  console.error("Refusing to overwrite .dev.vars / .dev.client.json (pass --force).");
  process.exit(1);
}

const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const seed = privateKey.export({ format: "der", type: "pkcs8" }).subarray(-32).toString("hex");
const responsePublicKey = publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("hex");
const adminToken = randomBytes(32).toString("base64url");

const vars = {
  ADMIN_TOKEN_SHA256: createHash("sha256").update(adminToken).digest("hex"),
  UPLOAD_TOKEN_KEY: randomBytes(32).toString("hex"),
  RESPONSE_SIGNING_KEY: seed,
  INSTALL_HASH_KEY: randomBytes(32).toString("hex"),
  // Cloudflare's documented always-pass Turnstile test secret.
  TURNSTILE_SECRET: "1x0000000000000000000000000000000AA",
};

writeFileSync(
  varsPath,
  "# THROWAWAY local development secrets (scripts/dev-secrets.mjs). Never deploy these.\n" +
    Object.entries(vars)
      .map(([k, v]) => `${k}=${v}`)
      .join("\n") +
    "\n",
  { mode: 0o600 },
);
writeFileSync(clientPath, JSON.stringify({ admin_token: adminToken, response_public_key_hex: responsePublicKey }, null, 2) + "\n", {
  mode: 0o600,
});
console.log(`Wrote ${path.relative(process.cwd(), varsPath)} and ${path.relative(process.cwd(), clientPath)}.`);
console.log(`Response public key (hex): ${responsePublicKey}`);

import { createHash, generateKeyPairSync, randomBytes } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

const here = path.dirname(fileURLToPath(import.meta.url));

// Throwaway secrets generated for every test run. Nothing here is a real
// credential and nothing is written to disk.
function throwawaySecrets(): Record<string, string> {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  // PKCS#8 and SPKI DER encodings of Ed25519 keys end with the raw 32 bytes.
  const seed = privateKey.export({ format: "der", type: "pkcs8" }).subarray(-32);
  const pub = publicKey.export({ format: "der", type: "spki" }).subarray(-32);
  const adminToken = randomBytes(32).toString("base64url");
  return {
    RESPONSE_SIGNING_KEY: Buffer.from(seed).toString("hex"),
    TEST_RESPONSE_PUBLIC_KEY: Buffer.from(pub).toString("hex"),
    TEST_ADMIN_TOKEN: adminToken,
    ADMIN_TOKEN_SHA256: createHash("sha256").update(adminToken).digest("hex"),
    UPLOAD_TOKEN_KEY: randomBytes(32).toString("hex"),
    INSTALL_HASH_KEY: randomBytes(32).toString("hex"),
    TURNSTILE_SECRET: "test-turnstile-secret",
  };
}

export default defineConfig(async () => {
  const migrations = await readD1Migrations(path.join(here, "migrations"));
  return {
    plugins: [
      cloudflareTest({
        wrangler: { configPath: "./wrangler.jsonc" },
        miniflare: {
          bindings: { ...throwawaySecrets(), TEST_MIGRATIONS: migrations },
        },
      }),
    ],
    test: {
      setupFiles: ["./test/apply-migrations.ts"],
    },
  };
});

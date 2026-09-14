// Bindings, variables and secrets available to the Worker.
export interface Env {
  DB: D1Database;
  ARTIFACTS: R2Bucket;

  // Plain variables (wrangler.jsonc "vars").
  ALLOWED_ORIGIN?: string;

  // Secrets (wrangler secret put). All are optional at the type level so the
  // code has to fail closed when one is missing.
  ADMIN_TOKEN_SHA256?: string;
  UPLOAD_TOKEN_KEY?: string;
  RESPONSE_SIGNING_KEY?: string;
  INSTALL_HASH_KEY?: string;
  TURNSTILE_SECRET?: string;
  TELEGRAM_BOT_TOKEN?: string;
  TELEGRAM_CHAT_ID?: string;
}

// Secrets are mandatory at run time: a missing one is a 500, never a bypass.
export function requireSecret(value: string | undefined, name: string): string {
  if (!value) throw new Error(`secret ${name} is not configured`);
  return value;
}

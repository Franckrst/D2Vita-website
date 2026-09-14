// Types of the bindings seen by tests through `import { env } from "cloudflare:workers"`.
declare namespace Cloudflare {
  interface GlobalProps {
    mainModule: typeof import("../src/index");
  }

  interface Env {
    DB: D1Database;
    ARTIFACTS: R2Bucket;
    ALLOWED_ORIGIN?: string;
    ADMIN_TOKEN_SHA256?: string;
    UPLOAD_TOKEN_KEY?: string;
    RESPONSE_SIGNING_KEY?: string;
    INSTALL_HASH_KEY?: string;
    TURNSTILE_SECRET?: string;
    TELEGRAM_BOT_TOKEN?: string;
    TELEGRAM_CHAT_ID?: string;

    // Test-only bindings injected by vitest.config.ts.
    TEST_MIGRATIONS: import("cloudflare:test").D1Migration[];
    TEST_RESPONSE_PUBLIC_KEY: string;
    TEST_ADMIN_TOKEN: string;
  }
}

// Runs before every test file: storage is isolated per file, so each file
// starts from an empty D1 database with the migrations applied.
import { applyD1Migrations } from "cloudflare:test";
import { env } from "cloudflare:workers";

await applyD1Migrations(env.DB, env.TEST_MIGRATIONS);

// Shared test helpers.
import { env } from "cloudflare:workers";

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

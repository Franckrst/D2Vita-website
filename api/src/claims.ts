// POST /v1/claims (spec sections 5.2, 5.4, 5.5).
//
// Order: size -> kill switch -> schema -> console headers -> known build ->
// replay -> rate limits -> one D1 transaction (dedup + counters + lease).
// The sample lease is an atomic conditional UPDATE: of N simultaneous claims
// of a new signature exactly one obtains it, whatever the interleaving.

import { installHash, toHex } from "./crypto";
import { requireSecret, type Env } from "./env";
import { error, json, jsonText, readBoundedJson } from "./http";
import {
  SCOPE,
  consumeAll,
  installCaps,
  ipHash,
  loadSettings,
  networkKey,
  notAccepting,
  rateLimited,
  utcDay,
  type LimitCheck,
} from "./limits";
import { notify } from "./notify";
import { RULES_VERSION, canon, signatureId } from "./signature";
import { createUploadToken, type RequestedArtifact } from "./token";
import { ARTIFACT_MAX_BYTES, type ArtifactName, type Channel, type Claim, type Kind } from "./types";
import { validateClaim } from "./validate";

export const CLAIM_MAX_BYTES = 16 * 1024;
export const LEASE_SECONDS = 1800;

// Pieces requested for each kind (spec section 4.5 "Envoyée pour").
const WANTED: Record<Kind, readonly ArtifactName[]> = {
  host_fault: ["dump", "crash_log", "boot_progress"],
  halt: ["crash_txt", "crash_log", "boot_progress"],
  abnormal_exit: ["crash_txt", "crash_log", "boot_progress"],
  guest_fault: ["crash_log", "boot_progress"],
  hang: ["crash_log", "boot_progress"],
};

interface BuildRow {
  build_id: string;
  version: string;
  channel: Channel;
}

interface SignatureHead {
  id: string;
  status: string;
  fixed_in_version: string | null;
  merged_into: string | null;
}

// Numeric X.Y.Z comparison (build_id VERSION part).
export function compareVersions(a: string, b: string): number {
  const pa = a.split(".").map((x) => BigInt(x));
  const pb = b.split(".").map((x) => BigInt(x));
  for (let i = 0; i < 3; i++) {
    const x = pa[i] ?? 0n;
    const y = pb[i] ?? 0n;
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

function consoleHeaderError(request: Request, claim: Claim): string | null {
  if (request.headers.get("x-d2v-client") !== `d2vita/${claim.build_id}`) {
    return "X-D2V-Client must be d2vita/<build_id of the claim>";
  }
  if (request.headers.get("x-d2v-install") !== claim.install_id) {
    return "X-D2V-Install must be the install_id of the claim";
  }
  return null;
}

// Follows merged_into to the root (merges are flattened by the admin route;
// the hop limit only guards against a corrupted chain).
async function resolveSignature(db: D1Database, id: string): Promise<{ id: string; head: SignatureHead | null }> {
  const read = (sig: string) =>
    db
      .prepare("SELECT id, status, fixed_in_version, merged_into FROM signatures WHERE id = ?1")
      .bind(sig)
      .first<SignatureHead>();
  let head = await read(id);
  for (let hops = 0; head?.merged_into && hops < 4; hops++) {
    const next = await read(head.merged_into);
    if (!next) break;
    head = next;
  }
  return { id: head?.id ?? id, head };
}

function requestedArtifacts(claim: Claim): RequestedArtifact[] {
  return WANTED[claim.kind]
    .filter((name) => {
      const offered = claim.artifacts.find((a) => a.name === name);
      return offered !== undefined && offered.bytes <= ARTIFACT_MAX_BYTES[name];
    })
    .map((name) => ({ name, max_bytes: ARTIFACT_MAX_BYTES[name] }));
}

function decisionText(
  reportId: string,
  signature: string,
  upload: { token: string; expires_unix: number; artifacts: RequestedArtifact[] } | null,
): string {
  return JSON.stringify({
    v: 1,
    report_id: reportId,
    signature,
    action: upload ? "upload" : "count_only",
    upload,
    retry_after_s: null,
    disable_until_unix: null,
  });
}

export interface IngestOutcome {
  decision: string;
  inserted: boolean; // false when a concurrent request with the same report_id won
  newSignature: boolean;
  regressed: boolean;
  signature: string;
}

export async function handleClaim(request: Request, env: Env, ctx: ExecutionContext, now: number): Promise<Response> {
  const body = await readBoundedJson(request, CLAIM_MAX_BYTES);
  if (!body.ok) return body.response;

  const settings = await loadSettings(env.DB);
  if (!settings.accepting) return notAccepting(settings, now);

  const validation = validateClaim(body.value);
  if (!validation.ok) return error("invalid_payload", validation.error);
  const claim = validation.value;
  // Answers to a valid claim are bound to its report (decisions already are).
  const bound = { report_id: claim.report_id };
  const headerError = consoleHeaderError(request, claim);
  if (headerError) return error("invalid_payload", headerError, bound);

  const build = await env.DB.prepare("SELECT build_id, version, channel FROM builds WHERE build_id = ?1")
    .bind(claim.build_id)
    .first<BuildRow>();
  if (!build) return error("unknown_build", "This build is not registered", bound);

  const install = await installHash(requireSecret(env.INSTALL_HASH_KEY, "INSTALL_HASH_KEY"), claim.install_id);

  // Replay of the same report_id: same decision, nothing counted again.
  const previous = await env.DB.prepare("SELECT install_hash, decision FROM reports WHERE report_id = ?1")
    .bind(claim.report_id)
    .first<{ install_hash: string; decision: string }>();
  if (previous) {
    if (previous.install_hash !== install) {
      return error("invalid_payload", "report_id is already used by another installation", bound);
    }
    return jsonText(previous.decision);
  }

  const rawCanon = canon(claim);
  const rawId = await signatureId(rawCanon);
  const target = await resolveSignature(env.DB, rawId);

  // Rate limits, most specific first (spec section 5.5).
  const day = utcDay(now);
  const network = networkKey(request.headers.get("cf-connecting-ip"), 48);
  const ipSubject = await ipHash(env, env.DB, network, day, settings.salts);
  const perInstall = installCaps(settings.caps, build.channel);
  const checks: LimitCheck[] = [
    { scope: SCOPE.installClaims, subject: install, amount: 1, cap: perInstall.claims },
    { scope: SCOPE.ipClaims, subject: ipSubject, amount: 1, cap: settings.caps.ip_claims_per_day },
    { scope: SCOPE.globalClaims, subject: "*", amount: 1, cap: settings.caps.global_claims_per_day },
  ];
  if (!target.head) {
    checks.push({ scope: SCOPE.globalNewSignatures, subject: "*", amount: 1, cap: settings.caps.global_new_signatures_per_day });
  }
  if (await consumeAll(env.DB, day, checks)) return rateLimited(now, bound);

  const outcome = await ingest(env, claim, build, install, rawId, rawCanon, target, now, target.head ? null : day);
  if (outcome.newSignature) {
    ctx.waitUntil(notify(env, `D2Vita crash: new signature ${outcome.signature} (${claim.kind}) on ${claim.build_id}\n${rawCanon}`));
  } else if (outcome.regressed) {
    ctx.waitUntil(
      notify(env, `D2Vita crash: signature ${outcome.signature} regressed on ${claim.build_id} (fixed in ${target.head?.fixed_in_version})`),
    );
  }
  return jsonText(outcome.decision);
}

async function ingest(
  env: Env,
  claim: Claim,
  build: BuildRow,
  install: string,
  rawId: string,
  rawCanon: string,
  target: { id: string; head: SignatureHead | null },
  now: number,
  // UTC day whose new-signature budget this request consumed, if any.
  newSignatureDay: string | null,
): Promise<IngestOutcome> {
  const db = env.DB;
  const nonce = toHex(crypto.getRandomValues(new Uint8Array(16)));
  const sig = target.id;
  const requested = requestedArtifacts(claim);
  const expires = now + LEASE_SECONDS;
  const countOnly = decisionText(claim.report_id, sig, null);
  const upload =
    requested.length > 0
      ? decisionText(claim.report_id, sig, {
          token: await createUploadToken(requireSecret(env.UPLOAD_TOKEN_KEY, "UPLOAD_TOKEN_KEY"), {
            report_id: claim.report_id,
            signature: sig,
            artifacts: requested,
            expires_unix: expires,
          }),
          expires_unix: expires,
          artifacts: requested,
        })
      : null;

  const head = target.head;
  const mayRegress =
    head !== null &&
    head.status === "fixed" &&
    head.fixed_in_version !== null &&
    compareVersions(build.version, head.fixed_in_version) >= 0;

  // Every statement after the insert only acts if THIS request inserted the
  // report row (a duplicate report_id leaves another nonce in place).
  const mine = "EXISTS (SELECT 1 FROM reports WHERE report_id = ?1 AND ingest_nonce = ?2)";
  const statements: D1PreparedStatement[] = [];

  // The claim is kept as it was received: admin.v1#ReportDetail returns it and
  // the contract validates it against claim.v1, where install_id is required.
  // The pseudonym install_hash is what every counter and every link uses.

  statements.push(
    db
      .prepare(
        `INSERT INTO reports (report_id, ingest_nonce, signature, raw_signature, install_hash, build_id, channel,
                              kind, received_at, claim, decision, action, rules_version)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 'count_only', ?12)
         ON CONFLICT (report_id) DO NOTHING`,
      )
      .bind(
        claim.report_id,
        nonce,
        sig,
        rawId,
        install,
        claim.build_id,
        build.channel,
        claim.kind,
        now,
        JSON.stringify(claim),
        countOnly,
        RULES_VERSION,
      ),
  );

  const regressionIndex = statements.length;
  if (mayRegress) {
    statements.push(
      db
        .prepare(
          `UPDATE signatures SET status = 'regressed', status_changed_at = ?3, sample_state = 'none',
                  lease_report = NULL, lease_expires = NULL
           WHERE id = ?4 AND status = 'fixed' AND fixed_in_version = ?5 AND ${mine}
           RETURNING id`,
        )
        .bind(claim.report_id, nonce, now, sig, head.fixed_in_version),
    );
  }

  const upsertIndex = statements.length;
  statements.push(
    db
      .prepare(
        `INSERT INTO signatures (id, kind, canon, rules_version, count, installs, first_seen, last_seen, first_build, last_build)
         SELECT ?3, ?4, ?5, ?6, 1, 0, ?7, ?7, ?8, ?8 WHERE ${mine}
         ON CONFLICT (id) DO UPDATE SET count = count + 1, last_seen = excluded.last_seen, last_build = excluded.last_build
         RETURNING count`,
      )
      .bind(claim.report_id, nonce, sig, claim.kind, rawCanon, RULES_VERSION, now, claim.build_id),
  );
  if (newSignatureDay !== null) {
    // The signature looked new before the transaction, but a concurrent claim
    // created it first: give back the new-signature budget taken for it.
    statements.push(
      db
        .prepare(
          `UPDATE rate_counters SET n = n - 1
           WHERE scope = ?3 AND subject = '*' AND day = ?4 AND n > 0 AND ${mine}
             AND EXISTS (SELECT 1 FROM signatures WHERE id = ?5 AND count > 1)`,
        )
        .bind(claim.report_id, nonce, SCOPE.globalNewSignatures, newSignatureDay, sig),
    );
  }
  statements.push(
    db
      .prepare(
        `UPDATE signatures SET installs = installs + 1
         WHERE id = ?3 AND ${mine}
           AND NOT EXISTS (SELECT 1 FROM signature_installs WHERE signature = ?3 AND install_hash = ?4)`,
      )
      .bind(claim.report_id, nonce, sig, install),
    db
      .prepare(
        `INSERT INTO signature_installs (signature, install_hash, first_seen)
         SELECT ?3, ?4, ?5 WHERE ${mine}
         ON CONFLICT (signature, install_hash) DO NOTHING`,
      )
      .bind(claim.report_id, nonce, sig, install, now),
    db
      .prepare(
        `INSERT INTO signature_builds (signature, build_id, count, first_seen, last_seen)
         SELECT ?3, ?4, 1, ?5, ?5 WHERE ${mine}
         ON CONFLICT (signature, build_id) DO UPDATE SET count = count + 1, last_seen = excluded.last_seen`,
      )
      .bind(claim.report_id, nonce, sig, claim.build_id, now),
  );

  if (upload) {
    statements.push(
      // The lease: one conditional UPDATE, atomic in SQLite.
      db
        .prepare(
          `UPDATE signatures SET sample_state = 'leased', lease_report = ?1, lease_expires = ?4
           WHERE id = ?3 AND ${mine}
             AND (sample_state = 'none' OR (sample_state = 'leased' AND lease_expires < ?5))`,
        )
        .bind(claim.report_id, nonce, sig, expires, now),
      db
        .prepare(
          `UPDATE reports SET action = 'upload', decision = ?3, requested = ?4, upload_expires = ?5
           WHERE report_id = ?1 AND ingest_nonce = ?2
             AND EXISTS (SELECT 1 FROM signatures WHERE id = ?6 AND sample_state = 'leased' AND lease_report = ?1)`,
        )
        .bind(claim.report_id, nonce, upload, JSON.stringify(requested), expires, sig),
    );
  }

  const readIndex = statements.length;
  statements.push(
    db.prepare("SELECT decision, ingest_nonce = ?2 AS inserted FROM reports WHERE report_id = ?1").bind(claim.report_id, nonce),
  );

  const results = await db.batch<Record<string, unknown>>(statements);
  const final = results[readIndex]?.results[0] as { decision: string; inserted: number } | undefined;
  if (!final) throw new Error("claim transaction returned no decision");
  const upserted = results[upsertIndex]?.results[0] as { count: number } | undefined;
  return {
    decision: final.decision,
    inserted: final.inserted === 1,
    newSignature: final.inserted === 1 && upserted?.count === 1,
    regressed: mayRegress && (results[regressionIndex]?.results.length ?? 0) > 0,
    signature: sig,
  };
}

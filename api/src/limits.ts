// Rate limits (spec section 5.5): exact daily counters in D1.

const MiB = 1024 * 1024;

// Initial values of the adjustable caps (PUT /v1/admin/settings overrides them).
export const DEFAULT_CAPS = {
  install_claims: 3,
  install_artifact_bytes: 3 * MiB,
  // dev/test builds are not distributed: raised caps.
  install_claims_dev: 50,
  install_artifact_bytes_dev: 64 * MiB,
  ip_claims: 10,
  ip_bugs: 3,
  global_claims: 2000,
  global_artifact_bytes: 300 * MiB,
  global_new_signatures: 200,
  global_bugs: 100,
} as const;

export type CapName = keyof typeof DEFAULT_CAPS;
export type Caps = Record<CapName, number>;

export const CAP_NAMES = Object.keys(DEFAULT_CAPS) as CapName[];

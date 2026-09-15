// Test data builders.

const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

function randomChars(alphabet: string, n: number): string {
  const bytes = crypto.getRandomValues(new Uint8Array(n));
  let out = "";
  for (const b of bytes) out += alphabet[b % alphabet.length];
  return out;
}

export function ulid(): string {
  return "01" + randomChars(CROCKFORD, 24);
}

export function installId(): string {
  return randomChars("0123456789abcdef", 32);
}

export const BUILD_ID = "0.1.0+ab12cd34ef56";

// Halt features: every key of the contract schema is required, so an override
// only changes what it names.
export function haltFeatures(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    code: 1420,
    location: null,
    frames: ["Game+0x1fedf4", "Game+0x451c23", "Game+0x44f570"],
    ...overrides,
  };
}

// The claim of spec section 4.4 (halt), with fresh ids.
export function haltClaim(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    v: 1,
    report_id: ulid(),
    install_id: installId(),
    build_id: BUILD_ID,
    channel: "release",
    platform: { model: "vita", fw: "3.65" },
    session: { started_unix: 1789284000, uptime_s: 967, online: false },
    kind: "halt",
    features: haltFeatures(),
    hints: ["guest_fault"],
    artifacts: [
      { name: "crash_txt", bytes: 2210 },
      { name: "crash_log", bytes: 3104 },
      { name: "boot_progress", bytes: 262144 },
    ],
    ...overrides,
  };
}

export function hostFaultClaim(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return haltClaim({
    kind: "host_fault",
    features: {
      stop_reason: "0x30004",
      thread_name: "d2main",
      pc: { region: "eboot", module: "eboot", offset: "0x1a2b" },
      lr: { region: "eboot", module: "eboot", offset: "0x3c4d" },
      guest_frames: ["Game+0x10", "Game+0x20"],
      redaction: "clean",
    },
    hints: [],
    artifacts: [
      { name: "dump", bytes: 900000 },
      { name: "crash_log", bytes: 3104 },
      { name: "boot_progress", bytes: 262144 },
    ],
    ...overrides,
  });
}

export function bugBody(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    title: "Crash when opening the stash",
    description: "The game froze after I clicked the stash in Lut Gholein.",
    version: "0.1.0",
    contact: "player@example.com",
    lang: "en",
    turnstile_token: "XXXX.DUMMY.TOKEN.XXXX",
    ...overrides,
  };
}

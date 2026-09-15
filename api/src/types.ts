// Claim v1 (spec section 4.4) as seen by the API after validation.

export const KINDS = ["halt", "guest_fault", "host_fault", "abnormal_exit", "hang"] as const;
export type Kind = (typeof KINDS)[number];

export const ARTIFACT_NAMES = ["dump", "crash_txt", "crash_log", "boot_progress"] as const;
export type ArtifactName = (typeof ARTIFACT_NAMES)[number];

export const CHANNELS = ["release", "dev", "test"] as const;
export type Channel = (typeof CHANNELS)[number];

export const REGIONS = ["eboot", "jit", "sysmodule", "unknown"] as const;
export type Region = (typeof REGIONS)[number];

export const EXIT_REASONS = [
  "main_thread_fault",
  "unshimmed_import",
  "fatal_app_exit",
  "raise_exception",
  "exit_process",
] as const;
export type ExitReason = (typeof EXIT_REASONS)[number];

export const PLATFORM_MODELS = ["vita", "pstv", "unknown"] as const;

// Sealed size caps of design section 4.5, in bytes, and the smallest D2VSEAL1
// object (an empty artifact: 72-byte header plus one 16-byte tag).
export const ARTIFACT_MAX_BYTES: Record<ArtifactName, number> = {
  dump: 2 * 1024 * 1024,
  crash_txt: 64 * 1024,
  crash_log: 64 * 1024,
  boot_progress: 320 * 1024,
};
export const SEALED_MIN_BYTES = 88;

// "<module>+0x<offset>" addresses are kept as received strings.
export type Address = string;

export interface CodeLocation {
  region: Region;
  module: string;
  offset: string; // "0x…" lower-case hex
}

// Every feature key is required; null means unknown (contract README, decision 4).
export interface HaltFeatures {
  code: number;
  location: string | null;
  frames: Address[];
}

export interface GuestFaultFeatures {
  exception: string | null;
  thread: "main" | "worker";
  eip: Address;
  frames: Address[];
}

export interface HostFaultFeatures {
  stop_reason: string | null;
  thread_name: string | null;
  pc: CodeLocation;
  lr: CodeLocation;
  guest_frames: Address[];
  redaction: "clean" | "withheld";
}

export interface AbnormalExitFeatures {
  reason: ExitReason;
  code: number | null;
  import: string | null;
  frames: Address[];
}

export interface HangFeatures {
  stalled_beats: number;
  eip: Address | null;
  runner_state: string | null;
}

export type KindFeatures =
  | { kind: "halt"; features: HaltFeatures }
  | { kind: "guest_fault"; features: GuestFaultFeatures }
  | { kind: "host_fault"; features: HostFaultFeatures }
  | { kind: "abnormal_exit"; features: AbnormalExitFeatures }
  | { kind: "hang"; features: HangFeatures };

export interface ClaimArtifact {
  name: ArtifactName;
  bytes: number;
}

export type Claim = {
  v: 1;
  report_id: string;
  install_id: string;
  build_id: string;
  channel: Channel;
  platform: { model: string; fw: string };
  session: { started_unix: number; uptime_s: number | null; online: boolean };
  hints: Kind[];
  artifacts: ClaimArtifact[];
  redactions?: number;
} & KindFeatures;

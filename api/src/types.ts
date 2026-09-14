// Claim v1 (spec section 4.4) as seen by the API after validation.

export const KINDS = ["halt", "guest_fault", "host_fault", "abnormal_exit", "hang"] as const;
export type Kind = (typeof KINDS)[number];

export const ARTIFACT_NAMES = ["dump", "crash_txt", "crash_log", "boot_progress"] as const;
export type ArtifactName = (typeof ARTIFACT_NAMES)[number];

export const CHANNELS = ["release", "dev", "test"] as const;
export type Channel = (typeof CHANNELS)[number];

export const REGIONS = ["eboot", "jit", "sysmodule", "unknown"] as const;
export type Region = (typeof REGIONS)[number];

// "<module>+0x<offset>" addresses are kept as received strings.
export type Address = string;

export interface CodeLocation {
  region: Region;
  module: string | null;
  offset: string; // "0x…" lower-case hex
}

export interface HaltFeatures {
  code?: number | null;
  location?: string | null;
  frames?: Address[];
}

export interface GuestFaultFeatures {
  exception?: string | null;
  thread?: "main" | "worker" | null;
  eip?: Address | null;
  frames?: Address[];
}

export interface HostFaultFeatures {
  stop_reason?: string | null;
  thread_name?: string | null;
  pc?: CodeLocation | null;
  lr?: CodeLocation | null;
  guest_frames?: Address[];
  redaction?: "clean" | "withheld" | null;
}

export interface AbnormalExitFeatures {
  reason?: string | null;
  code?: number | null;
  import?: string | null;
  frames?: Address[];
}

export interface HangFeatures {
  stalled_beats?: number | null;
  eip?: Address | null;
  runner_state?: string | null;
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
  session: { started_unix: number; uptime_s: number; online: boolean };
  hints: Kind[];
  artifacts: ClaimArtifact[];
  redactions?: number;
} & KindFeatures;

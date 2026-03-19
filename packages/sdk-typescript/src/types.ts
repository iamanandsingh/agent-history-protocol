/**
 * AHP enums and constants — matches Appendix A protobuf schema.
 *
 * All enum values are identical to the Python SDK to ensure
 * cross-SDK canonical byte compatibility.
 */

// --- Enums ---

export enum RecordType {
  ACTION = 1,
  GAP = 2,
  CHECKPOINT = 3,
  BOOT = 4,
  RECOVERY = 5,
  KEY = 6,
  WITNESS = 7,
}

export enum ResultStatus {
  SUCCESS = 1,
  FAILURE = 2,
  TIMEOUT = 3,
  ERROR = 4,
}

export enum Protocol {
  MCP = 1,
  HTTP = 2,
  GRPC = 3,
  A2A = 4,
  SHELL = 5,
  CUSTOM = 6,
}

export enum ActionType {
  TOOL_CALL = 1,
  INFERENCE = 2,
  DELEGATION = 3,
  MESSAGE = 4,
  CUSTOM = 5,
}

export enum AuthorizationType {
  AUTH_NONE = 1,
  AUTH_HUMAN = 2,
  AUTH_AGENT = 3,
  AUTH_POLICY = 4,
  AUTH_MULTI_PARTY = 5,
}

export enum AuthorizerType {
  AUTHORIZER_HUMAN = 1,
  AUTHORIZER_AGENT = 2,
  AUTHORIZER_POLICY_ENGINE = 3,
}

export enum AuthorizationDecision {
  APPROVED = 1,
  REJECTED = 2,
  CONDITIONAL = 3,
}

export enum GapReason {
  CRASH = 1,
  DISK_FULL = 2,
  DISK_CORRUPT = 3,
  ROTATION = 4,
  INTERCEPTOR_FAILURE = 5,
  BACKPRESSURE = 6,
  MANUAL_PURGE = 7,
}

export enum ChainLevel {
  LEVEL_1 = 1,
  LEVEL_2 = 2,
  LEVEL_3 = 3,
}

export enum FsyncMode {
  EVERY = 1,
  BATCH = 2,
  NONE = 3,
}

export enum RecoveryMethod {
  CHECKPOINT_FILE = 1,
  CHAIN_SCAN = 2,
  FRESH_START = 3,
}

// --- Constants ---

export const SCHEMA_VERSION = 1;

/** 32 zero bytes — genesis prev_hash sentinel. Frozen to prevent mutation. */
export const ZERO_HASH_32: Readonly<Uint8Array> = Object.freeze(new Uint8Array(32));

/** 16 zero bytes — default hash placeholder. Frozen to prevent mutation. */
export const ZERO_HASH_16: Readonly<Uint8Array> = Object.freeze(new Uint8Array(16));

/** 16 zero bytes — null UUID. Frozen to prevent mutation. */
export const ZERO_UUID: Readonly<Uint8Array> = Object.freeze(new Uint8Array(16));

// --- Data model interfaces ---

export interface AuthorizationEntry {
  authorizer_type: AuthorizerType;
  authorizer_id: string;
  authorizer_agent_id: Uint8Array; // 16 bytes
  authorizer_seq: bigint;
  decision: AuthorizationDecision;
  condition: string;
  timestamp_ms: bigint;
}

export interface Authorization {
  type: AuthorizationType;
  entries: AuthorizationEntry[];
}

export interface ActionPayload {
  kind: "action";
  parent_action_id: Uint8Array; // 16 bytes UUID
  tool_name: string;
  parameters_hash: Uint8Array; // 16 bytes
  result_hash: Uint8Array; // 16 bytes
  result_status: ResultStatus;
  response_time_ms: number;
  protocol: Protocol;
  action_type: ActionType;
  target_entity: string;
  evidence_uri: string;
  redacted: boolean;
  model_id: string;
  input_token_count: number;
  output_token_count: number;
  authorization: Authorization;
}

export interface GapPayload {
  kind: "gap";
  first_lost_sequence: bigint;
  last_lost_sequence: bigint;
  count: bigint;
  reason: GapReason;
  detail: string;
}

export interface CheckpointPayload {
  kind: "checkpoint";
  record_count: bigint;
  gap_count: bigint;
  chain_hash: Uint8Array; // 32 bytes
  merkle_root: Uint8Array; // 32 bytes
  signature: Uint8Array; // 64 bytes
  signing_key_id: Uint8Array; // 32 bytes
  evidence_available: bigint;
  evidence_exported: bigint;
  evidence_expired: bigint;
  evidence_missing: bigint;
}

export interface BootPayload {
  kind: "boot";
  sdk_name: string;
  sdk_version: string;
  interceptors: string[];
  agent_framework: string;
  agent_name: string;
  runtime: string;
  chain_level: ChainLevel;
  fsync_mode: FsyncMode;
  clock_source: string;
  inference_recording: boolean;
  inference_evidence: boolean;
  evidence_recording: boolean;
  filter_config_hash: Uint8Array; // 32 bytes
  matched_agent_rule: string;
  config_source: string;
  authorization_recording: boolean;
}

export interface RecoveryPayload {
  kind: "recovery";
  records_verified: bigint;
  records_truncated: bigint;
  last_valid_seq: bigint;
  recovery_method: RecoveryMethod;
  detail: string;
}

export interface KeyPayload {
  kind: "key";
  public_key: Uint8Array; // 32 bytes
  key_id: Uint8Array; // 32 bytes
  expires_at: bigint;
  supersedes_key_id: Uint8Array; // 32 bytes
}

export interface WitnessPayload {
  kind: "witness";
  witness_id: string;
  checkpoint_seq: bigint;
  checkpoint_hash: Uint8Array; // 32 bytes
  witness_timestamp: bigint;
  receipt_signature: Uint8Array; // 64 bytes
  witness_public_key: Uint8Array; // 32 bytes
}

export type Payload =
  | ActionPayload
  | GapPayload
  | CheckpointPayload
  | BootPayload
  | RecoveryPayload
  | KeyPayload
  | WitnessPayload;

export interface Record {
  record_id: Uint8Array; // 16 bytes UUID v7
  agent_id: Uint8Array; // 16 bytes UUID
  session_id: Uint8Array; // 16 bytes UUID
  timestamp_ms: bigint;
  sequence: bigint;
  prev_hash: Uint8Array; // 32 bytes
  schema_version: number;
  record_type: RecordType;
  payload: Payload;
}

// --- Payload-to-RecordType mapping ---

export const PAYLOAD_TYPE_MAP: { [K in Payload["kind"]]: RecordType } = {
  action: RecordType.ACTION,
  gap: RecordType.GAP,
  checkpoint: RecordType.CHECKPOINT,
  boot: RecordType.BOOT,
  recovery: RecordType.RECOVERY,
  key: RecordType.KEY,
  witness: RecordType.WITNESS,
};

// --- Factory helpers ---

export function createActionPayload(
  overrides: Partial<Omit<ActionPayload, "kind">> = {}
): ActionPayload {
  return {
    kind: "action",
    parent_action_id: ZERO_UUID,
    tool_name: "",
    parameters_hash: ZERO_HASH_16,
    result_hash: ZERO_HASH_16,
    result_status: ResultStatus.SUCCESS,
    response_time_ms: 0,
    protocol: Protocol.CUSTOM,
    action_type: ActionType.TOOL_CALL,
    target_entity: "",
    evidence_uri: "",
    redacted: false,
    model_id: "",
    input_token_count: 0,
    output_token_count: 0,
    authorization: { type: AuthorizationType.AUTH_NONE, entries: [] },
    ...overrides,
  };
}

export function createGapPayload(
  overrides: Partial<Omit<GapPayload, "kind">> = {}
): GapPayload {
  return {
    kind: "gap",
    first_lost_sequence: 0n,
    last_lost_sequence: 0n,
    count: 0n,
    reason: GapReason.CRASH,
    detail: "",
    ...overrides,
  };
}

export function createCheckpointPayload(
  overrides: Partial<Omit<CheckpointPayload, "kind">> = {}
): CheckpointPayload {
  return {
    kind: "checkpoint",
    record_count: 0n,
    gap_count: 0n,
    chain_hash: ZERO_HASH_32,
    merkle_root: ZERO_HASH_32,
    signature: new Uint8Array(64),
    signing_key_id: ZERO_HASH_32,
    evidence_available: 0n,
    evidence_exported: 0n,
    evidence_expired: 0n,
    evidence_missing: 0n,
    ...overrides,
  };
}

export function createBootPayload(
  overrides: Partial<Omit<BootPayload, "kind">> = {}
): BootPayload {
  return {
    kind: "boot",
    sdk_name: "ahp-typescript",
    sdk_version: "0.1.0",
    interceptors: [],
    agent_framework: "",
    agent_name: "",
    runtime: "",
    chain_level: ChainLevel.LEVEL_1,
    fsync_mode: FsyncMode.BATCH,
    clock_source: "system",
    inference_recording: true,
    inference_evidence: false,
    evidence_recording: false,
    filter_config_hash: ZERO_HASH_32,
    matched_agent_rule: "",
    config_source: "",
    authorization_recording: false,
    ...overrides,
  };
}

export function createRecoveryPayload(
  overrides: Partial<Omit<RecoveryPayload, "kind">> = {}
): RecoveryPayload {
  return {
    kind: "recovery",
    records_verified: 0n,
    records_truncated: 0n,
    last_valid_seq: 0n,
    recovery_method: RecoveryMethod.CHAIN_SCAN,
    detail: "",
    ...overrides,
  };
}

export function createKeyPayload(
  overrides: Partial<Omit<KeyPayload, "kind">> = {}
): KeyPayload {
  return {
    kind: "key",
    public_key: ZERO_HASH_32,
    key_id: ZERO_HASH_32,
    expires_at: 0n,
    supersedes_key_id: ZERO_HASH_32,
    ...overrides,
  };
}

export function createWitnessPayload(
  overrides: Partial<Omit<WitnessPayload, "kind">> = {}
): WitnessPayload {
  return {
    kind: "witness",
    witness_id: "",
    checkpoint_seq: 0n,
    checkpoint_hash: ZERO_HASH_32,
    witness_timestamp: 0n,
    receipt_signature: new Uint8Array(64),
    witness_public_key: ZERO_HASH_32,
    ...overrides,
  };
}

export function createRecord(
  overrides: Partial<Record> = {}
): Record {
  const payload = overrides.payload ?? createActionPayload();
  return {
    record_id: ZERO_UUID,
    agent_id: ZERO_UUID,
    session_id: ZERO_UUID,
    timestamp_ms: 0n,
    sequence: 0n,
    prev_hash: ZERO_HASH_32,
    schema_version: SCHEMA_VERSION,
    record_type: PAYLOAD_TYPE_MAP[payload.kind],
    payload,
    ...overrides,
  };
}

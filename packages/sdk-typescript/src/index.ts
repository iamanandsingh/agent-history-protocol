/**
 * Agent History Protocol — TypeScript SDK
 *
 * Cross-SDK interoperable implementation that produces byte-for-byte
 * identical canonical serialization as the Python SDK.
 */

// Types and enums
export {
  RecordType,
  ResultStatus,
  Protocol,
  ActionType,
  AuthorizationType,
  AuthorizerType,
  AuthorizationDecision,
  GapReason,
  ChainLevel,
  FsyncMode,
  RecoveryMethod,
  SCHEMA_VERSION,
  ZERO_HASH_32,
  ZERO_HASH_16,
  ZERO_UUID,
  PAYLOAD_TYPE_MAP,
} from "./types";

export type {
  Record,
  Payload,
  ActionPayload,
  GapPayload,
  CheckpointPayload,
  BootPayload,
  RecoveryPayload,
  KeyPayload,
  WitnessPayload,
  Authorization,
  AuthorizationEntry,
} from "./types";

// Factory helpers
export {
  createRecord,
  createActionPayload,
  createGapPayload,
  createCheckpointPayload,
  createBootPayload,
  createRecoveryPayload,
  createKeyPayload,
  createWitnessPayload,
} from "./types";

// Canonical serialization
export {
  canonicalBytes,
  parseEnvelope,
  parseActionPayload,
  parseGapPayload,
  readString,
} from "./canonical";

export type { ParsedEnvelope } from "./canonical";

// UUID v7
export { uuid7, uuid7ToStr, strToUuid7 } from "./uuid7";

// Chain file I/O
export { ChainWriter, ChainReader, createChainFile } from "./chain";

// Verification
export { verifyChain, verifyChainFromBytes } from "./verify";

export type { VerifyResult } from "./verify";

// Validation
export { MAX_RECORD_SIZE, validateRecord } from "./validation";

export type { ValidationResult, ValidationError } from "./validation";

// Evidence store
export { EvidenceStore } from "./evidence";

// PII filters
export { Filter, FilterPipeline, PRESETS } from "./filters";

export type { FilterDefinition } from "./filters";

// Ed25519 signing
export {
  generateKeypair,
  sign,
  verifySignature,
  computeMerkleRoot,
} from "./signing";

export type { KeyPair } from "./signing";

// Configuration
export {
  loadConfig,
  validateConfig,
  defaultConfig,
} from "./config";

export type {
  AHPConfig,
  FilterConfig,
  WitnessConfig,
} from "./config";

// Crash recovery
export {
  scanChain,
  truncateChain,
  recoverChain,
} from "./recovery";

export type { RecoveryResult } from "./recovery";

// Recorder (main SDK entry point)
export { AHPRecorder } from "./recorder";

export type {
  AHPRecorderOptions,
  RecordActionOptions,
} from "./recorder";

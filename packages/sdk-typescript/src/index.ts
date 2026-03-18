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

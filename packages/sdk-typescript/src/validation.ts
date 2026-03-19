/**
 * Record validation — ensures records conform to AHP constraints
 * before writing to the chain.
 */

import {
  Record,
  RecordType,
  Protocol,
  ActionType,
  ResultStatus,
  AuthorizationType,
  AuthorizerType,
  AuthorizationDecision,
  GapReason,
  ChainLevel,
  FsyncMode,
  RecoveryMethod,
} from "./types";
import { canonicalBytes } from "./canonical";

/** Maximum serialized record size in bytes (1 MB). */
export const MAX_RECORD_SIZE = 1_048_576;

/** Maximum lengths for string fields. */
const MAX_TOOL_NAME_LENGTH = 1024;
const MAX_TARGET_ENTITY_LENGTH = 4096;
const MAX_DETAIL_LENGTH = 4096;
const MAX_AUTHORIZER_ID_LENGTH = 256;

/** All valid values for each enum, used for membership checks. */
const VALID_RECORD_TYPES = new Set<number>(
  Object.values(RecordType).filter((v) => typeof v === "number") as number[]
);
const VALID_PROTOCOLS = new Set<number>(
  Object.values(Protocol).filter((v) => typeof v === "number") as number[]
);
const VALID_ACTION_TYPES = new Set<number>(
  Object.values(ActionType).filter((v) => typeof v === "number") as number[]
);
const VALID_RESULT_STATUSES = new Set<number>(
  Object.values(ResultStatus).filter((v) => typeof v === "number") as number[]
);
const VALID_AUTHORIZATION_TYPES = new Set<number>(
  Object.values(AuthorizationType).filter((v) => typeof v === "number") as number[]
);
const VALID_AUTHORIZER_TYPES = new Set<number>(
  Object.values(AuthorizerType).filter((v) => typeof v === "number") as number[]
);
const VALID_AUTHORIZATION_DECISIONS = new Set<number>(
  Object.values(AuthorizationDecision).filter((v) => typeof v === "number") as number[]
);
const VALID_GAP_REASONS = new Set<number>(
  Object.values(GapReason).filter((v) => typeof v === "number") as number[]
);
const VALID_CHAIN_LEVELS = new Set<number>(
  Object.values(ChainLevel).filter((v) => typeof v === "number") as number[]
);
const VALID_FSYNC_MODES = new Set<number>(
  Object.values(FsyncMode).filter((v) => typeof v === "number") as number[]
);
const VALID_RECOVERY_METHODS = new Set<number>(
  Object.values(RecoveryMethod).filter((v) => typeof v === "number") as number[]
);

export interface ValidationError {
  field: string;
  message: string;
}

export interface ValidationResult {
  valid: boolean;
  errors: ValidationError[];
}

function err(field: string, message: string): ValidationError {
  return { field, message };
}

function checkStringLength(
  value: string,
  fieldName: string,
  maxLength: number,
  errors: ValidationError[]
): void {
  if (new TextEncoder().encode(value).length > maxLength) {
    errors.push(
      err(fieldName, `exceeds max length of ${maxLength} bytes`)
    );
  }
}

/**
 * Validate a Record against AHP constraints.
 *
 * Checks:
 * - Enum fields contain valid values
 * - String fields do not exceed maximum byte lengths
 * - Total serialized size does not exceed MAX_RECORD_SIZE
 */
export function validateRecord(record: Record): ValidationResult {
  const errors: ValidationError[] = [];

  // Envelope enum
  if (!VALID_RECORD_TYPES.has(record.record_type)) {
    errors.push(err("record_type", `invalid value: ${record.record_type}`));
  }

  // Payload-specific validation
  const p = record.payload;
  switch (p.kind) {
    case "action": {
      if (!VALID_RESULT_STATUSES.has(p.result_status)) {
        errors.push(err("result_status", `invalid value: ${p.result_status}`));
      }
      if (!VALID_PROTOCOLS.has(p.protocol)) {
        errors.push(err("protocol", `invalid value: ${p.protocol}`));
      }
      if (!VALID_ACTION_TYPES.has(p.action_type)) {
        errors.push(err("action_type", `invalid value: ${p.action_type}`));
      }
      checkStringLength(p.tool_name, "tool_name", MAX_TOOL_NAME_LENGTH, errors);
      checkStringLength(p.target_entity, "target_entity", MAX_TARGET_ENTITY_LENGTH, errors);
      checkStringLength(p.evidence_uri, "evidence_uri", MAX_TARGET_ENTITY_LENGTH, errors);

      // Authorization
      if (!VALID_AUTHORIZATION_TYPES.has(p.authorization.type)) {
        errors.push(err("authorization.type", `invalid value: ${p.authorization.type}`));
      }
      for (let i = 0; i < p.authorization.entries.length; i++) {
        const entry = p.authorization.entries[i];
        if (!VALID_AUTHORIZER_TYPES.has(entry.authorizer_type)) {
          errors.push(
            err(`authorization.entries[${i}].authorizer_type`, `invalid value: ${entry.authorizer_type}`)
          );
        }
        if (!VALID_AUTHORIZATION_DECISIONS.has(entry.decision)) {
          errors.push(
            err(`authorization.entries[${i}].decision`, `invalid value: ${entry.decision}`)
          );
        }
        checkStringLength(
          entry.authorizer_id,
          `authorization.entries[${i}].authorizer_id`,
          MAX_AUTHORIZER_ID_LENGTH,
          errors
        );
      }
      break;
    }
    case "gap": {
      if (!VALID_GAP_REASONS.has(p.reason)) {
        errors.push(err("reason", `invalid value: ${p.reason}`));
      }
      checkStringLength(p.detail, "detail", MAX_DETAIL_LENGTH, errors);
      break;
    }
    case "boot": {
      if (!VALID_CHAIN_LEVELS.has(p.chain_level)) {
        errors.push(err("chain_level", `invalid value: ${p.chain_level}`));
      }
      if (!VALID_FSYNC_MODES.has(p.fsync_mode)) {
        errors.push(err("fsync_mode", `invalid value: ${p.fsync_mode}`));
      }
      break;
    }
    case "recovery": {
      if (!VALID_RECOVERY_METHODS.has(p.recovery_method)) {
        errors.push(err("recovery_method", `invalid value: ${p.recovery_method}`));
      }
      checkStringLength(p.detail, "detail", MAX_DETAIL_LENGTH, errors);
      break;
    }
    // checkpoint, key, witness — no additional string/enum checks needed beyond record_type
  }

  // Check total serialized size
  if (errors.length === 0) {
    try {
      const serialized = canonicalBytes(record);
      if (serialized.length > MAX_RECORD_SIZE) {
        errors.push(
          err("_serialized", `serialized size ${serialized.length} exceeds MAX_RECORD_SIZE (${MAX_RECORD_SIZE})`)
        );
      }
    } catch (e) {
      errors.push(err("_serialized", `serialization failed: ${e}`));
    }
  }

  return { valid: errors.length === 0, errors };
}

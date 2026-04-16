/**
 * Canonical serialization — deterministic byte representation for hashing.
 *
 * Implements Section 4 of the AHP specification. Every field is serialized in
 * strictly ascending tag order with fixed-width little-endian integers, length-
 * prefixed UTF-8 strings, and raw UUID bytes. This produces identical output
 * across all implementations for the same logical record.
 *
 * MUST produce BYTE-FOR-BYTE identical output as the Python SDK.
 */

import {
  RecordType,
  Record,
  ActionPayload,
  GapPayload,
  CheckpointPayload,
  BootPayload,
  RecoveryPayload,
  KeyPayload,
  WitnessPayload,
  Payload,
} from "./types";

// Shared TextEncoder instance
const textEncoder = new TextEncoder();

/**
 * Growable byte buffer that writes little-endian primitives and raw bytes.
 */
class BufferWriter {
  private chunks: Uint8Array[] = [];
  private totalLength = 0;

  /** Append raw bytes. */
  writeBytes(data: Uint8Array): void {
    this.chunks.push(data);
    this.totalLength += data.length;
  }

  /** Write a fixed-width 4-byte little-endian uint32. */
  writeUint32(value: number): void {
    const buf = new ArrayBuffer(4);
    const view = new DataView(buf);
    view.setUint32(0, value, true); // true = little-endian
    this.chunks.push(new Uint8Array(buf));
    this.totalLength += 4;
  }

  /** Write a fixed-width 8-byte little-endian uint64 using BigInt. */
  writeUint64(value: bigint): void {
    const buf = new ArrayBuffer(8);
    const view = new DataView(buf);
    view.setBigUint64(0, value, true); // true = little-endian
    this.chunks.push(new Uint8Array(buf));
    this.totalLength += 8;
  }

  /** Write a length-prefixed UTF-8 string (uint32 length prefix + bytes). */
  writeString(s: string): void {
    const encoded = textEncoder.encode(s);
    if (encoded.length > 0xFFFFFFFF) {
      throw new Error(`String too long for uint32 length prefix: ${encoded.length} bytes`);
    }
    this.writeUint32(encoded.length);
    this.writeBytes(encoded);
  }

  /** Write a boolean as a single byte: 0x00 = false, 0x01 = true. */
  writeBool(value: boolean): void {
    this.chunks.push(new Uint8Array([value ? 0x01 : 0x00]));
    this.totalLength += 1;
  }

  /** Concatenate all chunks into a single Uint8Array. */
  finish(): Uint8Array {
    const result = new Uint8Array(this.totalLength);
    let offset = 0;
    for (const chunk of this.chunks) {
      result.set(chunk, offset);
      offset += chunk.length;
    }
    return result;
  }
}

/**
 * Serialize a record to canonical bytes for hashing and storage.
 *
 * The output is deterministic and MUST match the Python SDK byte-for-byte.
 */
export function canonicalBytes(record: Record): Uint8Array {
  const buf = new BufferWriter();

  // --- Envelope (ascending tag order) ---
  buf.writeBytes(record.record_id);               // tag 1: 16 bytes UUID
  buf.writeBytes(record.agent_id);                 // tag 2: 16 bytes UUID
  buf.writeBytes(record.session_id);               // tag 3: 16 bytes UUID
  buf.writeUint64(record.timestamp_ms);            // tag 4: 8 bytes
  buf.writeUint64(record.sequence);                // tag 5: 8 bytes
  buf.writeBytes(record.prev_hash);                // tag 6: 32 bytes
  buf.writeUint32(record.schema_version);          // tag 7: 4 bytes
  buf.writeUint32(record.record_type);             // tag 8: 4 bytes enum

  // --- Payload type discriminator ---
  buf.writeUint32(record.record_type);             // payload type tag

  // --- Payload fields (ascending tag order per type) ---
  const p = record.payload;
  switch (p.kind) {
    case "action":
      serializeAction(buf, p);
      break;
    case "gap":
      serializeGap(buf, p);
      break;
    case "checkpoint":
      serializeCheckpoint(buf, p);
      break;
    case "boot":
      serializeBoot(buf, p);
      break;
    case "recovery":
      serializeRecovery(buf, p);
      break;
    case "key":
      serializeKey(buf, p);
      break;
    case "witness":
      serializeWitness(buf, p);
      break;
    default:
      throw new Error(`Unknown payload kind: ${(p as Payload).kind}`);
  }

  return buf.finish();
}

function serializeAction(buf: BufferWriter, p: ActionPayload): void {
  buf.writeBytes(p.parent_action_id);              // tag 1: 16 bytes UUID
  buf.writeString(p.tool_name);                    // tag 2
  buf.writeBytes(p.parameters_hash);               // tag 3: 16 bytes
  buf.writeBytes(p.result_hash);                   // tag 4: 16 bytes
  buf.writeUint32(p.result_status);                // tag 5: enum
  buf.writeUint32(p.response_time_ms);             // tag 6
  buf.writeUint32(p.protocol);                     // tag 7: enum
  buf.writeUint32(p.action_type);                  // tag 8: enum
  buf.writeString(p.target_entity);                // tag 9
  buf.writeString(p.evidence_uri);                 // tag 10
  buf.writeBool(p.redacted);                       // tag 11
  buf.writeString(p.model_id);                     // tag 12
  buf.writeUint32(p.input_token_count);            // tag 13
  buf.writeUint32(p.output_token_count);           // tag 14
  buf.writeUint32(p.cache_read_tokens);            // tag 15
  buf.writeUint32(p.cache_creation_tokens);        // tag 16
  buf.writeUint32(p.reasoning_tokens);             // tag 17
  buf.writeUint64(BigInt(p.cost_nano_usd));        // tag 18
  buf.writeString(p.provider);                     // tag 19
  // tag 20: Authorization (nested, inline)
  buf.writeUint32(p.authorization.type);           // tag 20.1: enum
  buf.writeUint32(p.authorization.entries.length); // tag 20.2: count
  for (const entry of p.authorization.entries) {
    buf.writeUint32(entry.authorizer_type);         // tag 20.2.1: enum
    buf.writeString(entry.authorizer_id);           // tag 20.2.2
    buf.writeBytes(entry.authorizer_agent_id);      // tag 20.2.3: 16 bytes UUID
    buf.writeUint64(entry.authorizer_seq);          // tag 20.2.4
    buf.writeUint32(entry.decision);                // tag 20.2.5: enum
    buf.writeString(entry.condition);               // tag 20.2.6
    buf.writeUint64(entry.timestamp_ms);            // tag 20.2.7
  }
}

function serializeGap(buf: BufferWriter, p: GapPayload): void {
  buf.writeUint64(p.first_lost_sequence);          // tag 1
  buf.writeUint64(p.last_lost_sequence);           // tag 2
  buf.writeUint64(p.count);                        // tag 3
  buf.writeUint32(p.reason);                       // tag 4: enum
  buf.writeString(p.detail);                       // tag 5
}

function serializeCheckpoint(buf: BufferWriter, p: CheckpointPayload): void {
  buf.writeUint64(p.record_count);                 // tag 1
  buf.writeUint64(p.gap_count);                    // tag 2
  buf.writeBytes(p.chain_hash);                    // tag 3: 32 bytes
  buf.writeBytes(p.merkle_root);                   // tag 4: 32 bytes
  buf.writeBytes(p.signature);                     // tag 5: 64 bytes
  buf.writeBytes(p.signing_key_id);                // tag 6: 32 bytes
  // tag 7: EvidenceStatus (nested, inline)
  buf.writeUint64(p.evidence_available);           // tag 7.1
  buf.writeUint64(p.evidence_exported);            // tag 7.2
  buf.writeUint64(p.evidence_expired);             // tag 7.3
  buf.writeUint64(p.evidence_missing);             // tag 7.4
}

function serializeBoot(buf: BufferWriter, p: BootPayload): void {
  buf.writeString(p.sdk_name);                     // tag 1
  buf.writeString(p.sdk_version);                  // tag 2
  // tag 3: repeated string (interceptors)
  buf.writeUint32(p.interceptors.length);
  for (const s of p.interceptors) {
    buf.writeString(s);
  }
  buf.writeString(p.agent_framework);              // tag 4
  buf.writeString(p.agent_name);                   // tag 5
  buf.writeString(p.runtime);                      // tag 6
  buf.writeUint32(p.chain_level);                  // tag 7: enum
  buf.writeUint32(p.fsync_mode);                   // tag 8: enum
  buf.writeString(p.clock_source);                 // tag 9
  buf.writeBool(p.inference_recording);            // tag 10
  buf.writeBool(p.inference_evidence);             // tag 11
  buf.writeBool(p.evidence_recording);             // tag 12
  buf.writeBytes(p.filter_config_hash);            // tag 13: 32 bytes
  buf.writeString(p.matched_agent_rule);           // tag 14
  buf.writeString(p.config_source);                // tag 15
  buf.writeBool(p.authorization_recording);        // tag 16
}

function serializeRecovery(buf: BufferWriter, p: RecoveryPayload): void {
  buf.writeUint64(p.records_verified);             // tag 1
  buf.writeUint64(p.records_truncated);            // tag 2
  buf.writeUint64(p.last_valid_seq);               // tag 3
  buf.writeUint32(p.recovery_method);              // tag 4: enum
  buf.writeString(p.detail);                       // tag 5
}

function serializeKey(buf: BufferWriter, p: KeyPayload): void {
  buf.writeBytes(p.public_key);                    // tag 1: 32 bytes
  buf.writeBytes(p.key_id);                        // tag 2: 32 bytes
  buf.writeUint64(p.expires_at);                   // tag 3
  buf.writeBytes(p.supersedes_key_id);             // tag 4: 32 bytes
}

function serializeWitness(buf: BufferWriter, p: WitnessPayload): void {
  buf.writeString(p.witness_id);                   // tag 1
  buf.writeUint64(p.checkpoint_seq);               // tag 2
  buf.writeBytes(p.checkpoint_hash);               // tag 3: 32 bytes
  buf.writeUint64(p.witness_timestamp);            // tag 4
  buf.writeBytes(p.receipt_signature);             // tag 5: 64 bytes
  buf.writeBytes(p.witness_public_key);            // tag 6: 32 bytes
}

// --- Envelope parsing (for chain reader / verifier) ---

export interface ParsedEnvelope {
  record_id: Uint8Array;
  agent_id: Uint8Array;
  session_id: Uint8Array;
  timestamp_ms: bigint;
  sequence: bigint;
  prev_hash: Uint8Array;
  schema_version: number;
  record_type: RecordType;
  payload_offset: number;
  payload_bytes: Uint8Array;
  stored_bytes: Uint8Array;
}

/**
 * Parse the common envelope from canonical bytes.
 */
export function parseEnvelope(storedBytes: Uint8Array): ParsedEnvelope {
  if (storedBytes.length < 108) {
    throw new Error("Record too short for envelope");
  }

  const view = new DataView(
    storedBytes.buffer,
    storedBytes.byteOffset,
    storedBytes.byteLength
  );
  let offset = 0;

  const record_id = storedBytes.slice(offset, offset + 16);
  offset += 16;
  const agent_id = storedBytes.slice(offset, offset + 16);
  offset += 16;
  const session_id = storedBytes.slice(offset, offset + 16);
  offset += 16;
  const timestamp_ms = view.getBigUint64(offset, true);
  offset += 8;
  const sequence = view.getBigUint64(offset, true);
  offset += 8;
  const prev_hash = storedBytes.slice(offset, offset + 32);
  offset += 32;
  const schema_version = view.getUint32(offset, true);
  offset += 4;
  const record_type = view.getUint32(offset, true) as RecordType;
  offset += 4;

  // Skip payload type discriminator (same as record_type)
  offset += 4;

  return {
    record_id,
    agent_id,
    session_id,
    timestamp_ms,
    sequence,
    prev_hash,
    schema_version,
    record_type,
    payload_offset: offset,
    payload_bytes: storedBytes.slice(offset),
    stored_bytes: storedBytes,
  };
}

/**
 * Parse a length-prefixed UTF-8 string from payload bytes at the given offset.
 * Returns [string, newOffset].
 */
export function readString(
  data: Uint8Array,
  offset: number
): [string, number] {
  if (offset + 4 > data.length) {
    throw new Error(`String length prefix overflows buffer at offset ${offset}`);
  }
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const length = view.getUint32(offset, true);
  offset += 4;
  if (offset + length > data.length) {
    throw new Error(`String data overflows buffer: need ${length} bytes at offset ${offset}, have ${data.length - offset}`);
  }
  const strBytes = data.slice(offset, offset + length);
  const s = new TextDecoder().decode(strBytes);
  offset += length;
  return [s, offset];
}

/**
 * Parse an ActionPayload from canonical bytes after the envelope.
 */
export function parseActionPayload(payloadBytes: Uint8Array): {
  parent_action_id: Uint8Array;
  tool_name: string;
  parameters_hash: Uint8Array;
  result_hash: Uint8Array;
  result_status: number;
  response_time_ms: number;
  protocol: number;
  action_type: number;
  target_entity: string;
  evidence_uri: string;
  redacted: boolean;
  model_id: string;
  input_token_count: number;
  output_token_count: number;
  cache_read_tokens: number;
  cache_creation_tokens: number;
  reasoning_tokens: number;
  cost_nano_usd: number;
  provider: string;
  authorization: {
    type: number;
    entries: Array<{
      authorizer_type: number;
      authorizer_id: string;
      authorizer_agent_id: Uint8Array;
      authorizer_seq: bigint;
      decision: number;
      condition: string;
      timestamp_ms: bigint;
    }>;
  };
} {
  const view = new DataView(
    payloadBytes.buffer,
    payloadBytes.byteOffset,
    payloadBytes.byteLength
  );
  let offset = 0;

  const parent_action_id = payloadBytes.slice(offset, offset + 16);
  offset += 16;
  const [tool_name, off2] = readString(payloadBytes, offset);
  offset = off2;
  const parameters_hash = payloadBytes.slice(offset, offset + 16);
  offset += 16;
  const result_hash = payloadBytes.slice(offset, offset + 16);
  offset += 16;
  const result_status = view.getUint32(offset, true);
  offset += 4;
  const response_time_ms = view.getUint32(offset, true);
  offset += 4;
  const protocol = view.getUint32(offset, true);
  offset += 4;
  const action_type = view.getUint32(offset, true);
  offset += 4;
  const [target_entity, off3] = readString(payloadBytes, offset);
  offset = off3;
  const [evidence_uri, off4] = readString(payloadBytes, offset);
  offset = off4;
  const redacted = payloadBytes[offset] === 0x01;
  offset += 1;
  const [model_id, off5] = readString(payloadBytes, offset);
  offset = off5;
  const input_token_count = view.getUint32(offset, true);
  offset += 4;
  const output_token_count = view.getUint32(offset, true);
  offset += 4;
  const cache_read_tokens = view.getUint32(offset, true);
  offset += 4;
  const cache_creation_tokens = view.getUint32(offset, true);
  offset += 4;
  const reasoning_tokens = view.getUint32(offset, true);
  offset += 4;
  const cost_nano_usd = Number(view.getBigUint64(offset, true));
  offset += 8;
  const [provider, off5b] = readString(payloadBytes, offset);
  offset = off5b;

  // Authorization (nested)
  const auth_type = view.getUint32(offset, true);
  offset += 4;
  const entry_count = view.getUint32(offset, true);
  offset += 4;

  const entries: Array<{
    authorizer_type: number;
    authorizer_id: string;
    authorizer_agent_id: Uint8Array;
    authorizer_seq: bigint;
    decision: number;
    condition: string;
    timestamp_ms: bigint;
  }> = [];

  for (let i = 0; i < entry_count; i++) {
    const authorizer_type = view.getUint32(offset, true);
    offset += 4;
    const [authorizer_id, off6] = readString(payloadBytes, offset);
    offset = off6;
    const authorizer_agent_id = payloadBytes.slice(offset, offset + 16);
    offset += 16;
    const authorizer_seq = view.getBigUint64(offset, true);
    offset += 8;
    const decision = view.getUint32(offset, true);
    offset += 4;
    const [condition, off7] = readString(payloadBytes, offset);
    offset = off7;
    const auth_timestamp = view.getBigUint64(offset, true);
    offset += 8;
    entries.push({
      authorizer_type,
      authorizer_id,
      authorizer_agent_id,
      authorizer_seq,
      decision,
      condition,
      timestamp_ms: auth_timestamp,
    });
  }

  return {
    parent_action_id,
    tool_name,
    parameters_hash,
    result_hash,
    result_status,
    response_time_ms,
    protocol,
    action_type,
    target_entity,
    evidence_uri,
    redacted,
    model_id,
    input_token_count,
    output_token_count,
    cache_read_tokens,
    cache_creation_tokens,
    reasoning_tokens,
    cost_nano_usd,
    provider,
    authorization: { type: auth_type, entries },
  };
}

/**
 * Parse a GapPayload from canonical bytes after the envelope.
 */
export function parseGapPayload(payloadBytes: Uint8Array): {
  first_lost_sequence: bigint;
  last_lost_sequence: bigint;
  count: bigint;
  reason: number;
  detail: string;
} {
  const view = new DataView(
    payloadBytes.buffer,
    payloadBytes.byteOffset,
    payloadBytes.byteLength
  );
  let offset = 0;

  const first_lost_sequence = view.getBigUint64(offset, true);
  offset += 8;
  const last_lost_sequence = view.getBigUint64(offset, true);
  offset += 8;
  const count = view.getBigUint64(offset, true);
  offset += 8;
  const reason = view.getUint32(offset, true);
  offset += 4;
  const [detail] = readString(payloadBytes, offset);

  return { first_lost_sequence, last_lost_sequence, count, reason, detail };
}

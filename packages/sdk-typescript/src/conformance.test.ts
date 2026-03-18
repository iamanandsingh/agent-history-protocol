/**
 * Conformance test — verifies the TypeScript SDK produces byte-for-byte
 * identical canonical serialization as the Python SDK.
 *
 * The test vector uses fixed inputs and the SHA-256 hash must match exactly.
 */

import { createHash } from "crypto";
import { strict as assert } from "assert";
import { test, describe } from "node:test";

import {
  RecordType,
  ResultStatus,
  Protocol,
  ActionType,
  AuthorizationType,
  SCHEMA_VERSION,
  ZERO_HASH_32,
  ZERO_UUID,
  Record,
  createActionPayload,
} from "./types";
import { canonicalBytes, parseEnvelope, parseActionPayload } from "./canonical";

// --- Helper to create a filled Uint8Array ---
function filledBytes(byte: number, length: number): Uint8Array {
  const arr = new Uint8Array(length);
  arr.fill(byte);
  return arr;
}

describe("Conformance: canonical bytes match Python SDK", () => {
  test("Action record test vector produces expected SHA-256", () => {
    // Build the exact test vector from the spec
    const record: Record = {
      record_id: filledBytes(0x01, 16),
      agent_id: filledBytes(0x02, 16),
      session_id: filledBytes(0x03, 16),
      timestamp_ms: 1710000000000n,
      sequence: 1n,
      prev_hash: new Uint8Array(32), // zeros
      schema_version: SCHEMA_VERSION,
      record_type: RecordType.ACTION,
      payload: createActionPayload({
        parent_action_id: new Uint8Array(16), // zeros
        tool_name: "read_file",
        parameters_hash: filledBytes(0xaa, 16),
        result_hash: filledBytes(0xbb, 16),
        result_status: ResultStatus.SUCCESS,
        response_time_ms: 42,
        protocol: Protocol.MCP,
        action_type: ActionType.TOOL_CALL,
        target_entity: "",
        evidence_uri: "",
        redacted: false,
        model_id: "",
        input_token_count: 0,
        output_token_count: 0,
        authorization: {
          type: AuthorizationType.AUTH_NONE,
          entries: [],
        },
      }),
    };

    // Serialize
    const cb = canonicalBytes(record);

    // SHA-256
    const hash = createHash("sha256").update(cb).digest("hex");

    // Expected hash from Python SDK
    const expectedHash =
      "9cdbb99f78a5636458dd7939a5e71a867f9bf5d088bdec415c9cbd520f89ab66";

    console.log(`Canonical bytes length: ${cb.length}`);
    console.log(`SHA-256: ${hash}`);
    console.log(`Expected: ${expectedHash}`);
    console.log(`Match: ${hash === expectedHash}`);

    assert.equal(hash, expectedHash, "SHA-256 hash must match Python test vector");
    assert.equal(cb.length, 214, "Canonical bytes length must be 214");
  });

  test("Canonical bytes hex matches Python output exactly", () => {
    const record: Record = {
      record_id: filledBytes(0x01, 16),
      agent_id: filledBytes(0x02, 16),
      session_id: filledBytes(0x03, 16),
      timestamp_ms: 1710000000000n,
      sequence: 1n,
      prev_hash: new Uint8Array(32),
      schema_version: SCHEMA_VERSION,
      record_type: RecordType.ACTION,
      payload: createActionPayload({
        parent_action_id: new Uint8Array(16),
        tool_name: "read_file",
        parameters_hash: filledBytes(0xaa, 16),
        result_hash: filledBytes(0xbb, 16),
        result_status: ResultStatus.SUCCESS,
        response_time_ms: 42,
        protocol: Protocol.MCP,
        action_type: ActionType.TOOL_CALL,
        target_entity: "",
        evidence_uri: "",
        redacted: false,
        model_id: "",
        input_token_count: 0,
        output_token_count: 0,
        authorization: {
          type: AuthorizationType.AUTH_NONE,
          entries: [],
        },
      }),
    };

    const cb = canonicalBytes(record);
    const hex = Buffer.from(cb).toString("hex");

    // Expected hex from Python canonical_bytes output
    const expectedHex =
      "010101010101010101010101010101010202020202020202020202020202020203030303030303030303030303030303" +
      "004cf1238e010000" + // timestamp_ms = 1710000000000 LE
      "0100000000000000" + // sequence = 1 LE
      "0000000000000000000000000000000000000000000000000000000000000000" + // prev_hash
      "01000000" + // schema_version = 1
      "01000000" + // record_type = ACTION (1)
      "01000000" + // payload type discriminator = ACTION (1)
      "00000000000000000000000000000000" + // parent_action_id (zeros)
      "09000000" + // tool_name length = 9
      "726561645f66696c65" + // "read_file"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" + // parameters_hash 16 bytes = 32 hex
      "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" + // result_hash 16 bytes = 32 hex
      "01000000" + // result_status = SUCCESS (1)
      "2a000000" + // response_time_ms = 42
      "01000000" + // protocol = MCP (1)
      "01000000" + // action_type = TOOL_CALL (1)
      "00000000" + // target_entity (empty string, length=0)
      "00000000" + // evidence_uri (empty string, length=0)
      "00" + // redacted = false
      "00000000" + // model_id (empty string, length=0)
      "00000000" + // input_token_count = 0
      "00000000" + // output_token_count = 0
      "01000000" + // authorization.type = AUTH_NONE (1)
      "00000000"; // authorization.entries count = 0

    assert.equal(hex, expectedHex, "Hex bytes must match Python output exactly");
  });

  test("Envelope round-trip parse", () => {
    const record: Record = {
      record_id: filledBytes(0x01, 16),
      agent_id: filledBytes(0x02, 16),
      session_id: filledBytes(0x03, 16),
      timestamp_ms: 1710000000000n,
      sequence: 1n,
      prev_hash: new Uint8Array(32),
      schema_version: SCHEMA_VERSION,
      record_type: RecordType.ACTION,
      payload: createActionPayload({
        tool_name: "read_file",
        parameters_hash: filledBytes(0xaa, 16),
        result_hash: filledBytes(0xbb, 16),
        response_time_ms: 42,
        protocol: Protocol.MCP,
      }),
    };

    const cb = canonicalBytes(record);
    const env = parseEnvelope(cb);

    assert.deepEqual(env.record_id, filledBytes(0x01, 16));
    assert.deepEqual(env.agent_id, filledBytes(0x02, 16));
    assert.deepEqual(env.session_id, filledBytes(0x03, 16));
    assert.equal(env.timestamp_ms, 1710000000000n);
    assert.equal(env.sequence, 1n);
    assert.equal(env.schema_version, SCHEMA_VERSION);
    assert.equal(env.record_type, RecordType.ACTION);

    // Parse payload
    const action = parseActionPayload(env.payload_bytes);
    assert.equal(action.tool_name, "read_file");
    assert.equal(action.response_time_ms, 42);
    assert.equal(action.protocol, Protocol.MCP);
    assert.equal(action.result_status, ResultStatus.SUCCESS);
    assert.equal(action.authorization.type, AuthorizationType.AUTH_NONE);
    assert.equal(action.authorization.entries.length, 0);
  });

  test("Enum values match Python", () => {
    // RecordType
    assert.equal(RecordType.ACTION, 1);
    assert.equal(RecordType.GAP, 2);
    assert.equal(RecordType.CHECKPOINT, 3);
    assert.equal(RecordType.BOOT, 4);
    assert.equal(RecordType.RECOVERY, 5);
    assert.equal(RecordType.KEY, 6);
    assert.equal(RecordType.WITNESS, 7);

    // ResultStatus
    assert.equal(ResultStatus.SUCCESS, 1);
    assert.equal(ResultStatus.FAILURE, 2);
    assert.equal(ResultStatus.TIMEOUT, 3);
    assert.equal(ResultStatus.ERROR, 4);

    // Protocol
    assert.equal(Protocol.MCP, 1);
    assert.equal(Protocol.HTTP, 2);
    assert.equal(Protocol.GRPC, 3);
    assert.equal(Protocol.A2A, 4);
    assert.equal(Protocol.SHELL, 5);
    assert.equal(Protocol.CUSTOM, 6);

    // ActionType
    assert.equal(ActionType.TOOL_CALL, 1);
    assert.equal(ActionType.INFERENCE, 2);
    assert.equal(ActionType.DELEGATION, 3);
    assert.equal(ActionType.MESSAGE, 4);
    assert.equal(ActionType.CUSTOM, 5);

    // AuthorizationType
    assert.equal(AuthorizationType.AUTH_NONE, 1);
    assert.equal(AuthorizationType.AUTH_HUMAN, 2);
    assert.equal(AuthorizationType.AUTH_AGENT, 3);
    assert.equal(AuthorizationType.AUTH_POLICY, 4);
    assert.equal(AuthorizationType.AUTH_MULTI_PARTY, 5);
  });

  test("Constants are correct", () => {
    assert.equal(SCHEMA_VERSION, 1);
    assert.equal(ZERO_HASH_32.length, 32);
    assert.equal(ZERO_UUID.length, 16);
    assert.ok(ZERO_HASH_32.every((b) => b === 0));
    assert.ok(ZERO_UUID.every((b) => b === 0));
  });
});

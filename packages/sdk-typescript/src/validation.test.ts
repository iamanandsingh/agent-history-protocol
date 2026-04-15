/**
 * Tests for validateRecord — enum membership, string length, size limits.
 */

import { strict as assert } from "assert";
import { test, describe } from "node:test";

import {
  RecordType,
  ResultStatus,
  Protocol,
  ActionType,
  AuthorizationType,
  SCHEMA_VERSION,
  Record,
  createActionPayload,
  createGapPayload,
  GapReason,
} from "./types";
import { validateRecord, MAX_RECORD_SIZE } from "./validation";

function filledBytes(byte: number, length: number): Uint8Array {
  const arr = new Uint8Array(length);
  arr.fill(byte);
  return arr;
}

function makeActionRecord(overrides: Partial<Record> = {}): Record {
  return {
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
    ...overrides,
  };
}

describe("validateRecord — happy path", () => {
  test("valid action record passes", () => {
    const result = validateRecord(makeActionRecord());
    assert.equal(result.valid, true, JSON.stringify(result.errors));
    assert.equal(result.errors.length, 0);
  });

  test("MAX_RECORD_SIZE is 1 MiB", () => {
    assert.equal(MAX_RECORD_SIZE, 1_048_576);
  });
});

describe("validateRecord — enum failures", () => {
  test("invalid record_type produces error", () => {
    const r = makeActionRecord({ record_type: 9999 as unknown as RecordType });
    const result = validateRecord(r);
    assert.equal(result.valid, false);
    assert.ok(result.errors.some((e) => e.field === "record_type"));
  });

  test("invalid protocol on action payload produces error", () => {
    const r = makeActionRecord();
    if (r.payload.kind === "action") {
      (r.payload as { protocol: number }).protocol = 9999;
    }
    const result = validateRecord(r);
    assert.equal(result.valid, false);
    assert.ok(result.errors.some((e) => e.field === "protocol"));
  });

  test("invalid result_status produces error", () => {
    const r = makeActionRecord();
    if (r.payload.kind === "action") {
      (r.payload as { result_status: number }).result_status = 9999;
    }
    const result = validateRecord(r);
    assert.equal(result.valid, false);
    assert.ok(result.errors.some((e) => e.field === "result_status"));
  });
});

describe("validateRecord — string length failures", () => {
  test("tool_name exceeding 1024 bytes produces error", () => {
    const r = makeActionRecord();
    if (r.payload.kind === "action") {
      (r.payload as { tool_name: string }).tool_name = "x".repeat(2000);
    }
    const result = validateRecord(r);
    assert.equal(result.valid, false);
    assert.ok(result.errors.some((e) => e.field === "tool_name"));
  });
});

describe("validateRecord — gap payload", () => {
  test("invalid gap reason produces error", () => {
    const r: Record = {
      ...makeActionRecord(),
      record_type: RecordType.GAP,
      payload: createGapPayload({
        first_lost_sequence: 1n,
        last_lost_sequence: 1n,
        count: 1n,
        reason: 9999 as unknown as GapReason,
        detail: "test",
      }),
    };
    const result = validateRecord(r);
    assert.equal(result.valid, false);
    assert.ok(result.errors.some((e) => e.field === "reason"));
  });
});

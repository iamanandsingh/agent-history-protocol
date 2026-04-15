/**
 * Tests for verifyChainFromBytes — genesis check, hash chain, sequence rules.
 */

import { strict as assert } from "assert";
import { test, describe } from "node:test";
import * as crypto from "crypto";

import {
  RecordType,
  ResultStatus,
  Protocol,
  ActionType,
  AuthorizationType,
  SCHEMA_VERSION,
  Record,
  createActionPayload,
} from "./types";
import { canonicalBytes } from "./canonical";
import { verifyChainFromBytes } from "./verify";

function filledBytes(byte: number, length: number): Uint8Array {
  const arr = new Uint8Array(length);
  arr.fill(byte);
  return arr;
}

function actionPayload() {
  return createActionPayload({
    parent_action_id: new Uint8Array(16),
    tool_name: "tool",
    parameters_hash: filledBytes(0xaa, 16),
    result_hash: filledBytes(0xbb, 16),
    result_status: ResultStatus.SUCCESS,
    response_time_ms: 1,
    protocol: Protocol.MCP,
    action_type: ActionType.TOOL_CALL,
    target_entity: "",
    evidence_uri: "",
    redacted: false,
    model_id: "",
    input_token_count: 0,
    output_token_count: 0,
    authorization: { type: AuthorizationType.AUTH_NONE, entries: [] },
  });
}

function makeRecord(seq: bigint, prevHash: Uint8Array): Record {
  return {
    record_id: filledBytes(Number(seq) & 0xff, 16),
    agent_id: filledBytes(0x02, 16),
    session_id: filledBytes(0x03, 16),
    timestamp_ms: 1710000000000n + seq,
    sequence: seq,
    prev_hash: prevHash,
    schema_version: SCHEMA_VERSION,
    record_type: RecordType.ACTION,
    payload: actionPayload(),
  };
}

function sha256(bytes: Uint8Array): Uint8Array {
  const digest = crypto.createHash("sha256").update(bytes).digest();
  const out = new Uint8Array(32);
  out.set(digest);
  return out;
}

function buildValidChain(n: number): Uint8Array[] {
  const out: Uint8Array[] = [];
  let prevHash: Uint8Array = new Uint8Array(32);
  for (let i = 1; i <= n; i++) {
    const r = makeRecord(BigInt(i), prevHash);
    const stored = Uint8Array.from(canonicalBytes(r));
    out.push(stored);
    prevHash = Uint8Array.from(sha256(stored));
  }
  return out;
}

describe("verifyChainFromBytes — happy path", () => {
  test("empty array is valid", () => {
    const result = verifyChainFromBytes([]);
    assert.equal(result.valid, true);
    assert.equal(result.records_checked, 0);
    assert.equal(result.gaps, 0);
  });

  test("single genesis record verifies", () => {
    const chain = buildValidChain(1);
    const result = verifyChainFromBytes(chain);
    assert.equal(result.valid, true, result.error);
    assert.equal(result.records_checked, 1);
    assert.equal(result.gaps, 0);
  });

  test("multi-record chain verifies", () => {
    const chain = buildValidChain(5);
    const result = verifyChainFromBytes(chain);
    assert.equal(result.valid, true, result.error);
    assert.equal(result.records_checked, 5);
  });
});

describe("verifyChainFromBytes — failures", () => {
  test("genesis with non-zero prev_hash fails", () => {
    const r = makeRecord(1n, filledBytes(0xff, 32));
    const result = verifyChainFromBytes([canonicalBytes(r)]);
    assert.equal(result.valid, false);
    assert.match(result.error || "", /Genesis record prev_hash/);
  });

  test("broken hash chain at second record is detected", () => {
    // Genesis record is correct, but second record's prev_hash is bogus.
    const r1 = makeRecord(1n, new Uint8Array(32));
    const r2 = makeRecord(2n, filledBytes(0xcc, 32));
    const result = verifyChainFromBytes([canonicalBytes(r1), canonicalBytes(r2)]);
    assert.equal(result.valid, false);
    assert.equal(result.broken_at, 2n);
    assert.match(result.error || "", /Hash chain broken/);
    assert.ok(result.expected_hash);
    assert.ok(result.actual_hash);
  });

  test("sequence gap between non-gap records is detected", () => {
    const r1 = makeRecord(1n, new Uint8Array(32));
    const stored1 = canonicalBytes(r1);
    const r3 = makeRecord(3n, sha256(stored1));
    const result = verifyChainFromBytes([stored1, canonicalBytes(r3)]);
    assert.equal(result.valid, false);
    assert.match(result.error || "", /Expected sequence 2/);
  });

  test("tampered first record breaks chain at record 2", () => {
    // Build a valid chain, then mutate a byte in the genesis record so its
    // SHA-256 changes and the prev_hash in record 2 no longer matches.
    const chain = buildValidChain(3);
    const tampered = new Uint8Array(chain[0]);
    tampered[tampered.length - 1] ^= 0x01;
    const result = verifyChainFromBytes([tampered, chain[1], chain[2]]);
    assert.equal(result.valid, false);
    assert.equal(result.broken_at, 2n);
  });
});

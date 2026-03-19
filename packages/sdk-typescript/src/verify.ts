/**
 * Chain verification — Section 5.4 of the AHP specification.
 *
 * Checks:
 * 1. First record's prev_hash == 32 zero bytes
 * 2. Each subsequent record's prev_hash == SHA-256(stored_bytes of previous)
 * 3. Sequence numbers are monotonic with no gaps (except GapRecords)
 * 4. GapRecord constraints (first_lost_sequence, last_lost_sequence, count)
 */

import * as crypto from "crypto";

import { RecordType, ZERO_HASH_32 } from "./types";
import { parseEnvelope, parseGapPayload } from "./canonical";
import { ChainReader } from "./chain";

export interface VerifyResult {
  valid: boolean;
  records_checked: number;
  gaps: number;
  broken_at?: bigint;
  expected_hash?: Uint8Array;
  actual_hash?: Uint8Array;
  error?: string;
}

/**
 * Verify hash chain integrity per Section 5.4.
 * Streams records one at a time from the chain file to avoid loading
 * the entire chain into memory.
 */
export function verifyChain(path: string): VerifyResult {
  const reader = new ChainReader(path);

  let expectedSeq = 1n;
  let gaps = 0;
  let prevStored: Uint8Array | null = null;
  let i = 0;

  for (const stored of reader.iterRecords()) {
    const envelope = parseEnvelope(stored);
    const seq = envelope.sequence;
    const prevHash = envelope.prev_hash;
    const recordType = envelope.record_type;

    // Check hash chain
    if (i === 0) {
      if (!uint8ArrayEquals(prevHash, ZERO_HASH_32)) {
        return {
          valid: false,
          records_checked: i + 1,
          gaps,
          broken_at: seq,
          error: "Genesis record prev_hash is not zero bytes",
        };
      }
    } else {
      const expectedHash = new Uint8Array(
        crypto.createHash("sha256").update(prevStored!).digest()
      );
      if (!uint8ArrayEquals(prevHash, expectedHash)) {
        return {
          valid: false,
          records_checked: i + 1,
          gaps,
          broken_at: seq,
          expected_hash: expectedHash,
          actual_hash: prevHash,
          error:
            `Hash chain broken at record #${seq} (sequence ${seq}). ` +
            `Record #${seq > 1n ? seq - 1n : 0n} may have been modified.`,
        };
      }
    }

    // Check sequence
    if (recordType === RecordType.GAP) {
      if (seq <= expectedSeq) {
        return {
          valid: false,
          records_checked: i + 1,
          gaps,
          broken_at: seq,
          error: `GapRecord sequence ${seq} is not greater than expected ${expectedSeq}`,
        };
      }

      const gapData = parseGapPayload(envelope.payload_bytes);
      const gapFirst = gapData.first_lost_sequence;
      const gapLast = gapData.last_lost_sequence;
      const gapCount = gapData.count;

      if (gapFirst !== expectedSeq) {
        return {
          valid: false,
          records_checked: i + 1,
          gaps,
          broken_at: seq,
          error: `GapRecord first_lost_sequence ${gapFirst} != expected ${expectedSeq}`,
        };
      }
      if (gapLast !== seq - 1n) {
        return {
          valid: false,
          records_checked: i + 1,
          gaps,
          broken_at: seq,
          error: `GapRecord last_lost_sequence ${gapLast} != sequence - 1 (${seq - 1n})`,
        };
      }
      if (gapCount !== gapLast - gapFirst + 1n) {
        return {
          valid: false,
          records_checked: i + 1,
          gaps,
          broken_at: seq,
          error: `GapRecord count ${gapCount} != last - first + 1 (${gapLast - gapFirst + 1n})`,
        };
      }

      gaps += 1;
    } else {
      if (seq !== expectedSeq) {
        return {
          valid: false,
          records_checked: i + 1,
          gaps,
          broken_at: seq,
          error: `Expected sequence ${expectedSeq}, got ${seq}`,
        };
      }
    }

    expectedSeq = seq + 1n;
    prevStored = stored;
    i++;
  }

  return {
    valid: true,
    records_checked: i,
    gaps,
  };
}

/**
 * Verify an array of raw canonical byte records (without reading from file).
 */
export function verifyChainFromBytes(records: Uint8Array[]): VerifyResult {
  if (records.length === 0) {
    return { valid: true, records_checked: 0, gaps: 0 };
  }

  let expectedSeq = 1n;
  let gaps = 0;
  let prevStored: Uint8Array | null = null;

  for (let i = 0; i < records.length; i++) {
    const stored = records[i];
    const envelope = parseEnvelope(stored);
    const seq = envelope.sequence;
    const prevHash = envelope.prev_hash;
    const recordType = envelope.record_type;

    // Check hash chain
    if (i === 0) {
      if (!uint8ArrayEquals(prevHash, ZERO_HASH_32)) {
        return {
          valid: false,
          records_checked: i + 1,
          gaps,
          broken_at: seq,
          error: "Genesis record prev_hash is not zero bytes",
        };
      }
    } else {
      const expectedHash = new Uint8Array(
        crypto.createHash("sha256").update(prevStored!).digest()
      );
      if (!uint8ArrayEquals(prevHash, expectedHash)) {
        return {
          valid: false,
          records_checked: i + 1,
          gaps,
          broken_at: seq,
          expected_hash: expectedHash,
          actual_hash: prevHash,
          error:
            `Hash chain broken at record #${seq} (sequence ${seq}). ` +
            `Record #${seq > 1n ? seq - 1n : 0n} may have been modified.`,
        };
      }
    }

    // Check sequence
    if (recordType === RecordType.GAP) {
      if (seq <= expectedSeq) {
        return {
          valid: false,
          records_checked: i + 1,
          gaps,
          broken_at: seq,
          error: `GapRecord sequence ${seq} is not greater than expected ${expectedSeq}`,
        };
      }

      const gapData = parseGapPayload(envelope.payload_bytes);
      const gapFirst = gapData.first_lost_sequence;
      const gapLast = gapData.last_lost_sequence;
      const gapCount = gapData.count;

      if (gapFirst !== expectedSeq) {
        return {
          valid: false,
          records_checked: i + 1,
          gaps,
          broken_at: seq,
          error: `GapRecord first_lost_sequence ${gapFirst} != expected ${expectedSeq}`,
        };
      }
      if (gapLast !== seq - 1n) {
        return {
          valid: false,
          records_checked: i + 1,
          gaps,
          broken_at: seq,
          error: `GapRecord last_lost_sequence ${gapLast} != sequence - 1 (${seq - 1n})`,
        };
      }
      if (gapCount !== gapLast - gapFirst + 1n) {
        return {
          valid: false,
          records_checked: i + 1,
          gaps,
          broken_at: seq,
          error: `GapRecord count ${gapCount} != last - first + 1 (${gapLast - gapFirst + 1n})`,
        };
      }

      gaps += 1;
    } else {
      if (seq !== expectedSeq) {
        return {
          valid: false,
          records_checked: i + 1,
          gaps,
          broken_at: seq,
          error: `Expected sequence ${expectedSeq}, got ${seq}`,
        };
      }
    }

    expectedSeq = seq + 1n;
    prevStored = stored;
  }

  return {
    valid: true,
    records_checked: records.length,
    gaps,
  };
}

/** Compare two Uint8Arrays for equality. */
function uint8ArrayEquals(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

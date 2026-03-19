/**
 * Chain file writer and reader.
 *
 * Chain file format (Appendix C):
 *   Header: 4B magic "AHP\0" + 4B version + 8B creation timestamp
 *   Records: [4B length][NB canonical_bytes][4B CRC32] repeated
 */

import * as fs from "fs";
import * as crypto from "crypto";

import {
  Record,
  RecordType,
  Payload,
  PAYLOAD_TYPE_MAP,
  ZERO_HASH_32,
  SCHEMA_VERSION,
  GapReason,
  RecoveryMethod,
  createGapPayload,
  createRecoveryPayload,
  createCheckpointPayload,
} from "./types";
import { canonicalBytes, parseEnvelope } from "./canonical";
import { uuid7 } from "./uuid7";

// File format constants
export const MAGIC = Buffer.from("AHP\x00");
const FILE_VERSION = 1;
export const HEADER_SIZE = 16; // 4 + 4 + 8

// Pre-computed CRC32 lookup table (ISO 3309 / ITU-T V.42 polynomial)
const CRC32_TABLE = new Uint32Array(256);
for (let i = 0; i < 256; i++) {
  let c = i;
  for (let j = 0; j < 8; j++) {
    if (c & 1) {
      c = 0xEDB88320 ^ (c >>> 1);
    } else {
      c = c >>> 1;
    }
  }
  CRC32_TABLE[i] = c;
}

/**
 * Compute CRC32 (same as Python zlib.crc32).
 * Node.js zlib does not directly expose crc32, so we use a manual table.
 */
export function crc32(data: Uint8Array): number {
  let crc = 0xFFFFFFFF;
  for (let i = 0; i < data.length; i++) {
    crc = CRC32_TABLE[(crc ^ data[i]) & 0xFF] ^ (crc >>> 8);
  }
  return (crc ^ 0xFFFFFFFF) >>> 0;
}

/**
 * Write a uint32 little-endian to a Buffer.
 */
function uint32LEBuffer(value: number): Buffer {
  const buf = Buffer.alloc(4);
  buf.writeUInt32LE(value, 0);
  return buf;
}

/**
 * Writes records to a chain file with hash chain integrity.
 */
export class ChainWriter {
  readonly path: string;
  readonly agentId: Uint8Array;
  readonly sessionId: Uint8Array;

  private _sequence = 0n;
  private _prevHash: Uint8Array = new Uint8Array(ZERO_HASH_32);
  private _recordCount = 0;
  private _gapCount = 0;
  private _fsyncMode: string;
  private _fsyncBatchSize: number;
  private _writesSinceFsync = 0;
  private _fd: number | null = null;
  private _bytesWritten = 0;

  constructor(
    path: string,
    agentId?: Uint8Array,
    sessionId?: Uint8Array,
    fsyncMode: string = "batch",
    fsyncBatchSize: number = 1000
  ) {
    this.path = path;
    this.agentId = agentId ?? uuid7();
    this.sessionId = sessionId ?? uuid7();
    this._fsyncMode = fsyncMode;
    this._fsyncBatchSize = fsyncBatchSize;

    if (!fs.existsSync(path)) {
      this._writeHeader();
    }

    // Initialize in-memory byte counter and open persistent handle
    this._bytesWritten = fs.statSync(this.path).size;
    this._fd = fs.openSync(this.path, "a");
  }

  private _writeHeader(): void {
    const fd = fs.openSync(this.path, "w");
    const header = Buffer.alloc(HEADER_SIZE);
    MAGIC.copy(header, 0);
    header.writeUInt32LE(FILE_VERSION, 4);
    header.writeBigUInt64LE(BigInt(Date.now()), 8);
    fs.writeSync(fd, header);
    fs.closeSync(fd);
  }

  /**
   * Create a record, compute hash chain, write to file. Returns the record.
   */
  writeRecord(
    payload: Payload,
    sessionId?: Uint8Array,
    timestampMs?: bigint
  ): Record {
    this._sequence += 1n;

    const record: Record = {
      record_id: uuid7(),
      agent_id: this.agentId,
      session_id: sessionId ?? this.sessionId,
      timestamp_ms: timestampMs ?? BigInt(Date.now()),
      sequence: this._sequence,
      prev_hash: new Uint8Array(this._prevHash),
      schema_version: SCHEMA_VERSION,
      record_type: PAYLOAD_TYPE_MAP[payload.kind],
      payload,
    };

    // Serialize to canonical bytes
    const stored = canonicalBytes(record);

    // Save old state for rollback on I/O failure
    const oldPrevHash = this._prevHash;
    const oldSequence = this._sequence;
    const oldRecordCount = this._recordCount;
    const oldGapCount = this._gapCount;

    // Update chain state
    this._prevHash = new Uint8Array(
      crypto.createHash("sha256").update(stored).digest()
    );
    this._recordCount += 1;
    if (record.record_type === RecordType.GAP) {
      this._gapCount += 1;
    }

    // Write to file: [length][canonical_bytes][crc32]
    // Uses persistent file handle and single batched write for performance.
    // NOTE: Concurrent writers to the same file are NOT supported.
    const oldBytesWritten = this._bytesWritten;
    try {
      const lengthBuf = uint32LEBuffer(stored.length);
      const crcInput = Buffer.concat([lengthBuf, stored]);
      const crcValue = crc32(crcInput);
      const crcBuf = uint32LEBuffer(crcValue);

      // Single concatenated write instead of 3 separate writeSync calls
      const frame = Buffer.concat([lengthBuf, stored, crcBuf]);

      // Reopen persistent handle if lost
      if (this._fd === null) {
        this._fd = fs.openSync(this.path, "a");
      }

      fs.writeSync(this._fd, frame);
      this._bytesWritten += frame.length;

      // fsync per spec Section 10.1
      this._writesSinceFsync += 1;
      if (this._fsyncMode === "every") {
        fs.fsyncSync(this._fd);
        this._writesSinceFsync = 0;
      } else if (this._fsyncMode === "batch" && this._writesSinceFsync >= this._fsyncBatchSize) {
        fs.fsyncSync(this._fd);
        this._writesSinceFsync = 0;
      }
    } catch (e) {
      // Rollback in-memory state so the chain stays consistent
      this._prevHash = oldPrevHash;
      this._sequence = oldSequence;
      this._recordCount = oldRecordCount;
      this._gapCount = oldGapCount;
      this._bytesWritten = oldBytesWritten;
      throw e;
    }

    return record;
  }

  /**
   * Write a GapRecord documenting lost records.
   * The GapRecord's sequence = last_lost + 1 (per spec Section 3.3).
   */
  writeGap(
    firstLost: bigint,
    lastLost: bigint,
    reason: GapReason,
    detail: string = ""
  ): Record {
    const count = lastLost - firstLost + 1n;
    this._sequence = lastLost; // will be incremented to lastLost + 1 by writeRecord
    const payload = createGapPayload({
      first_lost_sequence: firstLost,
      last_lost_sequence: lastLost,
      count,
      reason,
      detail,
    });
    return this.writeRecord(payload);
  }

  /**
   * Write a RecoveryRecord after crash recovery.
   */
  writeRecovery(
    recordsVerified: bigint,
    recordsTruncated: bigint,
    lastValidSeq: bigint,
    method: RecoveryMethod = RecoveryMethod.CHAIN_SCAN,
    detail: string = ""
  ): Record {
    const payload = createRecoveryPayload({
      records_verified: recordsVerified,
      records_truncated: recordsTruncated,
      last_valid_seq: lastValidSeq,
      recovery_method: method,
      detail,
    });
    return this.writeRecord(payload);
  }

  /**
   * Write a BatchCheckpoint summarizing current chain state.
   */
  writeCheckpoint(): Record {
    const payload = createCheckpointPayload({
      record_count: BigInt(this._recordCount + 1), // including this checkpoint
      gap_count: BigInt(this._gapCount),
      chain_hash: new Uint8Array(this._prevHash),
    });
    return this.writeRecord(payload);
  }

  get sequence(): bigint {
    return this._sequence;
  }

  get prevHash(): Uint8Array {
    return this._prevHash;
  }

  get recordCount(): number {
    return this._recordCount;
  }

  get gapCount(): number {
    return this._gapCount;
  }

  get bytesWritten(): number {
    return this._bytesWritten;
  }

  close(): void {
    if (this._fd !== null) {
      try { fs.closeSync(this._fd); } catch { /* ignore */ }
      this._fd = null;
    }
  }
}

/**
 * Reads records from a chain file.
 */
export class ChainReader {
  readonly path: string;

  constructor(path: string) {
    this.path = path;
  }

  /**
   * Read all stored_bytes from the chain file. Returns raw canonical byte arrays.
   */
  *iterRecords(): Generator<Uint8Array> {
    if (!fs.existsSync(this.path)) {
      return;
    }

    const fd = fs.openSync(this.path, "r");
    try {
      // Read header
      const header = Buffer.alloc(HEADER_SIZE);
      if (fs.readSync(fd, header, 0, HEADER_SIZE, null) < HEADER_SIZE) {
        return;
      }
      if (!header.slice(0, 4).equals(MAGIC)) {
        return;
      }

      // Read records
      while (true) {
        // Read length
        const lengthBuf = Buffer.alloc(4);
        if (fs.readSync(fd, lengthBuf, 0, 4, null) < 4) {
          break;
        }
        const length = lengthBuf.readUInt32LE(0);

        // Read canonical bytes
        const stored = Buffer.alloc(length);
        if (fs.readSync(fd, stored, 0, length, null) < length) {
          break;
        }

        // Read CRC
        const crcBuf = Buffer.alloc(4);
        if (fs.readSync(fd, crcBuf, 0, 4, null) < 4) {
          break;
        }
        const expectedCrc = crcBuf.readUInt32LE(0);

        // Verify CRC
        const crcInput = Buffer.concat([lengthBuf, stored]);
        const actualCrc = crc32(crcInput);
        if (actualCrc !== expectedCrc) {
          break;
        }

        yield new Uint8Array(stored);
      }
    } finally {
      fs.closeSync(fd);
    }
  }

  /**
   * Read all stored_bytes from the chain file.
   */
  readAll(): Uint8Array[] {
    return Array.from(this.iterRecords());
  }

  /**
   * Read records in a sequence range without loading entire chain.
   */
  readRange(startSeq: bigint, endSeq: bigint): Uint8Array[] {
    const results: Uint8Array[] = [];
    for (const stored of this.iterRecords()) {
      const env = parseEnvelope(stored);
      const seq = env.sequence;
      if (seq >= startSeq && seq <= endSeq) {
        results.push(stored);
      }
      if (seq > endSeq) {
        break;
      }
    }
    return results;
  }

  /**
   * Count records without loading all into memory.
   */
  count(): number {
    let n = 0;
    for (const _ of this.iterRecords()) {
      n++;
    }
    return n;
  }
}

/**
 * Create a new chain file with just the AHP header.
 */
export function createChainFile(path: string): void {
  const header = Buffer.alloc(HEADER_SIZE);
  MAGIC.copy(header, 0);
  header.writeUInt32LE(FILE_VERSION, 4);
  header.writeBigUInt64LE(BigInt(Date.now()), 8);
  fs.writeFileSync(path, header);
}

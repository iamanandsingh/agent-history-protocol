/**
 * Crash recovery — scan chain file, truncate corrupt records, resume.
 *
 * Implements the recovery protocol from spec Section 3.6.
 */

import * as fs from "fs";
import * as crypto from "crypto";

import { ZERO_HASH_32 } from "./types";
import { parseEnvelope } from "./canonical";
import { MAX_RECORD_SIZE } from "./validation";

// Chain file constants (must match chain.ts)
const MAGIC = Buffer.from("AHP\x00");
const HEADER_SIZE = 16;

// Pre-computed CRC32 lookup table (ISO 3309 / ITU-T V.42 polynomial)
const CRC32_TABLE = new Uint32Array(256);
for (let i = 0; i < 256; i++) {
  let c = i;
  for (let j = 0; j < 8; j++) {
    if (c & 1) {
      c = 0xedb88320 ^ (c >>> 1);
    } else {
      c = c >>> 1;
    }
  }
  CRC32_TABLE[i] = c;
}

function crc32(data: Uint8Array): number {
  let crc = 0xffffffff;
  for (let i = 0; i < data.length; i++) {
    crc = CRC32_TABLE[(crc ^ data[i]) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

export interface RecoveryResult {
  recordsVerified: number;
  recordsTruncated: number;
  lastValidSeq: number;
  lastValidOffset: number; // file offset after last valid record
  lastPrevHash: Uint8Array; // prev_hash for next record to continue chain
}

/**
 * Scan a chain file and find the last valid record.
 *
 * Reads sequentially, verifying CRC of each record.
 * Returns info about where the chain is valid up to.
 */
export function scanChain(chainPath: string): RecoveryResult {
  if (!fs.existsSync(chainPath)) {
    return {
      recordsVerified: 0,
      recordsTruncated: 0,
      lastValidSeq: 0,
      lastValidOffset: HEADER_SIZE,
      lastPrevHash: new Uint8Array(ZERO_HASH_32),
    };
  }

  const fd = fs.openSync(chainPath, "r");
  let recordsVerified = 0;
  let lastValidSeq = 0;
  let lastValidOffset = HEADER_SIZE;
  let lastStoredBytes: Buffer | null = null;

  try {
    // Read and verify header
    const header = Buffer.alloc(HEADER_SIZE);
    if (
      fs.readSync(fd, header, 0, HEADER_SIZE, null) < HEADER_SIZE ||
      !header.subarray(0, 4).equals(MAGIC)
    ) {
      return {
        recordsVerified: 0,
        recordsTruncated: 0,
        lastValidSeq: 0,
        lastValidOffset: 0,
        lastPrevHash: new Uint8Array(ZERO_HASH_32),
      };
    }

    let fileOffset = HEADER_SIZE;

    while (true) {
      // Read length
      const lengthBuf = Buffer.alloc(4);
      if (fs.readSync(fd, lengthBuf, 0, 4, null) < 4) break;

      const length = lengthBuf.readUInt32LE(0);
      if (length > MAX_RECORD_SIZE) break; // Corrupt data

      // Read canonical bytes
      const stored = Buffer.alloc(length);
      if (fs.readSync(fd, stored, 0, length, null) < length) break;

      // Read CRC
      const crcBuf = Buffer.alloc(4);
      if (fs.readSync(fd, crcBuf, 0, 4, null) < 4) break;

      const expectedCrc = crcBuf.readUInt32LE(0);
      const crcInput = Buffer.concat([lengthBuf, stored]);
      const actualCrc = crc32(crcInput);
      if (actualCrc !== expectedCrc) break; // Corrupt CRC

      // Record is valid
      recordsVerified += 1;
      fileOffset += 4 + length + 4;
      lastValidOffset = fileOffset;
      lastStoredBytes = stored;

      try {
        const env = parseEnvelope(new Uint8Array(stored));
        lastValidSeq = Number(env.sequence);
      } catch {
        // ignore parse errors — CRC was valid
      }
    }
  } finally {
    fs.closeSync(fd);
  }

  // Compute prev_hash for continuation
  let lastPrevHash: Uint8Array;
  if (lastStoredBytes) {
    lastPrevHash = new Uint8Array(
      crypto.createHash("sha256").update(lastStoredBytes).digest()
    );
  } else {
    lastPrevHash = new Uint8Array(ZERO_HASH_32);
  }

  // Estimate truncated records from corrupt tail
  const fileSize = fs.statSync(chainPath).size;
  let truncated = 0;
  if (fileSize > lastValidOffset) {
    const corruptBytes = fileSize - lastValidOffset;
    if (recordsVerified > 0) {
      const avgRecordFrame =
        (lastValidOffset - HEADER_SIZE) / recordsVerified;
      truncated = Math.max(1, Math.round(corruptBytes / avgRecordFrame));
    } else {
      truncated = 1;
    }
  }

  return {
    recordsVerified,
    recordsTruncated: truncated,
    lastValidSeq,
    lastValidOffset,
    lastPrevHash,
  };
}

/**
 * Truncate chain file to remove corrupt trailing data.
 */
export function truncateChain(chainPath: string, validOffset: number): void {
  const fd = fs.openSync(chainPath, "r+");
  try {
    fs.ftruncateSync(fd, validOffset);
  } finally {
    fs.closeSync(fd);
  }
}

/**
 * Full recovery: scan + truncate corrupt tail.
 *
 * Returns the recovery result. Caller should emit RecoveryRecord + GapRecord.
 */
export function recoverChain(chainPath: string): RecoveryResult {
  const result = scanChain(chainPath);

  if (result.recordsTruncated > 0) {
    truncateChain(chainPath, result.lastValidOffset);
  }

  return result;
}

/**
 * Tests for crash recovery — scanChain, truncateChain, recoverChain.
 *
 * Builds chain files at the byte level using ChainWriter for happy path and
 * raw fs for corruption scenarios.
 */

import { strict as assert } from "assert";
import { test, describe } from "node:test";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

import { scanChain, truncateChain, recoverChain } from "./recovery";
import { ChainWriter, MAGIC, HEADER_SIZE, crc32 } from "./chain";
import { ZERO_HASH_32 } from "./types";

function tmpPath(): string {
  return path.join(
    os.tmpdir(),
    `ahp_recovery_test_${Date.now()}_${Math.random().toString(36).slice(2)}.ahp`,
  );
}

function cleanup(p: string) {
  for (const f of [p, p + ".lock"]) {
    try {
      fs.unlinkSync(f);
    } catch {
      /* ignore */
    }
  }
}

describe("scanChain — empty / missing", () => {
  test("missing file returns zero state", () => {
    const result = scanChain("/nonexistent/path/to/chain.ahp");
    assert.equal(result.recordsVerified, 0);
    assert.equal(result.recordsTruncated, 0);
    assert.equal(result.lastValidSeq, 0n);
    assert.equal(result.lastValidOffset, HEADER_SIZE);
    assert.deepEqual(Array.from(result.lastPrevHash), Array.from(ZERO_HASH_32));
  });

  test("file with just a valid header reports zero records and HEADER_SIZE offset", () => {
    const p = tmpPath();
    const w = new ChainWriter(p); // writes header
    try {
      const result = scanChain(p);
      assert.equal(result.recordsVerified, 0);
      assert.equal(result.recordsTruncated, 0);
      assert.equal(result.lastValidOffset, HEADER_SIZE);
    } finally {
      cleanup(p);
    }
  });

  test("file with bad magic returns zero state with offset 0", () => {
    const p = tmpPath();
    const buf = Buffer.alloc(HEADER_SIZE);
    buf.write("XXXX", 0); // wrong magic
    fs.writeFileSync(p, buf);
    try {
      const result = scanChain(p);
      assert.equal(result.recordsVerified, 0);
      assert.equal(result.lastValidOffset, 0);
    } finally {
      cleanup(p);
    }
  });
});

describe("scanChain — corruption detection", () => {
  test("truncated record (length header without body) is ignored", () => {
    const p = tmpPath();
    // Write a valid header followed by 4 bytes claiming a 100-byte record.
    const header = Buffer.alloc(HEADER_SIZE);
    MAGIC.copy(header, 0);
    header.writeUInt32LE(1, 4);
    header.writeBigUInt64LE(BigInt(Date.now()), 8);
    const length = Buffer.alloc(4);
    length.writeUInt32LE(100, 0);
    fs.writeFileSync(p, Buffer.concat([header, length]));

    try {
      const result = scanChain(p);
      assert.equal(result.recordsVerified, 0);
    } finally {
      cleanup(p);
    }
  });

  test("oversized length field is treated as corruption and stops scan", () => {
    const p = tmpPath();
    const header = Buffer.alloc(HEADER_SIZE);
    MAGIC.copy(header, 0);
    header.writeUInt32LE(1, 4);
    header.writeBigUInt64LE(BigInt(Date.now()), 8);
    // length larger than MAX_RECORD_SIZE
    const length = Buffer.alloc(4);
    length.writeUInt32LE(0xffffffff, 0);
    fs.writeFileSync(p, Buffer.concat([header, length]));

    try {
      const result = scanChain(p);
      assert.equal(result.recordsVerified, 0);
    } finally {
      cleanup(p);
    }
  });

  test("bad CRC stops scan at first invalid record", () => {
    const p = tmpPath();
    const header = Buffer.alloc(HEADER_SIZE);
    MAGIC.copy(header, 0);
    header.writeUInt32LE(1, 4);
    header.writeBigUInt64LE(BigInt(Date.now()), 8);

    const body = Buffer.from([1, 2, 3, 4, 5]);
    const length = Buffer.alloc(4);
    length.writeUInt32LE(body.length, 0);
    const badCrc = Buffer.alloc(4);
    badCrc.writeUInt32LE(0xdeadbeef, 0);
    fs.writeFileSync(p, Buffer.concat([header, length, body, badCrc]));

    try {
      const result = scanChain(p);
      assert.equal(result.recordsVerified, 0);
    } finally {
      cleanup(p);
    }
  });
});

describe("truncateChain", () => {
  test("ftruncates the file to the given offset", () => {
    const p = tmpPath();
    fs.writeFileSync(p, Buffer.alloc(1000));
    truncateChain(p, 64);
    assert.equal(fs.statSync(p).size, 64);
    fs.unlinkSync(p);
  });
});

describe("recoverChain", () => {
  test("missing file is a no-op (returns zero state)", () => {
    const result = recoverChain("/nonexistent/recovery_test.ahp");
    assert.equal(result.recordsVerified, 0);
    assert.equal(result.recordsTruncated, 0);
  });

  test("file with corrupt tail is truncated to lastValidOffset", () => {
    const p = tmpPath();
    // Header only — no records.
    const header = Buffer.alloc(HEADER_SIZE);
    MAGIC.copy(header, 0);
    header.writeUInt32LE(1, 4);
    header.writeBigUInt64LE(BigInt(Date.now()), 8);
    // Garbage tail
    const garbage = Buffer.from([0xab, 0xcd, 0xef]);
    fs.writeFileSync(p, Buffer.concat([header, garbage]));

    try {
      const result = recoverChain(p);
      assert.equal(result.recordsVerified, 0);
      assert.ok(result.recordsTruncated >= 1);
      assert.equal(fs.statSync(p).size, HEADER_SIZE);
    } finally {
      cleanup(p);
    }
  });
});

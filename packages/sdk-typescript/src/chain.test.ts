/**
 * Smoke tests for ChainWriter — header format, CRC32, lock contention.
 */

import { strict as assert } from "assert";
import { test, describe } from "node:test";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

import { ChainWriter, crc32, MAGIC, HEADER_SIZE } from "./chain";

function tmpChainPath(): string {
  return path.join(
    os.tmpdir(),
    `ahp_chain_test_${Date.now()}_${Math.random().toString(36).slice(2)}.ahp`,
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

describe("crc32", () => {
  test("returns 0 for empty input", () => {
    assert.equal(crc32(new Uint8Array(0)), 0);
  });

  test("matches known value for ASCII '123456789' (0xCBF43926)", () => {
    const data = new TextEncoder().encode("123456789");
    assert.equal(crc32(data), 0xcbf43926);
  });

  test("is deterministic", () => {
    const data = new TextEncoder().encode("hello world");
    assert.equal(crc32(data), crc32(data));
  });
});

describe("ChainWriter file header", () => {
  test("MAGIC is the 4-byte 'AHP\\0' literal", () => {
    assert.equal(MAGIC.length, 4);
    assert.equal(MAGIC[0], 0x41);
    assert.equal(MAGIC[1], 0x48);
    assert.equal(MAGIC[2], 0x50);
    assert.equal(MAGIC[3], 0x00);
  });

  test("HEADER_SIZE is 16 bytes", () => {
    assert.equal(HEADER_SIZE, 16);
  });

  test("constructor writes header for new chain file", () => {
    const p = tmpChainPath();
    const writer = new ChainWriter(p);
    try {
      assert.ok(fs.existsSync(p));
      const stat = fs.statSync(p);
      assert.equal(stat.size, HEADER_SIZE);
      const buf = fs.readFileSync(p);
      assert.equal(buf[0], 0x41); // 'A'
      assert.equal(buf[1], 0x48); // 'H'
      assert.equal(buf[2], 0x50); // 'P'
      assert.equal(buf[3], 0x00);
      assert.equal(buf.readUInt32LE(4), 1); // file version
    } finally {
      // Manually drop fd via process exit during cleanup; best-effort unlink.
      cleanup(p);
    }
  });
});

describe("ChainWriter lock contention", () => {
  test("second writer on same chain path throws", () => {
    const p = tmpChainPath();
    const writerA = new ChainWriter(p);
    try {
      assert.throws(() => new ChainWriter(p), /locked by another process/);
    } finally {
      cleanup(p);
    }
  });
});

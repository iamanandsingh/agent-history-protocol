/**
 * Tests for EvidenceStore — content addressing, retrieval, verification, count.
 */

import { strict as assert } from "assert";
import { test, describe } from "node:test";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import * as crypto from "crypto";

import { EvidenceStore } from "./evidence";

function tmpStoreDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "ahp_evidence_"));
}

function expectedTruncatedHash(payload: Uint8Array): Uint8Array {
  return new Uint8Array(
    crypto.createHash("sha256").update(payload).digest().subarray(0, 16),
  );
}

describe("EvidenceStore.store", () => {
  test("creates the directory if it does not exist", () => {
    const dir = path.join(os.tmpdir(), `ahp_ev_new_${Date.now()}`);
    try {
      const store = new EvidenceStore(dir);
      assert.ok(fs.existsSync(dir));
      assert.equal(store.count().available, 0);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test("returns 16-byte truncated SHA-256 hash", () => {
    const dir = tmpStoreDir();
    try {
      const store = new EvidenceStore(dir);
      const payload = new TextEncoder().encode("hello");
      const hash = store.store(payload);
      assert.equal(hash.length, 16);
      assert.deepEqual(Array.from(hash), Array.from(expectedTruncatedHash(payload)));
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test("writes file named after hex hash", () => {
    const dir = tmpStoreDir();
    try {
      const store = new EvidenceStore(dir);
      const payload = new TextEncoder().encode("payload-1");
      const hash = store.store(payload);
      const expectedName = Buffer.from(hash).toString("hex");
      assert.ok(fs.existsSync(path.join(dir, expectedName)));
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test("storing identical payload twice is idempotent", () => {
    const dir = tmpStoreDir();
    try {
      const store = new EvidenceStore(dir);
      const payload = new TextEncoder().encode("dup");
      const h1 = store.store(payload);
      const h2 = store.store(payload);
      assert.deepEqual(Array.from(h1), Array.from(h2));
      assert.equal(store.count().available, 1);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test("distinct payloads produce distinct files", () => {
    const dir = tmpStoreDir();
    try {
      const store = new EvidenceStore(dir);
      store.store(new TextEncoder().encode("a"));
      store.store(new TextEncoder().encode("b"));
      store.store(new TextEncoder().encode("c"));
      assert.equal(store.count().available, 3);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("EvidenceStore.retrieve", () => {
  test("round-trips a stored payload", () => {
    const dir = tmpStoreDir();
    try {
      const store = new EvidenceStore(dir);
      const payload = new TextEncoder().encode("round trip");
      const hash = store.store(payload);
      const got = store.retrieve(hash);
      assert.ok(got);
      assert.deepEqual(Array.from(got!), Array.from(payload));
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test("returns null for unknown hash", () => {
    const dir = tmpStoreDir();
    try {
      const store = new EvidenceStore(dir);
      const got = store.retrieve(new Uint8Array(16));
      assert.equal(got, null);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("EvidenceStore.verify", () => {
  test("returns true for an intact file", () => {
    const dir = tmpStoreDir();
    try {
      const store = new EvidenceStore(dir);
      const payload = new TextEncoder().encode("intact");
      const hash = store.store(payload);
      assert.equal(store.verify(hash), true);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test("returns false when file is missing", () => {
    const dir = tmpStoreDir();
    try {
      const store = new EvidenceStore(dir);
      assert.equal(store.verify(new Uint8Array(16)), false);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test("returns false when file is tampered", () => {
    const dir = tmpStoreDir();
    try {
      const store = new EvidenceStore(dir);
      const payload = new TextEncoder().encode("tamper-me");
      const hash = store.store(payload);
      const filename = Buffer.from(hash).toString("hex");
      fs.writeFileSync(path.join(dir, filename), "tampered");
      assert.equal(store.verify(hash), false);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("EvidenceStore.count", () => {
  test("constructor counts pre-existing files (excluding dotfiles)", () => {
    const dir = tmpStoreDir();
    try {
      // Pre-populate with two regular files and one dotfile
      fs.writeFileSync(path.join(dir, "aa"), "x");
      fs.writeFileSync(path.join(dir, "bb"), "y");
      fs.writeFileSync(path.join(dir, ".hidden"), "z");
      const store = new EvidenceStore(dir);
      assert.equal(store.count().available, 2);
      assert.equal(store.count().missing, 0);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

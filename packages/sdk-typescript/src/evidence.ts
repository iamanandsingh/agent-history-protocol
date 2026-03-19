/**
 * Evidence store — content-addressed payload storage (Section 6).
 *
 * Stores evidence payloads indexed by their truncated SHA-256 hash.
 * Uses atomic writes (temp file + rename) to prevent TOCTOU races.
 */

import * as fs from "fs";
import * as path from "path";
import * as crypto from "crypto";
import * as os from "os";

export class EvidenceStore {
  readonly path: string;

  constructor(storePath: string = "evidence") {
    this.path = storePath;
    fs.mkdirSync(this.path, { recursive: true });
  }

  /**
   * Store payload, return 16-byte truncated SHA-256 hash.
   *
   * Uses atomic write (write to temp file + rename) to avoid
   * TOCTOU races. Since the store is content-addressed, if the
   * file already exists the content is identical and we skip.
   */
  store(payload: Uint8Array): Uint8Array {
    const fullHash = crypto.createHash("sha256").update(payload).digest();
    const truncated = new Uint8Array(fullHash.subarray(0, 16));
    const filename = Buffer.from(truncated).toString("hex");
    const filepath = path.join(this.path, filename);

    if (fs.existsSync(filepath)) {
      return truncated;
    }

    // Atomic write: temp file in the same directory, then rename
    const tmpPath = path.join(
      this.path,
      `.tmp_${crypto.randomBytes(8).toString("hex")}`
    );
    let tmpFd: number | null = null;
    try {
      tmpFd = fs.openSync(tmpPath, "w");
      fs.writeSync(tmpFd, payload);
      fs.closeSync(tmpFd);
      tmpFd = null;
      fs.renameSync(tmpPath, filepath);
    } catch (e) {
      if (tmpFd !== null) {
        try {
          fs.closeSync(tmpFd);
        } catch {
          // ignore
        }
      }
      try {
        fs.unlinkSync(tmpPath);
      } catch {
        // ignore
      }
      throw e;
    }

    return truncated;
  }

  /**
   * Retrieve payload by its 16-byte hash. Returns null if missing.
   */
  retrieve(hash16: Uint8Array): Uint8Array | null {
    const filename = Buffer.from(hash16).toString("hex");
    const filepath = path.join(this.path, filename);
    if (!fs.existsSync(filepath)) {
      return null;
    }
    return new Uint8Array(fs.readFileSync(filepath));
  }

  /**
   * Verify evidence file matches its hash.
   */
  verify(hash16: Uint8Array): boolean {
    const payload = this.retrieve(hash16);
    if (payload === null) {
      return false;
    }
    const actual = crypto
      .createHash("sha256")
      .update(payload)
      .digest()
      .subarray(0, 16);
    return Buffer.from(actual).equals(Buffer.from(hash16));
  }

  /**
   * Count evidence files by status.
   */
  count(): { available: number; missing: number } {
    try {
      const files = fs.readdirSync(this.path).filter((f) => !f.startsWith("."));
      return { available: files.length, missing: 0 };
    } catch {
      return { available: 0, missing: 0 };
    }
  }
}

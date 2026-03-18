/**
 * UUID v7 generation — time-ordered UUIDs per RFC 9562.
 *
 * Layout (128 bits):
 *   48 bits: unix_ts_ms (milliseconds since epoch)
 *    4 bits: version (0b0111 = 7)
 *   12 bits: rand_a
 *    2 bits: variant (0b10)
 *   62 bits: rand_b
 */

import * as crypto from "crypto";

/**
 * Generate a UUID v7 as 16 raw bytes.
 */
export function uuid7(): Uint8Array {
  const tsMs = BigInt(Date.now());
  const randBytes = crypto.randomBytes(10);

  const b = new Uint8Array(16);

  // Bytes 0-5: timestamp (48 bits, big-endian)
  b[0] = Number((tsMs >> 40n) & 0xFFn);
  b[1] = Number((tsMs >> 32n) & 0xFFn);
  b[2] = Number((tsMs >> 24n) & 0xFFn);
  b[3] = Number((tsMs >> 16n) & 0xFFn);
  b[4] = Number((tsMs >> 8n) & 0xFFn);
  b[5] = Number(tsMs & 0xFFn);

  // Bytes 6-7: version (4 bits) + rand_a (12 bits)
  b[6] = 0x70 | (randBytes[0] & 0x0F); // version 7
  b[7] = randBytes[1];

  // Bytes 8-15: variant (2 bits) + rand_b (62 bits)
  b[8] = 0x80 | (randBytes[2] & 0x3F); // variant 10
  b[9] = randBytes[3];
  b[10] = randBytes[4];
  b[11] = randBytes[5];
  b[12] = randBytes[6];
  b[13] = randBytes[7];
  b[14] = randBytes[8];
  b[15] = randBytes[9];

  return b;
}

/**
 * Convert 16 raw UUID bytes to standard hyphenated string.
 */
export function uuid7ToStr(raw: Uint8Array): string {
  const h = Buffer.from(raw).toString("hex");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

/**
 * Convert hyphenated UUID string to 16 raw bytes.
 */
export function strToUuid7(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s.replace(/-/g, ""), "hex"));
}

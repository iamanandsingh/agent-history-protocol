/**
 * Ed25519 signing — Section 7 of the AHP specification.
 *
 * Uses Node.js built-in crypto module for Ed25519 operations.
 */

import * as crypto from "crypto";

export interface KeyPair {
  privateKeyBytes: Uint8Array; // 32 bytes (raw seed)
  publicKeyBytes: Uint8Array; // 32 bytes
  keyId: Uint8Array; // SHA-256 of public key, 32 bytes
}

/**
 * Generate an Ed25519 keypair.
 */
export function generateKeypair(): KeyPair {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");

  // SPKI DER for Ed25519: 12-byte ASN.1 prefix + 32-byte raw key = 44 bytes
  const spkiDer = publicKey.export({ type: "spki", format: "der" });
  if (spkiDer.length !== 44) {
    throw new Error(`Unexpected SPKI DER length: ${spkiDer.length} (expected 44)`);
  }
  const publicKeyBytes = new Uint8Array(spkiDer.subarray(-32));

  // PKCS8 DER for Ed25519: 16-byte ASN.1 prefix + 32-byte raw seed = 48 bytes
  const pkcs8Der = privateKey.export({ type: "pkcs8", format: "der" });
  if (pkcs8Der.length !== 48) {
    throw new Error(`Unexpected PKCS8 DER length: ${pkcs8Der.length} (expected 48)`);
  }
  const privateKeyBytes = new Uint8Array(pkcs8Der.subarray(-32));

  const keyId = new Uint8Array(
    crypto.createHash("sha256").update(publicKeyBytes).digest()
  );

  return { privateKeyBytes, publicKeyBytes, keyId };
}

/**
 * Sign a message with Ed25519. Returns 64-byte signature.
 */
export function sign(message: Uint8Array, privateKeyBytes: Uint8Array): Uint8Array {
  // Reconstruct the private key object from raw bytes
  const privateKey = crypto.createPrivateKey({
    key: Buffer.concat([
      // PKCS8 DER prefix for Ed25519 (48 bytes total = 16 prefix + 32 key)
      Buffer.from("302e020100300506032b657004220420", "hex"),
      Buffer.from(privateKeyBytes),
    ]),
    format: "der",
    type: "pkcs8",
  });

  return new Uint8Array(crypto.sign(null, Buffer.from(message), privateKey));
}

/**
 * Verify an Ed25519 signature.
 */
export function verifySignature(
  message: Uint8Array,
  signature: Uint8Array,
  publicKeyBytes: Uint8Array
): boolean {
  try {
    // Reconstruct the public key object from raw bytes
    const publicKey = crypto.createPublicKey({
      key: Buffer.concat([
        // SPKI DER prefix for Ed25519 (44 bytes total = 12 prefix + 32 key)
        Buffer.from("302a300506032b6570032100", "hex"),
        Buffer.from(publicKeyBytes),
      ]),
      format: "der",
      type: "spki",
    });

    return crypto.verify(
      null,
      Buffer.from(message),
      publicKey,
      Buffer.from(signature)
    );
  } catch {
    return false;
  }
}

/**
 * Compute RFC 6962 Merkle tree root from a list of record hashes (each 32 bytes).
 *
 * Uses leaf prefix 0x00 per RFC 6962 Section 2.1 and node prefix 0x01.
 */
export function computeMerkleRoot(recordHashes: Uint8Array[]): Uint8Array {
  if (recordHashes.length === 0) {
    return new Uint8Array(32);
  }

  // RFC 6962 Merkle tree — leaf prefix 0x00 per Section 2.1
  let nodes: Uint8Array[] = recordHashes.map((h) => {
    const prefixed = new Uint8Array(1 + h.length);
    prefixed[0] = 0x00;
    prefixed.set(h, 1);
    return new Uint8Array(crypto.createHash("sha256").update(prefixed).digest());
  });

  if (nodes.length === 1) {
    return nodes[0];
  }

  while (nodes.length > 1) {
    const newNodes: Uint8Array[] = [];
    for (let i = 0; i < nodes.length; i += 2) {
      const left = nodes[i];
      const right = i + 1 < nodes.length ? nodes[i + 1] : nodes[i]; // duplicate odd node
      const combined = new Uint8Array(1 + left.length + right.length);
      combined[0] = 0x01;
      combined.set(left, 1);
      combined.set(right, 1 + left.length);
      newNodes.push(
        new Uint8Array(crypto.createHash("sha256").update(combined).digest())
      );
    }
    nodes = newNodes;
  }

  return nodes[0];
}

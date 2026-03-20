"""Ed25519 signing — Section 7 of the AHP specification."""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from typing import List

logger = logging.getLogger("ahp.signing")

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


@dataclass
class KeyPair:
    private_key_bytes: bytes  # 32 bytes
    public_key_bytes: bytes  # 32 bytes
    key_id: bytes  # SHA-256 of public key, 32 bytes


def generate_keypair() -> KeyPair:
    """Generate an Ed25519 keypair."""
    if not HAS_CRYPTO:
        raise RuntimeError(
            "The 'cryptography' package is required for Level 2+ signing. Install with: pip install ahp[signing]"
        )
    private_key = Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    public_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )

    key_id = hashlib.sha256(public_bytes).digest()
    return KeyPair(private_key_bytes=private_bytes, public_key_bytes=public_bytes, key_id=key_id)


def sign(message: bytes, private_key_bytes: bytes) -> bytes:
    """Sign a message with Ed25519. Returns 64-byte signature."""
    if not HAS_CRYPTO:
        raise RuntimeError(
            "The 'cryptography' package is required for Level 2+ signing. Install with: pip install ahp[signing]"
        )
    private_key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    return private_key.sign(message)


def verify_signature(message: bytes, signature: bytes, public_key_bytes: bytes) -> bool:
    """Verify an Ed25519 signature."""
    if not HAS_CRYPTO:
        raise RuntimeError(
            "The 'cryptography' package is required for Level 2+ signing. Install with: pip install ahp[signing]"
        )
    try:
        public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        public_key.verify(signature, message)
        return True
    except Exception as exc:
        logger.debug("verify_signature failed: %s: %s", type(exc).__name__, exc)
        return False


def compute_merkle_root(record_hashes: List[bytes]) -> bytes:
    """Compute RFC 6962 Merkle tree root from a list of record hashes (each 32 bytes)."""
    if not record_hashes:
        return b"\x00" * 32

    # RFC 6962 Merkle tree — leaf prefix 0x00 per Section 2.1
    nodes = [hashlib.sha256(b"\x00" + h).digest() for h in record_hashes]
    if len(nodes) == 1:
        return nodes[0]
    while len(nodes) > 1:
        new_nodes: List[bytes] = []
        for i in range(0, len(nodes), 2):
            if i + 1 < len(nodes):
                combined = b"\x01" + nodes[i] + nodes[i + 1]
            else:
                combined = b"\x01" + nodes[i] + nodes[i]  # duplicate odd node
            new_nodes.append(hashlib.sha256(combined).digest())
        nodes = new_nodes
    return nodes[0]

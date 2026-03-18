"""Evidence store — content-addressed payload storage (Section 6)."""
from __future__ import annotations
import hashlib
import os
from pathlib import Path
from typing import Optional


class EvidenceStore:
    """Content-addressed evidence storage."""

    def __init__(self, path: str = "evidence"):
        self.path = Path(path)
        self.path.mkdir(parents=True, exist_ok=True)

    def store(self, payload: bytes) -> bytes:
        """Store payload, return 16-byte truncated SHA-256 hash."""
        full_hash = hashlib.sha256(payload).digest()
        truncated = full_hash[:16]  # 128 bits
        filename = truncated.hex()
        filepath = self.path / filename
        if not filepath.exists():
            filepath.write_bytes(payload)
        return truncated

    def retrieve(self, hash_16: bytes) -> Optional[bytes]:
        """Retrieve payload by its 16-byte hash. Returns None if missing."""
        filepath = self.path / hash_16.hex()
        if filepath.exists():
            return filepath.read_bytes()
        return None

    def verify(self, hash_16: bytes) -> bool:
        """Verify evidence file matches its hash."""
        payload = self.retrieve(hash_16)
        if payload is None:
            return False
        actual = hashlib.sha256(payload).digest()[:16]
        return actual == hash_16

    def count(self) -> dict:
        """Count evidence files by status."""
        files = list(self.path.iterdir())
        return {
            'available': len(files),
            'missing': 0,  # would need chain scan to determine
        }

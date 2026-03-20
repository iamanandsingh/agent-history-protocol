"""Evidence store — content-addressed payload storage (Section 6)."""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import tempfile
import time
from pathlib import Path
from typing import Optional

logger = logging.getLogger("ahp.evidence")


class EvidenceStore:
    """Content-addressed evidence storage with optional lifecycle management.

    Evidence payloads are indexed by truncated SHA-256 hashes (128 bits / 16 bytes).
    This provides a collision resistance of ~2^64 (birthday bound), which is
    acceptable for evidence deduplication. The truncation is a deliberate
    spec design choice (Section 6) to reduce storage overhead for filenames
    and hash fields in the chain. It does NOT affect the chain's own integrity,
    which uses full 256-bit SHA-256 hashes.

    Parameters:
        path: Directory to store evidence files.
        max_size_bytes: Maximum total size of all evidence files.
            When exceeded, oldest files are removed during cleanup.
            None means unlimited.
        max_age_seconds: Maximum age of evidence files in seconds.
            Files older than this are removed during cleanup.
            None means unlimited.
    """

    def __init__(
        self,
        path: str = "evidence",
        max_size_bytes: Optional[int] = None,
        max_age_seconds: Optional[int] = None,
        cleanup_interval: int = 100,
    ):
        self.path = Path(path)
        self.path.mkdir(parents=True, exist_ok=True)
        self._max_size_bytes = max_size_bytes
        self._max_age_seconds = max_age_seconds
        self._cleanup_interval = cleanup_interval
        self._stores_since_cleanup = 0
        self._file_count = sum(1 for f in self.path.iterdir() if f.is_file())

    @property
    def max_size_bytes(self) -> Optional[int]:
        return self._max_size_bytes

    @max_size_bytes.setter
    def max_size_bytes(self, value: Optional[int]) -> None:
        self._max_size_bytes = value

    @property
    def max_age_seconds(self) -> Optional[int]:
        return self._max_age_seconds

    @max_age_seconds.setter
    def max_age_seconds(self, value: Optional[int]) -> None:
        self._max_age_seconds = value

    def store(self, payload: bytes) -> bytes:
        """Store payload, return 16-byte truncated SHA-256 hash.

        Uses atomic write (write to temp file + rename) to avoid
        TOCTOU races. Since the store is content-addressed, if the
        file already exists the content is identical and we skip.

        If size or age limits are configured, runs cleanup automatically
        after each store.
        """
        full_hash = hashlib.sha256(payload).digest()
        truncated = full_hash[:16]  # 128 bits
        filename = truncated.hex()
        filepath = self.path / filename
        if filepath.exists():
            return truncated
        # Atomic write: temp file in the same directory, then rename
        fd, tmp = tempfile.mkstemp(dir=str(self.path))
        fd_closed = False
        try:
            os.write(fd, payload)
            os.close(fd)
            fd_closed = True
            os.rename(tmp, str(filepath))
            self._file_count += 1
        except BaseException:
            if not fd_closed:
                try:
                    os.close(fd)
                except OSError:
                    pass
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

        # Auto-cleanup if limits are configured (throttled by cleanup_interval)
        if self._max_size_bytes is not None or self._max_age_seconds is not None:
            self._stores_since_cleanup += 1
            if self._stores_since_cleanup >= self._cleanup_interval:
                self.cleanup()
                self._stores_since_cleanup = 0

        return truncated

    def retrieve(self, hash_16: bytes) -> Optional[bytes]:
        """Retrieve payload by its 16-byte hash. Returns None if missing."""
        try:
            return (self.path / hash_16.hex()).read_bytes()
        except FileNotFoundError:
            return None

    def verify(self, hash_16: bytes) -> bool:
        """Verify evidence file matches its hash."""
        payload = self.retrieve(hash_16)
        if payload is None:
            return False
        actual = hashlib.sha256(payload).digest()[:16]
        return hmac.compare_digest(actual, hash_16)

    def count(self) -> dict:
        """Count evidence files by status (in-memory, no directory scan)."""
        return {
            "available": self._file_count,
            "missing": 0,  # would need chain scan to determine
        }

    def cleanup(self) -> int:
        """Remove evidence files exceeding TTL or when total size exceeds max.

        Eviction order: oldest files first (by mtime).

        Returns the number of files removed.
        """
        removed = 0

        try:
            files = list(self.path.iterdir())
        except OSError:
            return 0

        # Filter to actual files (skip directories, temp files, etc.)
        evidence_files = []
        for f in files:
            if f.is_file():
                try:
                    stat = f.stat()
                    evidence_files.append((f, stat))
                except OSError:
                    continue

        now = time.time()

        # 1. Remove files exceeding max_age_seconds (TTL)
        if self._max_age_seconds is not None:
            cutoff = now - self._max_age_seconds
            surviving = []
            for filepath, stat in evidence_files:
                if stat.st_mtime < cutoff:
                    try:
                        filepath.unlink()
                        removed += 1
                        logger.debug(
                            "Evidence cleanup: removed expired file %s (age=%.0fs)",
                            filepath.name,
                            now - stat.st_mtime,
                        )
                    except OSError as exc:
                        logger.debug("Failed to remove expired evidence %s: %s", filepath.name, exc)
                        surviving.append((filepath, stat))
                else:
                    surviving.append((filepath, stat))
            evidence_files = surviving

        # 2. Remove oldest files when total size exceeds max_size_bytes
        if self._max_size_bytes is not None:
            # Sort by mtime ascending (oldest first)
            evidence_files.sort(key=lambda x: x[1].st_mtime)

            total_size = sum(stat.st_size for _, stat in evidence_files)

            while total_size > self._max_size_bytes and evidence_files:
                filepath, stat = evidence_files.pop(0)
                try:
                    filepath.unlink()
                    total_size -= stat.st_size
                    removed += 1
                    logger.debug(
                        "Evidence cleanup: removed file %s to stay under size limit (removed %d bytes, total now %d)",
                        filepath.name,
                        stat.st_size,
                        total_size,
                    )
                except OSError as exc:
                    logger.debug("Failed to remove evidence %s: %s", filepath.name, exc)
                    continue

        if removed > 0:
            self._file_count -= removed
            logger.info("Evidence cleanup: removed %d files", removed)

        return removed

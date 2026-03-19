"""Evidence store — content-addressed payload storage (Section 6)."""
from __future__ import annotations
import hashlib
import logging
import os
import tempfile
import time
from pathlib import Path
from typing import Optional

logger = logging.getLogger("ahp.evidence")


class EvidenceStore:
    """Content-addressed evidence storage with optional lifecycle management.

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
    ):
        self.path = Path(path)
        self.path.mkdir(parents=True, exist_ok=True)
        self._max_size_bytes = max_size_bytes
        self._max_age_seconds = max_age_seconds

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

        # Auto-cleanup if limits are configured
        if self._max_size_bytes is not None or self._max_age_seconds is not None:
            self.cleanup()

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
                            filepath.name, now - stat.st_mtime,
                        )
                    except OSError:
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
                        "Evidence cleanup: removed file %s to stay under size limit "
                        "(removed %d bytes, total now %d)",
                        filepath.name, stat.st_size, total_size,
                    )
                except OSError:
                    continue

        if removed > 0:
            logger.info("Evidence cleanup: removed %d files", removed)

        return removed

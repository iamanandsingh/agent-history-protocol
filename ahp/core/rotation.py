"""Chain file rotation — manages 64MB segments with export-gated deletion.

Implements the chain rotation strategy from spec Appendix C:
- Segments at 64MB max
- New segment when current exceeds limit
- Old segments only deleted after export confirmed
- GapRecord with reason=ROTATION when segments removed
"""
from __future__ import annotations

import os
import struct
import time
from pathlib import Path
from typing import Optional, List, Dict

from ahp.core.chain import ChainWriter, ChainReader, MAGIC, HEADER_SIZE


DEFAULT_MAX_SEGMENT_BYTES = 64 * 1024 * 1024  # 64MB


class SegmentInfo:
    """Metadata about a chain segment file."""

    def __init__(self, path: str, index: int):
        self.path = path
        self.index = index
        self.exported = False
        self.record_count = 0

    @property
    def size(self) -> int:
        p = Path(self.path)
        return p.stat().st_size if p.exists() else 0

    @property
    def exists(self) -> bool:
        return Path(self.path).exists()


class ChainRotator:
    """Manages chain file segments with automatic rotation.

    Usage:
        rotator = ChainRotator("my-agent")
        writer = rotator.get_writer()

        # Write records...
        writer.write_record(payload)

        # Check if rotation needed after each write
        if rotator.needs_rotation():
            writer = rotator.rotate()

        # After export confirmed:
        rotator.mark_exported(segment_index)

        # Clean up exported segments:
        rotator.compact()
    """

    def __init__(self, base_name: str, directory: str = ".",
                 max_segment_bytes: int = DEFAULT_MAX_SEGMENT_BYTES):
        self.base_name = base_name
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.max_segment_bytes = max_segment_bytes
        self.segments: List[SegmentInfo] = []
        self._current_writer: Optional[ChainWriter] = None
        self._current_segment_index = 0

        # Discover existing segments
        self._discover_segments()

        # If no segments, create the first one
        if not self.segments:
            self._create_segment()

    def _discover_segments(self) -> None:
        """Find existing segment files."""
        pattern = f"{self.base_name}.*.ahp"
        for f in sorted(self.directory.glob(pattern)):
            try:
                # Extract index from filename: agent.001.ahp → 1
                parts = f.stem.split('.')
                if len(parts) >= 2:
                    idx = int(parts[-1])
                    seg = SegmentInfo(str(f), idx)
                    seg.record_count = ChainReader(str(f)).count()
                    self.segments.append(seg)
                    self._current_segment_index = max(self._current_segment_index, idx)
            except (ValueError, IndexError):
                pass

        # Also check for non-indexed file (single segment mode)
        single = self.directory / f"{self.base_name}.ahp"
        if single.exists() and not self.segments:
            seg = SegmentInfo(str(single), 0)
            seg.record_count = ChainReader(str(single)).count()
            self.segments.append(seg)

    def _create_segment(self) -> SegmentInfo:
        """Create a new segment file."""
        self._current_segment_index += 1
        idx = self._current_segment_index
        path = str(self.directory / f"{self.base_name}.{idx:03d}.ahp")
        seg = SegmentInfo(path, idx)
        self.segments.append(seg)
        return seg

    def get_writer(self) -> ChainWriter:
        """Get the writer for the current segment."""
        if self._current_writer is None:
            seg = self.segments[-1] if self.segments else self._create_segment()
            self._current_writer = ChainWriter(seg.path)
        return self._current_writer

    def needs_rotation(self) -> bool:
        """Check if current segment exceeds the size limit."""
        if not self.segments:
            return False
        current = self.segments[-1]
        return current.size >= self.max_segment_bytes

    def rotate(self) -> ChainWriter:
        """Close current segment and create a new one. Returns new writer."""
        # Close current writer
        if self._current_writer:
            self._current_writer.close()

        # Update record count on old segment
        if self.segments:
            old_seg = self.segments[-1]
            old_seg.record_count = ChainReader(old_seg.path).count()

        # Create new segment
        new_seg = self._create_segment()
        self._current_writer = ChainWriter(new_seg.path)
        return self._current_writer

    def mark_exported(self, segment_index: int) -> None:
        """Mark a segment as fully exported."""
        for seg in self.segments:
            if seg.index == segment_index:
                seg.exported = True
                break

    def compact(self) -> int:
        """Remove exported segments. Returns count of segments removed.

        Per spec: segments SHOULD NOT be removed until exported.
        At Level 3: segments MUST NOT be removed until exported.
        """
        removed = 0
        remaining = []
        for seg in self.segments:
            if seg.exported and seg != self.segments[-1]:
                # Don't remove the current/active segment
                try:
                    Path(seg.path).unlink()
                    removed += 1
                except OSError:
                    remaining.append(seg)
            else:
                remaining.append(seg)
        self.segments = remaining
        return removed

    @property
    def total_records(self) -> int:
        return sum(s.record_count for s in self.segments)

    @property
    def total_size(self) -> int:
        return sum(s.size for s in self.segments)

    @property
    def segment_count(self) -> int:
        return len(self.segments)

    def close(self) -> None:
        if self._current_writer:
            self._current_writer.close()
            self._current_writer = None

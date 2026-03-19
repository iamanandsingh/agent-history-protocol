"""Async chain writer — non-blocking record writing for asyncio agent frameworks.

Uses an internal asyncio.Queue as a staging buffer. A background task
drains the queue and writes to disk, matching the spec's staging file pattern.

Usage:
    writer = AsyncChainWriter("agent.ahp")
    await writer.start()
    record = await writer.write_record(payload)
    await writer.stop()
"""
from __future__ import annotations

import asyncio
import hashlib
import os
import struct
import time
import zlib
from pathlib import Path
from typing import Optional, Union

from ahp.core.types import RecordType, ZERO_HASH_32, SCHEMA_VERSION
from ahp.core.records import Record, Payload, PAYLOAD_TYPE_MAP
from ahp.core.canonical import canonical_bytes
from ahp.core.uuid7 import uuid7
from ahp.core.chain import MAGIC, FILE_VERSION, HEADER_SIZE


class AsyncChainWriter:
    """Async chain writer with internal staging queue.

    Records are queued via write_record() (non-blocking) and written
    to disk by a background drain task. This matches the spec's
    staging file → single writer architecture.
    """

    def __init__(self, path: Union[str, Path], agent_id: Optional[bytes] = None,
                 session_id: Optional[bytes] = None, max_queue: int = 10000):
        self.path = Path(path)
        self.agent_id = agent_id or uuid7()
        self.session_id = session_id or uuid7()
        self._sequence = 0
        self._prev_hash = ZERO_HASH_32
        self._record_count = 0
        self._gap_count = 0
        self._max_queue = max_queue
        self._queue: Optional[asyncio.Queue] = None
        self._drain_task: Optional[asyncio.Task] = None
        self._running = False
        self._write_lock = asyncio.Lock()
        self._lock_file = None
        self._header_written = False

        # Acquire exclusive file lock (synchronous — done once at init)
        try:
            import fcntl
            lock_path = str(self.path) + '.lock'
            self._lock_file = open(lock_path, 'w')
            fcntl.flock(self._lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (ImportError, OSError):
            pass  # File locking not available on this platform

    def _write_header(self) -> None:
        with open(self.path, 'wb') as f:
            f.write(MAGIC)
            f.write(struct.pack('<I', FILE_VERSION))
            f.write(struct.pack('<Q', int(time.time() * 1000)))
        self._header_written = True

    async def start(self) -> None:
        """Start the background drain task. Writes header if needed."""
        if self._running:
            return
        if not self.path.exists():
            await asyncio.to_thread(self._write_header)
        self._queue = asyncio.Queue(maxsize=self._max_queue)
        self._running = True
        self._drain_task = asyncio.ensure_future(self._drain_loop())

    async def stop(self) -> None:
        """Flush remaining records and stop the drain task."""
        if not self._running:
            return
        self._running = False
        if self._queue:
            await self._queue.join()
        if self._drain_task:
            self._drain_task.cancel()
            try:
                await self._drain_task
            except asyncio.CancelledError:
                pass
        self._drain_task = None
        # Release file lock
        if self._lock_file:
            try:
                import fcntl
                fcntl.flock(self._lock_file.fileno(), fcntl.LOCK_UN)
            except (ImportError, OSError):
                pass
            try:
                lock_path = str(self.path) + '.lock'
                self._lock_file.close()
                os.unlink(lock_path)
            except OSError:
                pass
            self._lock_file = None

    async def write_record(self, payload: Payload,
                           session_id: Optional[bytes] = None,
                           timestamp_ms: Optional[int] = None) -> Record:
        """Queue a record for async writing. Returns the record immediately.

        The record is assigned sequence + prev_hash synchronously for
        correct ordering, then queued for background disk write.
        """
        async with self._write_lock:
            self._sequence += 1

            record = Record(
                record_id=uuid7(),
                agent_id=self.agent_id,
                session_id=session_id or self.session_id,
                timestamp_ms=timestamp_ms or int(time.time() * 1000),
                sequence=self._sequence,
                prev_hash=self._prev_hash,
                schema_version=SCHEMA_VERSION,
                record_type=PAYLOAD_TYPE_MAP[type(payload)],
                payload=payload,
            )

            stored = canonical_bytes(record)
            record._stored_bytes = stored

            self._prev_hash = hashlib.sha256(stored).digest()
            self._record_count += 1
            if record.record_type == RecordType.GAP:
                self._gap_count += 1

            if self._queue:
                await self._queue.put(stored)

            return record

    async def _drain_loop(self) -> None:
        """Background: drain queue and write records to disk (non-blocking)."""
        while self._running or (self._queue and not self._queue.empty()):
            try:
                stored = await asyncio.wait_for(self._queue.get(), timeout=0.1)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                if not self._running and self._queue.empty():
                    break
                continue

            await asyncio.to_thread(self._write_to_file, stored)
            self._queue.task_done()

    def _write_to_file(self, stored: bytes) -> None:
        """Synchronous disk write — runs in a thread via asyncio.to_thread."""
        with open(self.path, 'ab') as f:
            length = len(stored)
            length_bytes = struct.pack('<I', length)
            f.write(length_bytes)
            f.write(stored)
            crc = zlib.crc32(length_bytes + stored) & 0xFFFFFFFF
            f.write(struct.pack('<I', crc))

    @property
    def sequence(self) -> int:
        return self._sequence

    @property
    def prev_hash(self) -> bytes:
        return self._prev_hash

    @property
    def record_count(self) -> int:
        return self._record_count

    @property
    def gap_count(self) -> int:
        return self._gap_count

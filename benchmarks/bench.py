#!/usr/bin/env python3
"""Performance benchmarks for the AHP SDK.

Measures:
  - Records/second (sync writer)
  - Records/second (async writer)
  - Canonical serialization time
  - Verification time
  - Memory per record

Usage: python3 benchmarks/bench.py
"""
from __future__ import annotations

import asyncio
import hashlib
import os
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from ahp.core.types import ResultStatus, Protocol, ActionType, AuthorizationType
from ahp.core.records import ActionPayload, Authorization
from ahp.core.canonical import canonical_bytes
from ahp.core.chain import ChainWriter, ChainReader
from ahp.core.async_chain import AsyncChainWriter
from ahp.core.verify import verify_chain
from ahp.core.records import Record
from ahp.core.types import RecordType, ZERO_HASH_32, SCHEMA_VERSION
from ahp.core.uuid7 import uuid7


def _make_payload(i: int) -> ActionPayload:
    return ActionPayload(
        tool_name=f"benchmark_tool_{i}",
        parameters_hash=hashlib.sha256(f"params_{i}".encode()).digest()[:16],
        result_hash=hashlib.sha256(f"result_{i}".encode()).digest()[:16],
        result_status=ResultStatus.SUCCESS,
        response_time_ms=42,
        protocol=Protocol.MCP,
        action_type=ActionType.TOOL_CALL,
        authorization=Authorization(type=AuthorizationType.AUTH_NONE),
    )


def bench_serialization(n: int = 10000) -> None:
    """Benchmark canonical serialization speed."""
    record = Record(
        record_id=uuid7(),
        agent_id=uuid7(),
        session_id=uuid7(),
        timestamp_ms=int(time.time() * 1000),
        sequence=1,
        prev_hash=ZERO_HASH_32,
        schema_version=SCHEMA_VERSION,
        record_type=RecordType.ACTION,
        payload=_make_payload(0),
    )

    start = time.time()
    for i in range(n):
        canonical_bytes(record)
    elapsed = time.time() - start

    per_record = elapsed / n * 1_000_000  # microseconds
    records_sec = n / elapsed
    print(f"  Serialization:    {records_sec:,.0f} records/sec  ({per_record:.1f} us/record)")


def bench_sync_write(n: int = 10000) -> None:
    """Benchmark synchronous chain write speed."""
    tmpdir = tempfile.mkdtemp()
    path = os.path.join(tmpdir, "bench_sync.ahp")

    writer = ChainWriter(path)
    start = time.time()
    for i in range(n):
        writer.write_record(_make_payload(i))
    elapsed = time.time() - start
    writer.close()

    records_sec = n / elapsed
    file_size = Path(path).stat().st_size
    mb = file_size / (1024 * 1024)
    print(f"  Sync write:       {records_sec:,.0f} records/sec  ({mb:.1f} MB for {n} records)")


def bench_async_write(n: int = 10000) -> None:
    """Benchmark async chain write speed."""
    tmpdir = tempfile.mkdtemp()
    path = os.path.join(tmpdir, "bench_async.ahp")

    async def _run():
        writer = AsyncChainWriter(path)
        await writer.start()
        start = time.time()
        for i in range(n):
            await writer.write_record(_make_payload(i))
        await writer.stop()
        elapsed = time.time() - start
        return elapsed

    elapsed = asyncio.get_event_loop().run_until_complete(_run())
    records_sec = n / elapsed
    file_size = Path(path).stat().st_size
    mb = file_size / (1024 * 1024)
    print(f"  Async write:      {records_sec:,.0f} records/sec  ({mb:.1f} MB for {n} records)")


def bench_verify(n: int = 10000) -> None:
    """Benchmark chain verification speed."""
    tmpdir = tempfile.mkdtemp()
    path = os.path.join(tmpdir, "bench_verify.ahp")

    writer = ChainWriter(path)
    for i in range(n):
        writer.write_record(_make_payload(i))
    writer.close()

    start = time.time()
    result = verify_chain(path)
    elapsed = time.time() - start

    records_sec = n / elapsed
    print(f"  Verification:     {records_sec:,.0f} records/sec  ({elapsed:.3f}s for {n} records, valid={result.valid})")


def bench_read_iter(n: int = 10000) -> None:
    """Benchmark streaming read speed."""
    tmpdir = tempfile.mkdtemp()
    path = os.path.join(tmpdir, "bench_read.ahp")

    writer = ChainWriter(path)
    for i in range(n):
        writer.write_record(_make_payload(i))
    writer.close()

    start = time.time()
    reader = ChainReader(path)
    count = sum(1 for _ in reader.iter_records())
    elapsed = time.time() - start

    records_sec = n / elapsed
    print(f"  Streaming read:   {records_sec:,.0f} records/sec  ({elapsed:.3f}s for {count} records)")


def bench_record_size() -> None:
    """Measure record sizes for different types."""
    from ahp.core.records import BootPayload, GapPayload, CheckpointPayload
    from ahp.core.records import AuthorizationEntry
    from ahp.core.types import AuthorizerType, AuthorizationDecision

    payloads = {
        "ActionPayload (AUTH_NONE)": _make_payload(0),
        "ActionPayload (AUTH_HUMAN)": ActionPayload(
            tool_name="process_refund",
            result_status=ResultStatus.SUCCESS,
            protocol=Protocol.MCP,
            action_type=ActionType.TOOL_CALL,
            authorization=Authorization(
                type=AuthorizationType.AUTH_HUMAN,
                entries=[AuthorizationEntry(
                    authorizer_type=AuthorizerType.AUTHORIZER_HUMAN,
                    authorizer_id="user:operator",
                    decision=AuthorizationDecision.APPROVED,
                    timestamp_ms=int(time.time() * 1000),
                )],
            ),
        ),
        "BootPayload": BootPayload(agent_name="bench-agent"),
        "GapPayload": GapPayload(first_lost_sequence=5, last_lost_sequence=10, count=6, reason=1),
        "CheckpointPayload": CheckpointPayload(record_count=1000),
    }

    print("  Record sizes:")
    for name, payload in payloads.items():
        record = Record(
            record_id=uuid7(), agent_id=uuid7(), session_id=uuid7(),
            timestamp_ms=int(time.time() * 1000), sequence=1,
            prev_hash=ZERO_HASH_32, schema_version=SCHEMA_VERSION,
            record_type=RecordType.ACTION if isinstance(payload, ActionPayload) else RecordType.BOOT,
            payload=payload,
        )
        size = len(canonical_bytes(record))
        print(f"    {name}: {size} bytes")


def main():
    n = 10000
    if len(sys.argv) > 1:
        n = int(sys.argv[1])

    print(f"\nAHP Performance Benchmarks ({n} records)\n")
    print("=" * 60)

    bench_record_size()
    print()
    bench_serialization(n)
    bench_sync_write(n)
    bench_async_write(n)
    bench_read_iter(n)
    bench_verify(n)

    print()
    print("=" * 60)
    print()


if __name__ == '__main__':
    main()

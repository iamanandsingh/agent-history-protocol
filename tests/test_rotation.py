"""Comprehensive tests for chain rotation (AHPRecorder._check_rotation()).

AHPRecorder rotates the active chain file when bytes_written exceeds
DEFAULT_MAX_SEGMENT_BYTES (64 MiB).  The old file is renamed to
``<path>.<unix_ts>.segment`` and a fresh chain is created at the original
path, preserving the hash-chain link via ``prev_hash`` and
``start_sequence``.
"""

from __future__ import annotations

import hashlib
import os
import tempfile
import time
import unittest
from pathlib import Path

from ahp.core.chain import ChainReader, parse_envelope
from ahp.core.signing import HAS_CRYPTO
from ahp.core.types import RecordType
from ahp.core.verify import verify_chain
from ahp.recorder import DEFAULT_MAX_SEGMENT_BYTES, AHPRecorder


def _verify_internal_chain(path: str) -> tuple:
    """Verify the internal hash chain of a segment file without requiring a
    zero-byte genesis prev_hash.  Returns (ok: bool, error: str|None).

    This is needed for continuation segments created by rotation, whose first
    record intentionally carries the previous segment's tail hash rather than
    the all-zeros genesis marker.
    """
    records = ChainReader(path).read_all()
    if not records:
        return True, None
    for i in range(1, len(records)):
        env = parse_envelope(records[i])
        expected = hashlib.sha256(records[i - 1]).digest()
        if env["prev_hash"] != expected:
            return False, f"Hash chain broken at record index {i}"
    return True, None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_recorder(tmpdir: str, name: str = "test.ahp", **kwargs) -> tuple:
    chain_path = os.path.join(tmpdir, name)
    recorder = AHPRecorder(
        agent_name="rotation-test",
        chain_path=chain_path,
        level=1,
        checkpoint_interval=99999,
        **kwargs,
    )
    return recorder, chain_path


def _record_n(recorder: AHPRecorder, n: int) -> None:
    for i in range(n):
        recorder.record_action(
            tool_name=f"tool_{i}",
            parameters=b'{"x": 1}',
            result=b'{"ok": true}',
        )


def _force_rotation(recorder: AHPRecorder) -> None:
    """Trigger exactly one rotation by setting the limit to the current file
    size, writing one record, then resetting the limit to 64 MiB so subsequent
    writes don't immediately re-rotate."""
    recorder._max_segment_bytes = recorder._chain.bytes_written
    recorder.record_action(tool_name="force_rotate", parameters=b"r", result=b"r")
    recorder._max_segment_bytes = DEFAULT_MAX_SEGMENT_BYTES


def _find_segments(tmpdir: str, base: str = "test.ahp") -> list:
    return sorted(Path(tmpdir).glob(f"{base}.*.segment"))


# ---------------------------------------------------------------------------
# Basic rotation: file management
# ---------------------------------------------------------------------------


class TestRotationBasic(unittest.TestCase):
    """Rotation creates a .segment file and continues at the original path."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def test_no_rotation_below_limit(self):
        """No segment files when chain stays below the size limit."""
        recorder, chain_path = _make_recorder(self.tmpdir)
        _record_n(recorder, 10)
        recorder.close()

        self.assertEqual(len(_find_segments(self.tmpdir)), 0)

    def test_rotation_creates_segment_file(self):
        """A .segment file appears once rotation fires."""
        recorder, chain_path = _make_recorder(self.tmpdir)
        _record_n(recorder, 5)
        _force_rotation(recorder)
        recorder.close()

        self.assertGreater(len(_find_segments(self.tmpdir)), 0)

    def test_segment_file_name_pattern(self):
        """Segment file name matches ``<base>.<unix_timestamp>.segment``."""
        recorder, chain_path = _make_recorder(self.tmpdir)
        _record_n(recorder, 3)
        _force_rotation(recorder)
        recorder.close()

        segments = _find_segments(self.tmpdir)
        self.assertEqual(len(segments), 1)
        self.assertRegex(segments[0].name, r"test\.ahp\.\d+\.segment")

    def test_original_path_still_exists_after_rotation(self):
        """New active chain exists at the original path after rotation."""
        recorder, chain_path = _make_recorder(self.tmpdir)
        _record_n(recorder, 3)
        _force_rotation(recorder)
        recorder.close()

        self.assertTrue(
            Path(chain_path).exists(),
            "Original chain_path must still exist after rotation",
        )

    def test_default_limit_is_64mib(self):
        """Default max_segment_bytes is exactly 64 MiB."""
        recorder, chain_path = _make_recorder(self.tmpdir)
        self.assertEqual(recorder._max_segment_bytes, 64 * 1024 * 1024)
        recorder.close()


# ---------------------------------------------------------------------------
# Hash-chain continuity across the rotation boundary
# ---------------------------------------------------------------------------


class TestRotationChainContinuity(unittest.TestCase):
    """The hash chain must be unbroken at a rotation boundary."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def test_new_segment_prev_hash_links_to_old_segment_last_record(self):
        """New segment's first record prev_hash == SHA-256 of old segment's last record."""
        recorder, chain_path = _make_recorder(self.tmpdir)
        _record_n(recorder, 5)
        _force_rotation(recorder)
        recorder.close()

        segments = _find_segments(self.tmpdir)
        self.assertEqual(len(segments), 1)

        old_records = ChainReader(segments[0]).read_all()
        expected_link = hashlib.sha256(old_records[-1]).digest()

        new_records = ChainReader(chain_path).read_all()
        first_env = parse_envelope(new_records[0])

        self.assertEqual(
            expected_link,
            first_env["prev_hash"],
            "New segment must link via prev_hash to old segment's last record",
        )

    def test_sequence_numbers_continue_across_rotation(self):
        """Sequence numbers in the new segment follow on from the old segment."""
        recorder, chain_path = _make_recorder(self.tmpdir)
        _record_n(recorder, 5)
        _force_rotation(recorder)
        _record_n(recorder, 3)
        recorder.close()

        segments = _find_segments(self.tmpdir)
        old_records = ChainReader(segments[0]).read_all()
        last_old_seq = parse_envelope(old_records[-1])["sequence"]

        new_records = ChainReader(chain_path).read_all()
        first_new_seq = parse_envelope(new_records[0])["sequence"]

        self.assertGreater(
            first_new_seq,
            last_old_seq,
            "First sequence in new segment must exceed last sequence in old segment",
        )

    def test_old_segment_passes_verification(self):
        """The rotated-away segment file is a valid standalone chain."""
        recorder, chain_path = _make_recorder(self.tmpdir)
        _record_n(recorder, 5)
        _force_rotation(recorder)
        recorder.close()

        segments = _find_segments(self.tmpdir)
        result = verify_chain(str(segments[0]))
        self.assertTrue(result.valid, f"Old segment invalid: {result.error}")

    def test_new_segment_internal_chain_is_consistent(self):
        """The new active chain after rotation has a consistent internal hash chain.

        Note: verify_chain() is not used here because it requires a zero-byte
        genesis prev_hash, which rotation segments intentionally do not have —
        they carry the previous segment's tail hash for cross-segment continuity.
        """
        recorder, chain_path = _make_recorder(self.tmpdir)
        _record_n(recorder, 5)
        _force_rotation(recorder)
        _record_n(recorder, 3)
        recorder.close()

        ok, error = _verify_internal_chain(chain_path)
        self.assertTrue(ok, f"New segment internal chain invalid: {error}")

    def test_records_written_before_rotation_are_preserved(self):
        """Records written before rotation are intact in the segment file."""
        recorder, chain_path = _make_recorder(self.tmpdir)
        _record_n(recorder, 8)
        _force_rotation(recorder)
        recorder.close()

        segments = _find_segments(self.tmpdir)
        count = ChainReader(segments[0]).count()
        # Boot record + 8 action records + rotation-trigger record = 10 minimum
        self.assertGreaterEqual(count, 9)


# ---------------------------------------------------------------------------
# Genesis records in the new segment
# ---------------------------------------------------------------------------


class TestRotationGenesisRecords(unittest.TestCase):
    """New segment re-emits genesis records (BOOT and optionally KEY_GENESIS)."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def test_new_segment_starts_with_boot_record(self):
        """First record in the new segment is a BOOT record."""
        recorder, chain_path = _make_recorder(self.tmpdir)
        _record_n(recorder, 3)
        _force_rotation(recorder)
        recorder.close()

        new_records = ChainReader(chain_path).read_all()
        first_type = parse_envelope(new_records[0])["record_type"]
        self.assertEqual(first_type, RecordType.BOOT)

    def test_level1_new_segment_has_no_key_genesis(self):
        """Level-1 recorder does not emit KEY_GENESIS in new segment."""
        recorder, chain_path = _make_recorder(self.tmpdir)
        _record_n(recorder, 3)
        _force_rotation(recorder)
        recorder.close()

        new_records = ChainReader(chain_path).read_all()
        types = [parse_envelope(r)["record_type"] for r in new_records]
        self.assertNotIn(RecordType.KEY, types)

    @unittest.skipUnless(HAS_CRYPTO, "cryptography library not installed")
    def test_level2_new_segment_has_key_genesis(self):
        """Level-2 recorder emits a KEY record after rotation."""
        chain_path = os.path.join(self.tmpdir, "l2.ahp")
        recorder = AHPRecorder(
            agent_name="rotation-l2",
            chain_path=chain_path,
            level=2,
            checkpoint_interval=99999,
        )
        _record_n(recorder, 3)
        _force_rotation(recorder)
        recorder.close()

        new_records = ChainReader(chain_path).read_all()
        types = [parse_envelope(r)["record_type"] for r in new_records]
        self.assertIn(RecordType.KEY, types)


# ---------------------------------------------------------------------------
# Multiple rotations
# ---------------------------------------------------------------------------


class TestRotationMultiple(unittest.TestCase):
    """Multiple consecutive rotations produce multiple segment files."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def _do_two_rotations(self) -> tuple:
        recorder, chain_path = _make_recorder(self.tmpdir)
        _record_n(recorder, 4)
        _force_rotation(recorder)
        # Ensure a different Unix second so segment names don't collide
        time.sleep(1.1)
        _record_n(recorder, 3)
        _force_rotation(recorder)
        _record_n(recorder, 2)
        return recorder, chain_path

    def test_two_rotations_produce_two_segment_files(self):
        """Two rotations with distinct timestamps → exactly two .segment files."""
        recorder, chain_path = self._do_two_rotations()
        recorder.close()

        segments = _find_segments(self.tmpdir)
        self.assertEqual(
            len(segments),
            2,
            f"Expected 2 segments, got {[s.name for s in segments]}",
        )

    def test_all_segments_internally_valid(self):
        """Every segment file and the active chain have a consistent internal hash chain.

        The first segment (original chain) also passes the stricter verify_chain()
        zero-genesis check.  Continuation segments use _verify_internal_chain()
        because they intentionally start with a non-zero prev_hash.
        """
        recorder, chain_path = self._do_two_rotations()
        recorder.close()

        segments = _find_segments(self.tmpdir)
        # First segment is the original chain → verify_chain applies
        result = verify_chain(str(segments[0]))
        self.assertTrue(result.valid, f"First segment invalid: {result.error}")

        # Subsequent segments are continuations → use internal check
        for seg in segments[1:]:
            ok, error = _verify_internal_chain(str(seg))
            self.assertTrue(ok, f"Segment {seg.name} internal chain invalid: {error}")

        ok, error = _verify_internal_chain(chain_path)
        self.assertTrue(ok, f"Active chain internal chain invalid: {error}")

    def test_sequences_monotone_across_all_segments(self):
        """All sequence numbers are strictly increasing across every segment."""
        recorder, chain_path = self._do_two_rotations()
        recorder.close()

        all_seqs: list = []
        for seg in _find_segments(self.tmpdir):
            for stored in ChainReader(str(seg)).iter_records():
                all_seqs.append(parse_envelope(stored)["sequence"])
        for stored in ChainReader(chain_path).iter_records():
            all_seqs.append(parse_envelope(stored)["sequence"])

        for i in range(1, len(all_seqs)):
            self.assertGreater(
                all_seqs[i],
                all_seqs[i - 1],
                f"Sequence not monotone at index {i}: {all_seqs[i - 1]} → {all_seqs[i]}",
            )

    def test_hash_chain_links_all_segments_in_order(self):
        """Each segment's last-record hash == next segment's first-record prev_hash."""
        recorder, chain_path = self._do_two_rotations()
        recorder.close()

        segments = _find_segments(self.tmpdir)
        all_paths = [str(s) for s in segments] + [chain_path]

        for i in range(len(all_paths) - 1):
            old_records = ChainReader(all_paths[i]).read_all()
            link_hash = hashlib.sha256(old_records[-1]).digest()

            new_records = ChainReader(all_paths[i + 1]).read_all()
            next_prev = parse_envelope(new_records[0])["prev_hash"]

            self.assertEqual(
                link_hash,
                next_prev,
                f"Hash chain broken between {all_paths[i]} and {all_paths[i + 1]}",
            )


# ---------------------------------------------------------------------------
# Fail-open: recorder remains functional through rotation
# ---------------------------------------------------------------------------


class TestRotationFailOpen(unittest.TestCase):
    """Recorder continues accepting records after rotation (fail-open design)."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def test_recorder_accepts_records_after_rotation(self):
        """record_action() succeeds both before and after a rotation."""
        recorder, chain_path = _make_recorder(self.tmpdir)
        _record_n(recorder, 5)
        _force_rotation(recorder)
        _record_n(recorder, 5)  # must not raise
        recorder.close()

        ok, error = _verify_internal_chain(chain_path)
        self.assertTrue(ok, f"Chain invalid after rotation: {error}")

    def test_new_segment_bytes_tracked_from_new_baseline(self):
        """After rotation, bytes_written reflects the new (smaller) segment."""
        recorder, chain_path = _make_recorder(self.tmpdir)
        _record_n(recorder, 10)
        old_bytes = recorder._chain.bytes_written
        _force_rotation(recorder)
        new_bytes = recorder._chain.bytes_written

        self.assertLess(
            new_bytes,
            old_bytes,
            "New segment bytes_written should be less than the old chain's total",
        )

    def test_bytes_written_matches_file_size_after_rotation(self):
        """bytes_written matches actual on-disk file size after rotation."""
        recorder, chain_path = _make_recorder(self.tmpdir)
        _record_n(recorder, 5)
        _force_rotation(recorder)
        _record_n(recorder, 3)

        recorder._chain._data_file.flush()
        actual_size = Path(chain_path).stat().st_size
        self.assertEqual(recorder._chain.bytes_written, actual_size)
        recorder.close()


# ---------------------------------------------------------------------------
# Size tracking accuracy
# ---------------------------------------------------------------------------


class TestRotationSizeTracking(unittest.TestCase):
    """bytes_written accurately reflects chain growth for rotation decisions."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def test_bytes_written_grows_with_each_record(self):
        """bytes_written strictly increases after each record write."""
        recorder, chain_path = _make_recorder(self.tmpdir)
        sizes = [recorder._chain.bytes_written]
        for i in range(5):
            recorder.record_action(tool_name=f"t{i}", parameters=b"p", result=b"r")
            sizes.append(recorder._chain.bytes_written)

        for i in range(1, len(sizes)):
            self.assertGreater(sizes[i], sizes[i - 1])
        recorder.close()

    def test_bytes_written_matches_file_size_before_rotation(self):
        """bytes_written matches the flushed file size before any rotation."""
        recorder, chain_path = _make_recorder(self.tmpdir)
        _record_n(recorder, 8)
        recorder._chain._data_file.flush()
        actual = Path(chain_path).stat().st_size
        self.assertEqual(recorder._chain.bytes_written, actual)
        recorder.close()


if __name__ == "__main__":
    unittest.main()

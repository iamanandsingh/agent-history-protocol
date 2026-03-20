"""Tests for witness auto-flow through AHPRecorder."""

from __future__ import annotations

import os
import tempfile
import threading
import time
import unittest
from http.server import HTTPServer
from pathlib import Path

from ahp.core.verify import verify_chain


class TestWitnessAutoFlow(unittest.TestCase):
    """Witness integration through AHPRecorder auto-checkpoint."""

    def test_recorder_sends_to_witness(self):
        """Recorder with level=3 auto-sends checkpoints to the witness."""
        from witness.server import WitnessHandler, _load_receipts

        server = HTTPServer(("localhost", 0), WitnessHandler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        receipts_file = "witness_receipts.json"
        try:
            Path(receipts_file).unlink()
        except (FileNotFoundError, PermissionError):
            pass

        try:
            tmpdir = tempfile.mkdtemp()
            chain_path = os.path.join(tmpdir, "witness_flow.ahp")

            from ahp.recorder import AHPRecorder

            recorder = AHPRecorder(
                agent_name="witness-test",
                chain_path=chain_path,
                level=3,
                witness_endpoints=[f"http://localhost:{port}"],
                checkpoint_interval=3,
                witness_interval=3,
            )

            for i in range(5):
                recorder.record_action(
                    tool_name=f"tool_{i}",
                    parameters=f"params_{i}".encode(),
                    result=f"result_{i}".encode(),
                )

            time.sleep(0.5)
            receipts = _load_receipts()
            witness_count = len(receipts.get("receipts", []))

            self.assertGreater(
                witness_count,
                0,
                "Witness should have received at least one checkpoint",
            )

            self.assertTrue(verify_chain(chain_path).valid)

        finally:
            server.shutdown()
            try:
                if Path(receipts_file).exists():
                    Path(receipts_file).unlink()
            except (FileNotFoundError, PermissionError):
                pass


if __name__ == "__main__":
    unittest.main()

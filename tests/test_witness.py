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

    def test_witness_payload_carries_real_signature(self):
        """The WitnessPayload recorded in the chain must contain the
        witness's actual signature + public key, not zero bytes. A
        previous bug read the wrong receipt keys (``signature`` /
        ``public_key`` / ``timestamp_ms`` instead of
        ``witness_signature`` / ``witness_public_key`` /
        ``witness_timestamp``), so every chain had unsigned witness
        receipts — Level 3 attestation was effectively disabled.
        """
        import json as _json
        from urllib.request import urlopen

        from ahp.core.chain import ChainReader, parse_envelope, parse_witness_payload
        from ahp.core.signing import verify_signature
        from ahp.core.types import ZERO_HASH_32, RecordType
        from witness.server import WitnessHandler

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
            chain_path = os.path.join(tmpdir, "witness_sig.ahp")

            from ahp.recorder import AHPRecorder

            recorder = AHPRecorder(
                agent_name="witness-sig-test",
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
            recorder.close()

            # Find any WitnessPayload records in the chain.
            reader = ChainReader(chain_path)
            witness_records = []
            for stored in reader.iter_records():
                env = parse_envelope(stored)
                if env["record_type"] == RecordType.WITNESS:
                    wp = parse_witness_payload(env["payload_bytes"])
                    witness_records.append((env, wp))

            self.assertGreater(
                len(witness_records),
                0,
                "recorder did not emit any WitnessPayload to the chain",
            )
            env, wp = witness_records[0]

            # The headline regression: neither field may be zeroed.
            self.assertNotEqual(
                wp["receipt_signature"],
                b"\x00" * 64,
                "receipt_signature is all zeros — client misread the receipt field name",
            )
            self.assertNotEqual(
                wp["witness_public_key"],
                ZERO_HASH_32,
                "witness_public_key is all zeros — client misread the receipt field name",
            )

            # The recorded witness_public_key must match the witness's
            # published identity.
            with urlopen(f"http://localhost:{port}/ahp/v1/identity") as resp:
                identity = _json.loads(resp.read())
            self.assertEqual(
                wp["witness_public_key"],
                bytes.fromhex(identity["public_key"]),
                "witness_public_key in chain disagrees with witness's published identity",
            )

            # And the signature must actually verify against the canonical
            # blob the witness signs: {agent_id, chain_hash, sequence,
            # witness_timestamp}, sort_keys=True with compact separators
            # per spec §8.1.
            sign_data = _json.dumps(
                {
                    "agent_id": env["agent_id"].hex(),
                    "chain_hash": wp["checkpoint_hash"].hex(),
                    "sequence": wp["checkpoint_seq"],
                    "witness_timestamp": wp["witness_timestamp"],
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
            self.assertTrue(
                verify_signature(sign_data, wp["receipt_signature"], wp["witness_public_key"]),
                "witness signature in chain does not verify against the canonical signed blob",
            )

        finally:
            server.shutdown()
            try:
                if Path(receipts_file).exists():
                    Path(receipts_file).unlink()
            except (FileNotFoundError, PermissionError):
                pass


if __name__ == "__main__":
    unittest.main()

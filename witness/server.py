"""Reference AHP witness server — Section 8.1 + Appendix G.

Minimal implementation using stdlib only. No external dependencies.
Storage: JSON file (for simplicity, not SQLite).
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import TYPE_CHECKING, Dict, Optional

if TYPE_CHECKING:
    from ahp.core.signing import KeyPair

logger = logging.getLogger(__name__)

# Generate witness identity on startup
witness_keys: Optional[KeyPair] = None
try:
    from ahp.core.signing import generate_keypair, sign, verify_signature

    witness_keys = generate_keypair()
    _has_crypto = True
except ImportError:
    _has_crypto = False
    logger.warning("Crypto not available — witness will not verify client signatures")

WITNESS_ID = "ahp-reference-witness"
RECEIPTS_FILE = os.environ.get(
    "WITNESS_RECEIPTS_FILE",
    str(Path(__file__).parent / "witness_receipts.json"),
)
MAX_REQUEST_SIZE = 1_048_576  # 1 MB
MAX_RECEIPTS = 10_000  # rotate storage file after this many receipts
_receipts_lock = threading.Lock()
# In-memory index for O(1) duplicate receipt lookup; keyed by (agent_id, sequence).
_receipt_index: Dict[tuple, Dict] = {}


def _load_receipts() -> Dict:
    if os.path.exists(RECEIPTS_FILE):
        with open(RECEIPTS_FILE) as f:
            return json.load(f)
    return {"receipts": []}


def _save_receipts(data: Dict) -> None:
    """Atomic write: write to temp file then rename to prevent corruption."""
    dir_name = os.path.dirname(os.path.abspath(RECEIPTS_FILE))
    fd, tmp_path = tempfile.mkstemp(dir=dir_name, suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp_path, RECEIPTS_FILE)
    except Exception:
        # Clean up temp file on failure
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def _rotate_receipts_file() -> None:
    """Rename the current receipts file to a timestamped archive and start fresh."""
    if os.path.exists(RECEIPTS_FILE):
        archive = RECEIPTS_FILE.replace(".json", f".{int(time.time() * 1000)}.json")
        try:
            os.replace(RECEIPTS_FILE, archive)
            logger.info("Receipts file rotated to %s", archive)
        except OSError as e:
            logger.error("Failed to rotate receipts file: %s", e)
            raise


def _find_existing_receipt(agent_id: str, sequence: int) -> Optional[Dict]:
    """O(1) duplicate (agent_id, sequence) lookup via in-memory index."""
    return _receipt_index.get((agent_id, sequence))


def _init_receipt_index() -> None:
    """Build the in-memory dedup index from on-disk receipts (called at startup)."""
    global _receipt_index
    try:
        data = _load_receipts()
        _receipt_index = {(r.get("agent_id"), r.get("sequence")): r for r in data["receipts"]}
    except Exception as e:
        logger.warning("Failed to initialize receipt index: %s", e)
        _receipt_index = {}


_init_receipt_index()


def _verify_client_signature(body: dict) -> bool:
    """Verify the Ed25519 signature over checkpoint data if crypto is available.

    Returns True if signature is valid or if crypto is unavailable (graceful degradation).
    The request body must include 'public_key' (hex-encoded Ed25519 public key) for
    verification. 'signing_key_id' is a hash of the key and cannot be used for verification.
    """
    signature_hex = body.get("signature")
    public_key_hex = body.get("public_key")

    if not signature_hex:
        # No signature provided — allow for backwards compatibility
        return True

    if not public_key_hex:
        logger.warning("Checkpoint has signature but no public_key field — rejecting as possible tamper attempt.")
        return False

    if not _has_crypto:
        logger.warning(
            "Signature verification unavailable (no crypto support). Accepting checkpoint without verification."
        )
        return True

    try:
        # Reconstruct the signed data (canonical checkpoint fields)
        sign_data = json.dumps(
            {
                "agent_id": body.get("agent_id"),
                "chain_hash": body.get("chain_hash"),
                "sequence": body.get("sequence"),
                "timestamp_ms": body.get("timestamp_ms"),
            },
            sort_keys=True,
        ).encode()

        signature = bytes.fromhex(signature_hex)
        public_key = bytes.fromhex(public_key_hex)
        if not verify_signature(sign_data, signature, public_key):
            logger.warning("Signature verification returned False")
            return False
        return True
    except Exception as e:
        logger.warning("Signature verification failed: %s", e)
        return False


class WitnessHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == "/ahp/v1/checkpoints":
            # Check request size limit
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length < 0 or content_length > MAX_REQUEST_SIZE:
                self.send_error(413, "Request body too large")
                return

            try:
                body = json.loads(self.rfile.read(content_length))
            except (json.JSONDecodeError, ValueError):
                self.send_error(400, "Invalid JSON")
                return

            # Validate required fields
            agent_id = body.get("agent_id")
            sequence = body.get("sequence")
            if not isinstance(agent_id, str) or not agent_id:
                self.send_error(400, "agent_id must be a non-empty string")
                return
            if not isinstance(sequence, int) or isinstance(sequence, bool):
                self.send_error(400, "sequence must be an integer")
                return

            # Verify client signature if provided
            if not _verify_client_signature(body):
                self.send_error(403, "Invalid signature")
                return

            with _receipts_lock:
                # Check in-memory index first (avoids disk I/O on fast path)
                existing = _find_existing_receipt(agent_id, sequence)
                if existing is not None:
                    response = json.dumps(existing).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(response)))
                    self.end_headers()
                    self.wfile.write(response)
                    return

                receipt_id = os.urandom(16).hex()
                witness_timestamp = int(time.time() * 1000)

                # Sign the checkpoint + witness timestamp
                sign_data = json.dumps(
                    {
                        "agent_id": agent_id,
                        "chain_hash": body.get("chain_hash"),
                        "sequence": sequence,
                        "witness_timestamp": witness_timestamp,
                    },
                    sort_keys=True,
                ).encode()

                if witness_keys:
                    witness_sig = sign(sign_data, witness_keys.private_key_bytes).hex()
                    witness_pub = witness_keys.public_key_bytes.hex()
                else:
                    witness_sig = "00" * 64
                    witness_pub = "00" * 32

                receipt = {
                    "receipt_id": receipt_id,
                    "witness_id": WITNESS_ID,
                    "witness_timestamp": witness_timestamp,
                    "witness_signature": witness_sig,
                    "witness_public_key": witness_pub,
                    "agent_id": agent_id,
                    "chain_hash": body.get("chain_hash"),
                    "sequence": sequence,
                    "timestamp_ms": body.get("timestamp_ms"),
                }

                # Load from disk only when we need to append
                data = _load_receipts()

                # Rotate if at the size cap before appending
                if len(data["receipts"]) >= MAX_RECEIPTS:
                    _rotate_receipts_file()
                    data = {"receipts": []}
                    _receipt_index.clear()

                data["receipts"].append(receipt)
                _save_receipts(data)
                _receipt_index[(agent_id, sequence)] = receipt

            response = json.dumps(receipt).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(response)
        else:
            self.send_error(404)

    def do_GET(self):
        if self.path == "/health":
            response = json.dumps({"status": "ok"}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(response)
        elif self.path == "/ahp/v1/identity":
            identity = {
                "witness_id": WITNESS_ID,
                "public_key": witness_keys.public_key_bytes.hex() if witness_keys else "00" * 32,
            }
            response = json.dumps(identity).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(response)
        elif self.path.startswith("/ahp/v1/receipts/"):
            receipt_id = self.path.split("/")[-1]
            data = _load_receipts()
            for r in data["receipts"]:
                if r["receipt_id"] == receipt_id:
                    response = json.dumps(r).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(response)))
                    self.end_headers()
                    self.wfile.write(response)
                    return
            self.send_error(404)
        elif self.path.startswith("/ahp/v1/agents/"):
            parts = self.path.split("/")
            agent_id = parts[4] if len(parts) > 4 else ""
            data = _load_receipts()
            agent_receipts = [r for r in data["receipts"] if r.get("agent_id") == agent_id]
            response = json.dumps(agent_receipts).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(response)
        else:
            self.send_error(404)

    def log_message(self, format, *args):
        print("[witness] " + (format % args))


def main(port: int = 8120):
    server = HTTPServer(("localhost", port), WitnessHandler)
    print("AHP Reference Witness Server running on http://localhost:%d" % port)
    print("Witness ID: %s" % WITNESS_ID)
    if witness_keys:
        print("Public key: %s..." % witness_keys.public_key_bytes.hex()[:16])
    print("Endpoints:")
    print("  POST /ahp/v1/checkpoints")
    print("  GET  /ahp/v1/receipts/{id}")
    print("  GET  /ahp/v1/identity")
    print("  GET  /health")
    print()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nWitness server stopped.")


if __name__ == "__main__":
    import sys

    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8120
    main(port)

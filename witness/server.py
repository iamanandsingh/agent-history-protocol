"""Reference AHP witness server — Section 8.1 + Appendix G.

Minimal implementation using stdlib only. No external dependencies.
Storage: JSON file (for simplicity, not SQLite).
"""
from __future__ import annotations
import hashlib
import json
import os
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Dict, Optional

# Generate witness identity on startup
try:
    from ahp.core.signing import generate_keypair, sign
    witness_keys = generate_keypair()
except Exception:
    witness_keys = None

WITNESS_ID = "ahp-reference-witness"
RECEIPTS_FILE = "witness_receipts.json"


def _load_receipts() -> Dict:
    if os.path.exists(RECEIPTS_FILE):
        with open(RECEIPTS_FILE) as f:
            return json.load(f)
    return {"receipts": []}


def _save_receipts(data: Dict) -> None:
    with open(RECEIPTS_FILE, 'w') as f:
        json.dump(data, f, indent=2)


class WitnessHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == '/ahp/v1/checkpoints':
            content_length = int(self.headers.get('Content-Length', 0))
            body = json.loads(self.rfile.read(content_length))

            receipt_id = os.urandom(16).hex()
            witness_timestamp = int(time.time() * 1000)

            # Sign the checkpoint + witness timestamp
            sign_data = json.dumps({
                'agent_id': body.get('agent_id'),
                'chain_hash': body.get('chain_hash'),
                'sequence': body.get('sequence'),
                'witness_timestamp': witness_timestamp,
            }, sort_keys=True).encode()

            if witness_keys:
                witness_sig = sign(sign_data, witness_keys.private_key_bytes).hex()
                witness_pub = witness_keys.public_key_bytes.hex()
            else:
                witness_sig = '00' * 64
                witness_pub = '00' * 32

            receipt = {
                'receipt_id': receipt_id,
                'witness_id': WITNESS_ID,
                'witness_timestamp': witness_timestamp,
                'witness_signature': witness_sig,
                'witness_public_key': witness_pub,
                'agent_id': body.get('agent_id'),
                'chain_hash': body.get('chain_hash'),
                'sequence': body.get('sequence'),
                'timestamp_ms': body.get('timestamp_ms'),
            }

            data = _load_receipts()
            data['receipts'].append(receipt)
            _save_receipts(data)

            response = json.dumps(receipt).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(response)))
            self.end_headers()
            self.wfile.write(response)
        else:
            self.send_error(404)

    def do_GET(self):
        if self.path == '/ahp/v1/identity':
            identity = {
                'witness_id': WITNESS_ID,
                'public_key': witness_keys.public_key_bytes.hex() if witness_keys else '00' * 32,
            }
            response = json.dumps(identity).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(response)))
            self.end_headers()
            self.wfile.write(response)
        elif self.path.startswith('/ahp/v1/receipts/'):
            receipt_id = self.path.split('/')[-1]
            data = _load_receipts()
            for r in data['receipts']:
                if r['receipt_id'] == receipt_id:
                    response = json.dumps(r).encode()
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.send_header('Content-Length', str(len(response)))
                    self.end_headers()
                    self.wfile.write(response)
                    return
            self.send_error(404)
        elif self.path.startswith('/ahp/v1/agents/'):
            parts = self.path.split('/')
            agent_id = parts[4] if len(parts) > 4 else ''
            data = _load_receipts()
            agent_receipts = [r for r in data['receipts'] if r.get('agent_id') == agent_id]
            response = json.dumps(agent_receipts).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(response)))
            self.end_headers()
            self.wfile.write(response)
        else:
            self.send_error(404)

    def log_message(self, format, *args):
        print("[witness] %s" % (args[0],))


def main(port: int = 8120):
    server = HTTPServer(('localhost', port), WitnessHandler)
    print("AHP Reference Witness Server running on http://localhost:%d" % port)
    print("Witness ID: %s" % WITNESS_ID)
    if witness_keys:
        print("Public key: %s..." % witness_keys.public_key_bytes.hex()[:16])
    print("Endpoints:")
    print("  POST /ahp/v1/checkpoints")
    print("  GET  /ahp/v1/receipts/{id}")
    print("  GET  /ahp/v1/identity")
    print()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nWitness server stopped.")


if __name__ == '__main__':
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8120
    main(port)

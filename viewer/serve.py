#!/usr/bin/env python3
"""AHP Chain Viewer — visual inspector for AHP chain files.

Usage:
    python viewer/serve.py                          # open viewer on localhost:8080
    python viewer/serve.py 3000                     # custom port
    python viewer/serve.py --chain path/to/file.ahp # auto-load a chain file

Opens a browser with the viewer. Drag & drop any .ahp chain file to inspect it,
or pass --chain to auto-load one.
"""
from __future__ import annotations

import http.server
import json
import os
import shutil
import sys
import webbrowser
from pathlib import Path

VIEWER_DIR = os.path.dirname(os.path.abspath(__file__))


class ViewerHandler(http.server.SimpleHTTPRequestHandler):
    """Serves the viewer HTML + handles chain file uploads via POST."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=VIEWER_DIR, **kwargs)

    def do_POST(self):
        """Accept chain file uploads from the viewer."""
        if self.path == '/api/chain':
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length)
            # Save uploaded chain to temp location
            upload_path = os.path.join(VIEWER_DIR, '_uploaded_chain.ahp')
            with open(upload_path, 'wb') as f:
                f.write(body)
            self._json_response(200, {"status": "ok", "path": upload_path})
        else:
            self.send_error(404)

    def _json_response(self, code: int, data: dict) -> None:
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        print(f"[viewer] {args[0]}")


def main():
    port = 8080
    chain_path = None

    # Parse args
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == '--chain' and i + 1 < len(args):
            chain_path = args[i + 1]
            i += 2
        elif args[i].isdigit():
            port = int(args[i])
            i += 1
        else:
            i += 1

    # If --chain specified, copy to viewer dir for easy loading
    if chain_path:
        src = Path(chain_path).resolve()
        dst = (Path(VIEWER_DIR) / 'demo-chain.ahp').resolve()
        if not src.exists():
            print(f"Warning: chain file not found: {chain_path}")
        elif src != dst:
            shutil.copy2(str(src), str(dst))
            print(f"Loaded chain: {chain_path}")
        else:
            print(f"Chain already in viewer: {chain_path}")

    server = http.server.HTTPServer(("localhost", port), ViewerHandler)
    url = f"http://localhost:{port}/index.html"

    print(f"\nAHP Chain Viewer")
    print(f"  URL:    {url}")
    print(f"  Viewer: {VIEWER_DIR}")
    if chain_path:
        print(f"  Chain:  {chain_path} (pre-loaded as demo-chain.ahp)")
    print(f"\n  Drag & drop any .ahp file onto the viewer to inspect it.")
    print(f"  Press Ctrl+C to stop.\n")

    webbrowser.open(url)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nViewer stopped.")


if __name__ == "__main__":
    main()

"""Real MCP-compatible JSON-RPC tool server.

Hosts tools over HTTP using JSON-RPC 2.0, matching MCP's tool call pattern.
"""
from __future__ import annotations

import json
import time
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Dict, Callable, Any, Optional


class MCPToolServer:
    """JSON-RPC 2.0 server that hosts tools — mimics MCP server behavior."""

    def __init__(self, port: int = 8300):
        self.port = port
        self.tools: Dict[str, Callable] = {}
        self.server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def register_tool(self, name: str, func: Callable) -> None:
        self.tools[name] = func

    def start(self) -> str:
        tool_server = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                content_length = int(self.headers.get('Content-Length', 0))
                body = json.loads(self.rfile.read(content_length))

                # JSON-RPC 2.0 format
                method = body.get('method', '')
                params = body.get('params', {})
                req_id = body.get('id', 1)

                if method == 'tools/list':
                    # List available tools
                    result = {"tools": [{"name": name} for name in tool_server.tools]}
                    response = {"jsonrpc": "2.0", "id": req_id, "result": result}
                elif method == 'tools/call':
                    tool_name = params.get('name', '')
                    tool_params = params.get('arguments', {})

                    if tool_name not in tool_server.tools:
                        response = {
                            "jsonrpc": "2.0", "id": req_id,
                            "error": {"code": -32601, "message": f"Tool '{tool_name}' not found"}
                        }
                    else:
                        try:
                            result = tool_server.tools[tool_name](**tool_params)
                            response = {
                                "jsonrpc": "2.0", "id": req_id,
                                "result": {"content": [{"type": "text", "text": json.dumps(result, default=str)}]}
                            }
                        except Exception:
                            response = {
                                "jsonrpc": "2.0", "id": req_id,
                                "error": {"code": -32000, "message": "Tool execution failed"}
                            }
                else:
                    response = {
                        "jsonrpc": "2.0", "id": req_id,
                        "error": {"code": -32601, "message": f"Unknown method: {method}"}
                    }

                resp_bytes = json.dumps(response).encode()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(resp_bytes)))
                self.send_header('X-Content-Type-Options', 'nosniff')
                self.end_headers()
                self.wfile.write(resp_bytes)

            def log_message(self, format, *args):
                pass

        self.server = HTTPServer(('localhost', self.port), Handler)
        self.port = self.server.server_address[1]  # actual port (handles port=0)
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()
        return f"http://localhost:{self.port}"

    def stop(self) -> None:
        if self.server:
            self.server.shutdown()

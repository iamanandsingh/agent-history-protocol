"""Tests for MCP protocol wrapping (built-in JSON-RPC and mcp package detection)."""
from __future__ import annotations

import os
import tempfile
import unittest

from ahp.core.chain import ChainWriter
from ahp.core.verify import verify_chain
from ahp.interceptors.mcp_auto import HAS_MCP


class TestMCPRealWrapping(unittest.TestCase):
    """Test MCP real package wrapping (if mcp installed)."""

    def test_has_mcp_flag(self):
        """HAS_MCP is a boolean reporting whether the mcp package is installed."""
        self.assertIsInstance(HAS_MCP, bool)
        print(f"\n  mcp package installed: {HAS_MCP}")

    def test_patch_without_mcp(self):
        """If mcp not installed, patching returns False."""
        from ahp.interceptors.mcp_auto import patch_mcp_client
        if not HAS_MCP:
            result = patch_mcp_client(None)
            self.assertFalse(result)

    def test_fallback_json_rpc_mcp(self):
        """Built-in MCP JSON-RPC works regardless of the mcp package."""
        from ahp.protocols.mcp_server import MCPToolServer
        from ahp.protocols.mcp_client import MCPClient

        tmpdir = tempfile.mkdtemp()
        chain_path = os.path.join(tmpdir, "mcp_fallback.ahp")

        server = MCPToolServer(port=0)
        server.register_tool("ping", lambda: {"pong": True})
        url = server.start()

        try:
            writer = ChainWriter(chain_path)
            client = MCPClient(url, writer)
            result = client.call_tool("ping", {})
            self.assertEqual(result, {"pong": True})

            verify_result = verify_chain(chain_path)
            self.assertTrue(verify_result.valid)
        finally:
            server.stop()
            writer.close()


if __name__ == '__main__':
    unittest.main()

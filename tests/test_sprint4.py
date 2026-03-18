"""Sprint 4 tests: CI validation, PII preset completeness, MCP real wrapping, LangChain."""
from __future__ import annotations

import os
import tempfile
import unittest

from ahp.core.filters import FilterPipeline, PRESETS, PCRE2
from ahp.core.chain import ChainWriter, ChainReader
from ahp.core.verify import verify_chain
from ahp.core.types import ResultStatus, Protocol, ActionType, AuthorizationType
from ahp.core.records import ActionPayload, Authorization
from ahp.interceptors.mcp_auto import HAS_MCP


class TestAllPIIPresets(unittest.TestCase):
    """Verify all 5 spec-required PII presets exist and work."""

    def test_all_presets_exist(self):
        required = ['pci', 'pii-us', 'pii-eu', 'credentials', 'hipaa']
        for name in required:
            self.assertIn(name, PRESETS, f"Missing preset: {name}")

    def test_pci_credit_card(self):
        pipeline = FilterPipeline(presets=['pci'])
        filtered, redacted = pipeline.apply(b'Card: 4111 1111 1111 1111', 'parameters')
        self.assertTrue(redacted)
        self.assertIn(b'[REDACTED:CC]', filtered)

    def test_pii_us_ssn(self):
        pipeline = FilterPipeline(presets=['pii-us'])
        filtered, redacted = pipeline.apply(b'SSN: 123-45-6789', 'parameters')
        self.assertTrue(redacted)
        self.assertIn(b'[REDACTED:SSN]', filtered)

    def test_pii_eu_iban(self):
        pipeline = FilterPipeline(presets=['pii-eu'])
        filtered, redacted = pipeline.apply(b'IBAN: GB29NWBK60161331926819', 'parameters')
        self.assertTrue(redacted)
        self.assertIn(b'[REDACTED:IBAN]', filtered)

    def test_credentials_bearer(self):
        pipeline = FilterPipeline(presets=['credentials'])
        filtered, redacted = pipeline.apply(b'Authorization: Bearer sk-abc123def456ghi789', 'parameters')
        self.assertTrue(redacted)
        self.assertIn(b'[REDACTED:TOKEN]', filtered)

    def test_hipaa_mrn(self):
        pipeline = FilterPipeline(presets=['hipaa'])
        filtered, redacted = pipeline.apply(b'MRN: 1234567890', 'parameters')
        self.assertTrue(redacted)
        self.assertIn(b'[REDACTED:MRN]', filtered)

    def test_hipaa_email(self):
        pipeline = FilterPipeline(presets=['hipaa'])
        filtered, redacted = pipeline.apply(b'Contact: patient@hospital.com', 'parameters')
        self.assertTrue(redacted)
        self.assertIn(b'[REDACTED:EMAIL]', filtered)

    def test_hipaa_phone(self):
        pipeline = FilterPipeline(presets=['hipaa'])
        filtered, redacted = pipeline.apply(b'Phone: (555) 123-4567', 'parameters')
        self.assertTrue(redacted)
        self.assertIn(b'[REDACTED:PHONE]', filtered)

    def test_all_presets_combined(self):
        """Apply all presets at once — nothing should crash."""
        pipeline = FilterPipeline(presets=['pci', 'pii-us', 'pii-eu', 'credentials', 'hipaa'])
        text = (
            b'Card: 4111 1111 1111 1111, '
            b'SSN: 123-45-6789, '
            b'IBAN: DE89370400440532013000, '
            b'Bearer sk-secret123456789012, '
            b'MRN: 9876543210'
        )
        filtered, redacted = pipeline.apply(text, 'parameters')
        self.assertTrue(redacted)
        # Original PII should not be in filtered output
        self.assertNotIn(b'4111', filtered)
        self.assertNotIn(b'123-45-6789', filtered)

    def test_pcre2_flag(self):
        """Report whether PCRE2 is available (not a pass/fail)."""
        print(f"\n  PCRE2 available: {PCRE2}")


class TestMCPRealWrapping(unittest.TestCase):
    """Test MCP real package wrapping (if mcp installed)."""

    def test_has_mcp_flag(self):
        """Verify HAS_MCP flag works."""
        # Just check it's a boolean
        self.assertIsInstance(HAS_MCP, bool)
        print(f"\n  mcp package installed: {HAS_MCP}")

    def test_patch_without_mcp(self):
        """If mcp not installed, patching returns False."""
        from ahp.interceptors.mcp_auto import patch_mcp_client
        if not HAS_MCP:
            result = patch_mcp_client(None)
            self.assertFalse(result)

    def test_fallback_json_rpc_mcp(self):
        """Our built-in MCP JSON-RPC works regardless of mcp package."""
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


class TestLangChainInterface(unittest.TestCase):
    """Test LangChain integration interface (without requiring langchain installed)."""

    def test_callback_handler_exists(self):
        from ahp.integrations.langchain import AHPCallbackHandler
        self.assertTrue(callable(AHPCallbackHandler))

    def test_callback_handler_methods(self):
        """Verify the handler has the expected LangChain callback methods."""
        from ahp.integrations.langchain import AHPCallbackHandler

        tmpdir = tempfile.mkdtemp()
        chain_path = os.path.join(tmpdir, "lc.ahp")
        writer = ChainWriter(chain_path)
        handler = AHPCallbackHandler(writer)

        # Should have these LangChain callback methods
        self.assertTrue(hasattr(handler, 'on_tool_start'))
        self.assertTrue(hasattr(handler, 'on_tool_end'))
        self.assertTrue(hasattr(handler, 'on_tool_error'))
        self.assertTrue(hasattr(handler, 'on_llm_start'))
        self.assertTrue(hasattr(handler, 'on_llm_end'))
        writer.close()

    def test_simulated_tool_callbacks(self):
        """Simulate LangChain tool callbacks and verify AHP records."""
        from ahp.integrations.langchain import AHPCallbackHandler

        tmpdir = tempfile.mkdtemp()
        chain_path = os.path.join(tmpdir, "lc_sim.ahp")
        writer = ChainWriter(chain_path)
        handler = AHPCallbackHandler(writer)

        # Simulate on_tool_start → on_tool_end
        handler.on_tool_start(
            serialized={"name": "search"},
            input_str='{"query": "test"}',
            run_id="run-001",
            name="search",
        )
        handler.on_tool_end(
            output="search results here",
            run_id="run-001",
            name="search",
        )

        writer.close()

        # Verify record was created
        reader = ChainReader(chain_path)
        records = reader.read_all()
        self.assertGreaterEqual(len(records), 1)

        result = verify_chain(chain_path)
        self.assertTrue(result.valid)

    def test_simulated_tool_error(self):
        """Simulate tool error callback."""
        from ahp.integrations.langchain import AHPCallbackHandler

        tmpdir = tempfile.mkdtemp()
        chain_path = os.path.join(tmpdir, "lc_err.ahp")
        writer = ChainWriter(chain_path)
        handler = AHPCallbackHandler(writer)

        handler.on_tool_start(
            serialized={"name": "bad_tool"},
            input_str='{}',
            run_id="run-002",
            name="bad_tool",
        )
        handler.on_tool_error(
            error=ValueError("Something went wrong"),
            run_id="run-002",
            name="bad_tool",
        )

        writer.close()

        reader = ChainReader(chain_path)
        records = reader.read_all()
        self.assertGreaterEqual(len(records), 1)


class TestCIValidation(unittest.TestCase):
    """Tests that CI would run — validate all imports and basic functionality."""

    def test_all_core_imports(self):
        """Every core module imports without error."""
        import ahp.core.types
        import ahp.core.records
        import ahp.core.canonical
        import ahp.core.chain
        import ahp.core.verify
        import ahp.core.evidence
        import ahp.core.filters
        import ahp.core.signing
        import ahp.core.context
        import ahp.core.uuid7
        import ahp.core.json_format
        import ahp.core.recovery
        import ahp.core.async_chain
        import ahp.core.rotation

    def test_all_module_imports(self):
        """Every top-level module imports without error."""
        import ahp.recorder
        import ahp.async_recorder
        import ahp.config
        import ahp.protocols.a2a
        import ahp.protocols.mcp_server
        import ahp.protocols.mcp_client
        import ahp.interceptors.http_helper
        import ahp.interceptors.mcp_helper
        import ahp.interceptors.grpc
        import ahp.interceptors.http_auto
        import ahp.interceptors.mcp_auto
        import ahp.integrations.langchain
        import ahp.export.jsonl
        import ahp.export.otlp
        import ahp.cli.main

    def test_end_to_end_quick(self):
        """Quick end-to-end: record → verify → export."""
        from ahp.recorder import AHPRecorder

        tmpdir = tempfile.mkdtemp()
        chain_path = os.path.join(tmpdir, "ci_e2e.ahp")

        recorder = AHPRecorder(
            agent_name="ci-test",
            chain_path=chain_path,
            level=1,
        )

        recorder.record_action(
            tool_name="ci_test_tool",
            parameters=b'{"test": true}',
            result=b'{"ok": true}',
        )

        # Verify
        result = verify_chain(chain_path)
        self.assertTrue(result.valid)

        # Export
        reader = ChainReader(chain_path)
        records = reader.read_all()
        self.assertGreaterEqual(len(records), 2)  # Boot + action


if __name__ == '__main__':
    unittest.main()

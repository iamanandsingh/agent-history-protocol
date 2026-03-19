"""Tests for LangChain integration (AHPCallbackHandler)."""
from __future__ import annotations

import os
import tempfile
import unittest

from ahp.core.chain import ChainWriter, ChainReader
from ahp.core.verify import verify_chain


class TestLangChainInterface(unittest.TestCase):
    """Test LangChain integration interface (without requiring langchain installed)."""

    def test_callback_handler_exists(self):
        from ahp.integrations.langchain import AHPCallbackHandler
        self.assertTrue(callable(AHPCallbackHandler))

    def test_callback_handler_methods(self):
        """Handler has the expected LangChain callback methods."""
        from ahp.integrations.langchain import AHPCallbackHandler

        tmpdir = tempfile.mkdtemp()
        writer = ChainWriter(os.path.join(tmpdir, "lc.ahp"))
        handler = AHPCallbackHandler(writer)

        for method in ('on_tool_start', 'on_tool_end', 'on_tool_error',
                       'on_llm_start', 'on_llm_end', 'on_llm_error',
                       'on_chain_start', 'on_chain_end'):
            self.assertTrue(hasattr(handler, method), f"Missing method: {method}")
        writer.close()

    def test_simulated_tool_callbacks(self):
        """Simulate LangChain tool callbacks and verify AHP records."""
        from ahp.integrations.langchain import AHPCallbackHandler

        tmpdir = tempfile.mkdtemp()
        chain_path = os.path.join(tmpdir, "lc_sim.ahp")
        writer = ChainWriter(chain_path)
        handler = AHPCallbackHandler(writer)

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

        self.assertGreaterEqual(ChainReader(chain_path).count(), 1)
        self.assertTrue(verify_chain(chain_path).valid)

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

        self.assertGreaterEqual(ChainReader(chain_path).count(), 1)

    def test_recorder_based_handler(self):
        """LangChain handler with full AHPRecorder applies PII filtering and evidence."""
        from ahp.integrations.langchain import AHPCallbackHandler
        from ahp.recorder import AHPRecorder

        tmpdir = tempfile.mkdtemp()
        chain_path = os.path.join(tmpdir, "lc_recorder.ahp")
        evidence_path = os.path.join(tmpdir, "evidence")

        recorder = AHPRecorder(
            agent_name="langchain-test",
            chain_path=chain_path,
            level=1,
            evidence_path=evidence_path,
            filter_presets=["pii-us", "credentials"],
            checkpoint_interval=9999,
        )
        handler = AHPCallbackHandler(recorder)

        handler.on_tool_start(
            serialized={"name": "lookup"},
            input_str='{"ssn": "123-45-6789", "query": "test"}',
            run_id="run-pii",
            name="lookup_customer",
        )
        handler.on_tool_end(
            output='{"name": "John", "status": "active"}',
            run_id="run-pii",
            name="lookup_customer",
        )

        handler.on_llm_start(
            serialized={"model": "gpt-4"},
            prompts=["Summarize the customer info"],
            run_id="run-llm",
        )

        class MockResponse:
            llm_output = {"model_name": "gpt-4", "token_usage": {"prompt_tokens": 10, "completion_tokens": 25}}
            def __str__(self):
                return "Customer John is active."

        handler.on_llm_end(response=MockResponse(), run_id="run-llm")
        recorder.close()

        result = verify_chain(chain_path)
        self.assertTrue(result.valid, f"Chain invalid: {result.error}")
        self.assertGreaterEqual(ChainReader(chain_path).count(), 3)
        self.assertGreater(len(os.listdir(evidence_path)), 0)

    def test_recorder_handler_with_tool_error(self):
        """LangChain handler records tool and LLM errors via AHPRecorder."""
        from ahp.integrations.langchain import AHPCallbackHandler
        from ahp.recorder import AHPRecorder

        tmpdir = tempfile.mkdtemp()
        chain_path = os.path.join(tmpdir, "lc_rec_err.ahp")

        recorder = AHPRecorder(
            agent_name="langchain-err-test",
            chain_path=chain_path,
            level=1,
            checkpoint_interval=9999,
        )
        handler = AHPCallbackHandler(recorder)

        handler.on_tool_start(
            serialized={"name": "risky_tool"},
            input_str='{"action": "delete"}',
            run_id="run-err",
            name="risky_tool",
        )
        handler.on_tool_error(
            error=RuntimeError("Permission denied"),
            run_id="run-err",
            name="risky_tool",
        )

        handler.on_llm_start(
            serialized={"model": "claude"},
            prompts=["test prompt"],
            run_id="run-llm-err",
        )
        handler.on_llm_error(
            error=TimeoutError("API timeout"),
            run_id="run-llm-err",
        )

        recorder.close()

        result = verify_chain(chain_path)
        self.assertTrue(result.valid, f"Chain invalid: {result.error}")


class TestExternalPackages(unittest.TestCase):
    """Smoke tests for optional external package integration."""

    def test_langchain_import(self):
        """Simulate LangChain callbacks even when langchain-core is not installed."""
        try:
            import langchain_core  # noqa: F401
            print("\n  langchain-core IS installed — real integration available")
        except ImportError:
            print("\n  langchain-core not installed — testing simulated callbacks")
            from ahp.integrations.langchain import AHPCallbackHandler
            tmpdir = tempfile.mkdtemp()
            writer = ChainWriter(os.path.join(tmpdir, "lc.ahp"))
            handler = AHPCallbackHandler(writer)
            handler.on_tool_start({"name": "test"}, "input", run_id="r1", name="test")
            handler.on_tool_end("output", run_id="r1", name="test")
            writer.close()
            self.assertTrue(verify_chain(os.path.join(tmpdir, "lc.ahp")).valid)

    def test_mcp_import(self):
        """Report whether the mcp package is available."""
        from ahp.interceptors.mcp_auto import HAS_MCP
        if not HAS_MCP:
            print("\n  mcp package not installed — using built-in JSON-RPC fallback")
        else:
            print("\n  mcp package IS installed — real wrapping available")


if __name__ == '__main__':
    unittest.main()

"""Tests for config file loading (YAML/JSON) and module import validation."""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from ahp.core.chain import ChainReader
from ahp.core.verify import verify_chain


class TestConfigYAMLFile(unittest.TestCase):
    """Config loading from YAML/JSON files on disk."""

    def test_load_yaml_file(self):
        """Write a real ahp.yaml, load it, verify all settings are applied."""
        tmpdir = tempfile.mkdtemp()
        config_path = os.path.join(tmpdir, "ahp.yaml")

        # JSON is valid YAML — avoids pyyaml dependency in tests
        config_content = json.dumps({
            "defaults": {
                "level": 2,
                "inference": {"record": True, "evidence": False},
                "evidence": {"record": True},
                "authorization": {"record": True},
                "fsync_mode": "every",
                "checkpoint_interval": 500,
                "witness": {
                    "enabled": True,
                    "endpoints": ["https://localhost:8120"],
                },
            },
            "filters": [
                {"preset": "pci"},
                {"preset": "credentials"},
            ],
            "agents": [
                {"match": "test-*", "level": 3},
            ],
        })
        Path(config_path).write_text(config_content)

        from ahp.config import load_config
        config = load_config(config_path, agent_name="test-agent")

        self.assertEqual(config.level, 3)  # per-agent override
        self.assertTrue(config.inference_record)
        self.assertFalse(config.inference_evidence)
        self.assertTrue(config.evidence_record)
        self.assertTrue(config.authorization_record)
        self.assertEqual(config.fsync_mode, "every")
        self.assertEqual(config.checkpoint_interval, 500)
        self.assertEqual(config.matched_agent_rule, "test-*")
        self.assertIn("pci", config.filter_presets)
        self.assertIn("credentials", config.filter_presets)

    def test_load_json_config(self):
        """Load config from a .json file."""
        tmpdir = tempfile.mkdtemp()
        config_path = os.path.join(tmpdir, "ahp.json")
        Path(config_path).write_text(json.dumps({"defaults": {"level": 1}}))

        from ahp.config import load_config
        config = load_config(config_path, agent_name="any")
        self.assertEqual(config.level, 1)


class TestImportValidation(unittest.TestCase):
    """Smoke-test that every AHP module imports without error."""

    def test_all_core_imports(self):
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


    def test_all_module_imports(self):
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
        """Quick end-to-end smoke test: record → verify → read."""
        from ahp.recorder import AHPRecorder

        tmpdir = tempfile.mkdtemp()
        chain_path = os.path.join(tmpdir, "ci_e2e.ahp")

        recorder = AHPRecorder(agent_name="ci-test", chain_path=chain_path, level=1)
        recorder.record_action(
            tool_name="ci_test_tool",
            parameters=b'{"test": true}',
            result=b'{"ok": true}',
        )

        result = verify_chain(chain_path)
        self.assertTrue(result.valid)

        records = ChainReader(chain_path).read_all()
        self.assertGreaterEqual(len(records), 2)  # Boot + action


if __name__ == '__main__':
    unittest.main()

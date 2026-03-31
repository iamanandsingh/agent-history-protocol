"""Tests for OpenAI client adapter (mocked — no real API calls)."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from ahp._globals import set_default_recorder
from ahp.adapters.openai import _extract_usage, instrument
from ahp.core.chain import ChainReader, parse_action_payload, parse_envelope
from ahp.core.types import ActionType, RecordType, ResultStatus
from ahp.recorder import AHPRecorder


def _mock_response(
    model: str = "gpt-4o-2024-08-06",
    prompt_tokens: int = 100,
    completion_tokens: int = 50,
    cached_tokens: int = 0,
    reasoning_tokens: int = 0,
):
    """Create a mock OpenAI ChatCompletion response."""
    prompt_details = SimpleNamespace(cached_tokens=cached_tokens) if cached_tokens else None
    completion_details = SimpleNamespace(reasoning_tokens=reasoning_tokens) if reasoning_tokens else None

    usage = SimpleNamespace(
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        prompt_tokens_details=prompt_details,
        completion_tokens_details=completion_details,
    )

    return SimpleNamespace(
        model=model,
        usage=usage,
        choices=[SimpleNamespace(message=SimpleNamespace(content="Hello!"))],
        model_dump_json=lambda: '{"model":"' + model + '","choices":[{"message":{"content":"Hello!"}}]}',
    )


def _mock_stream_chunks(model="gpt-4o", prompt_tokens=80, completion_tokens=30):
    """Create mock streaming chunks."""
    # Content chunks (no usage)
    for i, text in enumerate(["Hello", " world", "!"]):
        yield SimpleNamespace(
            model=model,
            choices=[SimpleNamespace(delta=SimpleNamespace(content=text))],
            usage=None,
        )
    # Final chunk with usage (when stream_options.include_usage=True)
    yield SimpleNamespace(
        model=model,
        choices=[],
        usage=SimpleNamespace(
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            prompt_tokens_details=None,
            completion_tokens_details=None,
        ),
    )


class MockCompletions:
    def __init__(self, stream_error=False, create_error=False):
        self._stream_error = stream_error
        self._create_error = create_error

    def create(self, **kwargs):
        if self._create_error:
            raise RuntimeError("API error")
        model = kwargs.get("model", "gpt-4o")
        if kwargs.get("stream"):
            return _mock_stream_chunks(model=model)
        # Real OpenAI API returns dated model version
        return _mock_response(model=model)


class MockChat:
    def __init__(self, **kwargs):
        self.completions = MockCompletions(**kwargs)


class MockClient:
    def __init__(self, **kwargs):
        self.chat = MockChat(**kwargs)


class TestExtractUsage(unittest.TestCase):
    def test_standard_response(self):
        resp = _mock_response(prompt_tokens=200, completion_tokens=100)
        u = _extract_usage(resp)
        self.assertEqual(u["input_tokens"], 200)
        self.assertEqual(u["output_tokens"], 100)

    def test_cached_tokens(self):
        resp = _mock_response(cached_tokens=150)
        u = _extract_usage(resp)
        self.assertEqual(u["cache_read"], 150)

    def test_reasoning_tokens(self):
        resp = _mock_response(reasoning_tokens=512)
        u = _extract_usage(resp)
        self.assertEqual(u["reasoning"], 512)

    def test_no_usage(self):
        resp = SimpleNamespace(model="gpt-4o")  # no usage attr
        u = _extract_usage(resp)
        self.assertEqual(u["input_tokens"], 0)
        self.assertEqual(u["output_tokens"], 0)


class TestInstrumentNonStreaming(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.chain_path = str(Path(self.tmpdir) / "test.ahp")
        self.recorder = AHPRecorder(agent_name="test", chain_path=self.chain_path)
        set_default_recorder(self.recorder)

    def tearDown(self):
        self.recorder.close()
        set_default_recorder(None)

    def _get_actions(self):
        actions = []
        for stored in ChainReader(self.chain_path).read_all():
            env = parse_envelope(stored)
            if env["record_type"] == RecordType.ACTION:
                actions.append(parse_action_payload(env["payload_bytes"]))
        return actions

    def test_basic_call(self):
        client = instrument(MockClient())
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": "Hello"}],
        )
        self.assertIn("gpt-4o", response.model)

        actions = self._get_actions()
        self.assertEqual(len(actions), 1)
        a = actions[0]
        self.assertEqual(a["tool_name"], "openai.chat.completions")
        self.assertEqual(a["action_type"], ActionType.INFERENCE)
        self.assertEqual(a["model_id"], "gpt-4o")
        self.assertEqual(a["provider"], "openai")
        self.assertEqual(a["input_token_count"], 100)
        self.assertEqual(a["output_token_count"], 50)
        self.assertEqual(a["result_status"], ResultStatus.SUCCESS)
        self.assertGreater(a["cost_nano_usd"], 0)

    def test_error_recorded(self):
        client = instrument(MockClient(create_error=True))

        with self.assertRaises(RuntimeError):
            client.chat.completions.create(
                model="gpt-4o",
                messages=[{"role": "user", "content": "Hello"}],
            )

        actions = self._get_actions()
        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0]["result_status"], ResultStatus.ERROR)

    def test_explicit_recorder(self):
        tmpdir2 = tempfile.mkdtemp()
        chain2 = str(Path(tmpdir2) / "explicit.ahp")
        rec2 = AHPRecorder(agent_name="explicit", chain_path=chain2)

        client = instrument(MockClient(), recorder=rec2)
        client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": "Hi"}],
        )
        rec2.close()

        actions = []
        for stored in ChainReader(chain2).read_all():
            env = parse_envelope(stored)
            if env["record_type"] == RecordType.ACTION:
                actions.append(parse_action_payload(env["payload_bytes"]))
        self.assertEqual(len(actions), 1)

    def test_cached_and_reasoning_tokens(self):
        # Override mock to return cached + reasoning
        client = instrument(MockClient())
        client.chat.completions._original.create = lambda **kw: _mock_response(
            model="o3",
            prompt_tokens=500,
            completion_tokens=1200,
            cached_tokens=300,
            reasoning_tokens=1024,
        )
        client.chat.completions.create(
            model="o3",
            messages=[{"role": "user", "content": "Think hard"}],
        )

        actions = self._get_actions()
        a = actions[0]
        self.assertEqual(a["cache_read_tokens"], 300)
        self.assertEqual(a["reasoning_tokens"], 1024)
        self.assertEqual(a["input_token_count"], 500)
        self.assertEqual(a["output_token_count"], 1200)


class TestInstrumentStreaming(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.chain_path = str(Path(self.tmpdir) / "test.ahp")
        self.recorder = AHPRecorder(agent_name="test", chain_path=self.chain_path)
        set_default_recorder(self.recorder)

    def tearDown(self):
        self.recorder.close()
        set_default_recorder(None)

    def _get_actions(self):
        actions = []
        for stored in ChainReader(self.chain_path).read_all():
            env = parse_envelope(stored)
            if env["record_type"] == RecordType.ACTION:
                actions.append(parse_action_payload(env["payload_bytes"]))
        return actions

    def test_streaming_records_after_iteration(self):
        client = instrument(MockClient())
        stream = client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": "Hi"}],
            stream=True,
        )

        # No record yet
        self.assertEqual(len(self._get_actions()), 0)

        # Consume stream
        chunks = list(stream)
        self.assertEqual(len(chunks), 4)  # 3 content + 1 usage

        # Now record should exist
        actions = self._get_actions()
        self.assertEqual(len(actions), 1)
        a = actions[0]
        self.assertEqual(a["model_id"], "gpt-4o")
        self.assertEqual(a["input_token_count"], 80)
        self.assertEqual(a["output_token_count"], 30)

    def test_stream_options_injected(self):
        """stream_options.include_usage is auto-injected."""
        captured_kwargs = {}
        original_create = MockCompletions.create

        def spy_create(self_mock, **kwargs):
            captured_kwargs.update(kwargs)
            return original_create(self_mock, **kwargs)

        MockCompletions.create = spy_create
        client = instrument(MockClient())
        stream = client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": "Hi"}],
            stream=True,
        )
        list(stream)  # consume

        self.assertIn("stream_options", captured_kwargs)
        self.assertTrue(captured_kwargs["stream_options"].get("include_usage"))

        # Restore
        MockCompletions.create = original_create


class TestFailOpen(unittest.TestCase):
    def test_no_recorder(self):
        set_default_recorder(None)
        client = instrument(MockClient())
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": "Hi"}],
        )
        # Should work fine, just no recording
        self.assertIn("gpt-4o", response.model)

    def test_broken_recorder(self):
        class BrokenRecorder:
            def safe_record(self, **kw):
                raise RuntimeError("recorder broken")

        set_default_recorder(BrokenRecorder())
        client = instrument(MockClient())
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": "Hi"}],
        )
        self.assertIn("gpt-4o", response.model)
        set_default_recorder(None)


class TestCostEstimation(unittest.TestCase):
    def test_cost_auto_estimated(self):
        tmpdir = tempfile.mkdtemp()
        chain = str(Path(tmpdir) / "cost.ahp")
        rec = AHPRecorder(agent_name="cost", chain_path=chain)
        set_default_recorder(rec)

        client = instrument(MockClient())
        client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": "Hi"}],
        )
        rec.close()
        set_default_recorder(None)

        for stored in ChainReader(chain).read_all():
            env = parse_envelope(stored)
            if env["record_type"] == RecordType.ACTION:
                a = parse_action_payload(env["payload_bytes"])
                # gpt-4o: 100 * 2500 + 50 * 10000 = 750000 nano USD
                self.assertEqual(a["cost_nano_usd"], 750000)
                break


if __name__ == "__main__":
    unittest.main()

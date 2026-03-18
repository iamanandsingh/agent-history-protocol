"""Tests for W3C Trace Context propagation — Section 9."""
from __future__ import annotations

import unittest
from ahp.core.context import (
    generate_trace_id, generate_span_id,
    create_traceparent, parse_traceparent,
    encode_tracestate_ahp, decode_tracestate_ahp,
    create_tracestate, parse_tracestate_ahp,
    inject_headers, extract_context,
)
from ahp.core.uuid7 import uuid7


class TestTraceparent(unittest.TestCase):
    def test_create_and_parse(self):
        trace_id = generate_trace_id()
        span_id = generate_span_id()
        header = create_traceparent(trace_id, span_id, sampled=True)

        parsed = parse_traceparent(header)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed['trace_id'], trace_id)
        self.assertEqual(parsed['span_id'], span_id)
        self.assertTrue(parsed['sampled'])

    def test_format(self):
        trace_id = b'\x4b\xf9\x2f\x35\x77\xb3\x4d\xa6\xa3\xce\x92\x9d\x0e\x0e\x47\x36'
        span_id = b'\x00\xf0\x67\xaa\x0b\xa9\x02\xb7'
        header = create_traceparent(trace_id, span_id)
        self.assertTrue(header.startswith('00-'))
        parts = header.split('-')
        self.assertEqual(len(parts), 4)
        self.assertEqual(len(parts[1]), 32)  # trace_id hex
        self.assertEqual(len(parts[2]), 16)  # span_id hex

    def test_parse_invalid(self):
        self.assertIsNone(parse_traceparent('invalid'))
        self.assertIsNone(parse_traceparent('00-short-ab-01'))
        self.assertIsNone(parse_traceparent(''))

    def test_not_sampled(self):
        trace_id = generate_trace_id()
        header = create_traceparent(trace_id, sampled=False)
        parsed = parse_traceparent(header)
        self.assertFalse(parsed['sampled'])


class TestTracestate(unittest.TestCase):
    def test_encode_decode_round_trip(self):
        agent_id = uuid7()
        sequence = 42
        chain_hash = b'\xab' * 32

        encoded = encode_tracestate_ahp(agent_id, sequence, chain_hash)
        self.assertIsInstance(encoded, str)
        self.assertLessEqual(len(encoded), 56)  # 54 chars typical

        decoded = decode_tracestate_ahp(encoded)
        self.assertIsNotNone(decoded)
        self.assertEqual(decoded['agent_id'], agent_id)
        self.assertEqual(decoded['sequence'], sequence)
        self.assertEqual(decoded['chain_hash'], chain_hash[:16])

    def test_large_sequence(self):
        agent_id = uuid7()
        sequence = 2**63  # large sequence number
        chain_hash = b'\xff' * 32

        encoded = encode_tracestate_ahp(agent_id, sequence, chain_hash)
        decoded = decode_tracestate_ahp(encoded)
        self.assertEqual(decoded['sequence'], sequence)

    def test_create_tracestate_new(self):
        ahp_value = "test_encoded_value"
        ts = create_tracestate(ahp_value)
        self.assertEqual(ts, "ahp=test_encoded_value")

    def test_create_tracestate_with_existing(self):
        ahp_value = "ahp_data"
        ts = create_tracestate(ahp_value, existing="vendor1=val1,vendor2=val2")
        self.assertTrue(ts.startswith("ahp=ahp_data"))
        self.assertIn("vendor1=val1", ts)
        self.assertIn("vendor2=val2", ts)

    def test_create_tracestate_replaces_old_ahp(self):
        ahp_value = "new_data"
        ts = create_tracestate(ahp_value, existing="ahp=old_data,vendor=val")
        self.assertIn("ahp=new_data", ts)
        self.assertNotIn("ahp=old_data", ts)
        self.assertIn("vendor=val", ts)

    def test_parse_tracestate_ahp(self):
        agent_id = uuid7()
        encoded = encode_tracestate_ahp(agent_id, 100, b'\x00' * 32)
        tracestate = f"ahp={encoded},other=value"

        decoded = parse_tracestate_ahp(tracestate)
        self.assertIsNotNone(decoded)
        self.assertEqual(decoded['agent_id'], agent_id)
        self.assertEqual(decoded['sequence'], 100)

    def test_parse_tracestate_no_ahp(self):
        self.assertIsNone(parse_tracestate_ahp("vendor1=val1,vendor2=val2"))

    def test_decode_invalid(self):
        self.assertIsNone(decode_tracestate_ahp("not_valid_base64!!!"))
        self.assertIsNone(decode_tracestate_ahp(""))


class TestHeaderInjectionExtraction(unittest.TestCase):
    def test_inject_and_extract(self):
        trace_id = generate_trace_id()
        agent_id = uuid7()
        sequence = 500
        chain_hash = b'\xde\xad' * 16

        headers = {}
        inject_headers(headers, trace_id, agent_id, sequence, chain_hash)

        self.assertIn('traceparent', headers)
        self.assertIn('tracestate', headers)

        context = extract_context(headers)
        self.assertIsNotNone(context)
        self.assertEqual(context['trace_id'], trace_id)
        self.assertTrue(context['sampled'])

        # AHP data should be in context
        self.assertIn('ahp', context)
        self.assertEqual(context['ahp']['agent_id'], agent_id)
        self.assertEqual(context['ahp']['sequence'], sequence)
        self.assertEqual(context['ahp']['chain_hash'], chain_hash[:16])

    def test_extract_no_headers(self):
        self.assertIsNone(extract_context({}))

    def test_extract_traceparent_only(self):
        trace_id = generate_trace_id()
        headers = {'traceparent': create_traceparent(trace_id)}
        context = extract_context(headers)
        self.assertIsNotNone(context)
        self.assertEqual(context['trace_id'], trace_id)
        self.assertNotIn('ahp', context)  # no tracestate

    def test_preserves_existing_vendors(self):
        headers = {'tracestate': 'vendor1=abc,vendor2=def'}
        trace_id = generate_trace_id()
        agent_id = uuid7()
        inject_headers(headers, trace_id, agent_id, 1, b'\x00' * 32)
        # AHP added, existing preserved
        self.assertIn('ahp=', headers['tracestate'])
        self.assertIn('vendor1=abc', headers['tracestate'])
        self.assertIn('vendor2=def', headers['tracestate'])


class TestConfigIntegration(unittest.TestCase):
    def test_config_loads(self):
        from ahp.config import AHPConfig, load_config
        config = AHPConfig(agent_name="test", level=1)
        errors = config.validate()
        self.assertEqual(len(errors), 0)

    def test_config_validation_level3_no_witness(self):
        from ahp.config import AHPConfig
        config = AHPConfig(level=3)
        errors = config.validate()
        self.assertGreater(len(errors), 0)
        self.assertTrue(any("witness" in e for e in errors))

    def test_config_from_env(self):
        import os
        os.environ['AHP_LEVEL'] = '2'
        from ahp.config import _from_env
        config = _from_env("test-agent")
        self.assertEqual(config.level, 2)
        del os.environ['AHP_LEVEL']


if __name__ == '__main__':
    unittest.main()

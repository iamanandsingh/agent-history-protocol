"""Tests for OTLP export mapping and batch format."""

from __future__ import annotations

import json
import os
import tempfile
import unittest

from ahp.core.chain import ChainReader, ChainWriter
from ahp.core.json_format import record_to_json
from ahp.core.records import (
    ActionPayload,
    Authorization,
    AuthorizationEntry,
    BootPayload,
)
from ahp.core.types import (
    ActionType,
    AuthorizationDecision,
    AuthorizationType,
    AuthorizerType,
    GapReason,
    Protocol,
    ResultStatus,
)
from ahp.export.otlp import OTLPExporter, map_record_to_otlp_log


class TestMapActionRecord(unittest.TestCase):
    """Verify OTLP LogRecord has correct attributes for an ACTION record."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.chain_path = os.path.join(self.tmpdir, "test.ahp")
        writer = ChainWriter(self.chain_path)
        writer.write_record(
            ActionPayload(
                tool_name="read_file",
                parameters_hash=b"\xaa" * 16,
                result_hash=b"\xbb" * 16,
                result_status=ResultStatus.SUCCESS,
                response_time_ms=42,
                protocol=Protocol.MCP,
                action_type=ActionType.TOOL_CALL,
                model_id="gpt-4",
                authorization=Authorization(
                    type=AuthorizationType.AUTH_HUMAN,
                    entries=[
                        AuthorizationEntry(
                            authorizer_type=AuthorizerType.AUTHORIZER_HUMAN,
                            authorizer_id="user:alice",
                            decision=AuthorizationDecision.APPROVED,
                            timestamp_ms=1710000000000,
                        )
                    ],
                ),
            )
        )
        reader = ChainReader(self.chain_path)
        records = reader.read_all()
        self.record_json = record_to_json(records[0])
        self.otlp_log = map_record_to_otlp_log(self.record_json)

    def test_severity_is_info(self):
        self.assertEqual(self.otlp_log["severityText"], "INFO")
        self.assertEqual(self.otlp_log["severityNumber"], 9)

    def test_timestamp_conversion(self):
        expected_nano = str(self.record_json["timestamp_ms"] * 1_000_000)
        self.assertEqual(self.otlp_log["timeUnixNano"], expected_nano)

    def test_body_is_json_string(self):
        body = self.otlp_log["body"]["stringValue"]
        parsed = json.loads(body)
        self.assertEqual(parsed["tool_name"], "read_file")

    def test_core_attributes(self):
        attrs = {a["key"]: a["value"] for a in self.otlp_log["attributes"]}
        self.assertEqual(attrs["ahp.record.type"]["stringValue"], "ACTION")
        self.assertEqual(attrs["ahp.record.sequence"]["intValue"], str(self.record_json["sequence"]))
        self.assertEqual(attrs["ahp.agent.id"]["stringValue"], self.record_json["agent_id"])
        self.assertEqual(attrs["ahp.session.id"]["stringValue"], self.record_json["session_id"])

    def test_action_specific_attributes(self):
        attrs = {a["key"]: a["value"] for a in self.otlp_log["attributes"]}
        self.assertEqual(attrs["ahp.action.tool_name"]["stringValue"], "read_file")
        self.assertEqual(attrs["ahp.action.type"]["stringValue"], "TOOL_CALL")
        self.assertEqual(attrs["ahp.action.protocol"]["stringValue"], "MCP")
        self.assertEqual(attrs["ahp.action.status"]["stringValue"], "SUCCESS")
        self.assertEqual(attrs["ahp.action.duration_ms"]["intValue"], "42")
        self.assertEqual(attrs["ahp.auth.type"]["stringValue"], "AUTH_HUMAN")

    def test_model_id_attribute(self):
        attrs = {a["key"]: a["value"] for a in self.otlp_log["attributes"]}
        self.assertEqual(attrs["ahp.inference.model"]["stringValue"], "gpt-4")

    def test_trace_and_span_ids_present(self):
        self.assertIn("traceId", self.otlp_log)
        self.assertIn("spanId", self.otlp_log)


class TestMapBootRecord(unittest.TestCase):
    """Verify BOOT record maps correctly to OTLP LogRecord."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.chain_path = os.path.join(self.tmpdir, "test.ahp")
        writer = ChainWriter(self.chain_path)
        writer.write_record(
            BootPayload(
                agent_name="test-agent",
                authorization_recording=True,
            )
        )
        reader = ChainReader(self.chain_path)
        records = reader.read_all()
        self.record_json = record_to_json(records[0])
        self.otlp_log = map_record_to_otlp_log(self.record_json)

    def test_severity_is_info(self):
        self.assertEqual(self.otlp_log["severityText"], "INFO")
        self.assertEqual(self.otlp_log["severityNumber"], 9)

    def test_type_attribute(self):
        attrs = {a["key"]: a["value"] for a in self.otlp_log["attributes"]}
        self.assertEqual(attrs["ahp.record.type"]["stringValue"], "BOOT")

    def test_body_contains_boot_payload(self):
        body = json.loads(self.otlp_log["body"]["stringValue"])
        self.assertEqual(body["agent_name"], "test-agent")
        self.assertTrue(body["authorization_recording"])

    def test_no_action_attributes(self):
        attr_keys = {a["key"] for a in self.otlp_log["attributes"]}
        self.assertNotIn("ahp.action.tool_name", attr_keys)
        self.assertNotIn("ahp.action.status", attr_keys)


class TestMapErrorRecord(unittest.TestCase):
    """Verify ERROR severity for failed action records."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.chain_path = os.path.join(self.tmpdir, "test.ahp")
        writer = ChainWriter(self.chain_path)
        writer.write_record(
            ActionPayload(
                tool_name="dangerous_tool",
                result_status=ResultStatus.ERROR,
                protocol=Protocol.HTTP,
                action_type=ActionType.TOOL_CALL,
                authorization=Authorization(type=AuthorizationType.AUTH_NONE),
            )
        )
        reader = ChainReader(self.chain_path)
        records = reader.read_all()
        self.record_json = record_to_json(records[0])
        self.otlp_log = map_record_to_otlp_log(self.record_json)

    def test_severity_is_error(self):
        self.assertEqual(self.otlp_log["severityText"], "ERROR")
        self.assertEqual(self.otlp_log["severityNumber"], 17)

    def test_failure_also_maps_to_error(self):
        """FAILURE status should also produce ERROR severity."""
        tmpdir = tempfile.mkdtemp()
        path = os.path.join(tmpdir, "fail.ahp")
        writer = ChainWriter(path)
        writer.write_record(
            ActionPayload(
                tool_name="flaky_tool",
                result_status=ResultStatus.FAILURE,
                protocol=Protocol.MCP,
                action_type=ActionType.TOOL_CALL,
                authorization=Authorization(type=AuthorizationType.AUTH_NONE),
            )
        )
        reader = ChainReader(path)
        records = reader.read_all()
        j = record_to_json(records[0])
        otlp = map_record_to_otlp_log(j)
        self.assertEqual(otlp["severityText"], "ERROR")

    def test_timeout_also_maps_to_error(self):
        """TIMEOUT status should also produce ERROR severity."""
        tmpdir = tempfile.mkdtemp()
        path = os.path.join(tmpdir, "timeout.ahp")
        writer = ChainWriter(path)
        writer.write_record(
            ActionPayload(
                tool_name="slow_tool",
                result_status=ResultStatus.TIMEOUT,
                protocol=Protocol.MCP,
                action_type=ActionType.TOOL_CALL,
                authorization=Authorization(type=AuthorizationType.AUTH_NONE),
            )
        )
        reader = ChainReader(path)
        records = reader.read_all()
        j = record_to_json(records[0])
        otlp = map_record_to_otlp_log(j)
        self.assertEqual(otlp["severityText"], "ERROR")


class TestMapGapRecord(unittest.TestCase):
    """Verify WARN severity for GAP records."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.chain_path = os.path.join(self.tmpdir, "test.ahp")
        writer = ChainWriter(self.chain_path)
        # Write a boot record first so there's a valid chain
        writer.write_record(BootPayload(agent_name="test"))
        # Write a gap record
        writer.write_gap(
            first_lost=2,
            last_lost=5,
            reason=GapReason.CRASH,
            detail="unexpected shutdown",
        )
        reader = ChainReader(self.chain_path)
        records = reader.read_all()
        # The gap record is the second one
        self.record_json = record_to_json(records[1])
        self.otlp_log = map_record_to_otlp_log(self.record_json)

    def test_severity_is_warn(self):
        self.assertEqual(self.otlp_log["severityText"], "WARN")
        self.assertEqual(self.otlp_log["severityNumber"], 13)

    def test_type_attribute(self):
        attrs = {a["key"]: a["value"] for a in self.otlp_log["attributes"]}
        self.assertEqual(attrs["ahp.record.type"]["stringValue"], "GAP")

    def test_body_contains_gap_details(self):
        body = json.loads(self.otlp_log["body"]["stringValue"])
        self.assertEqual(body["first_lost_sequence"], 2)
        self.assertEqual(body["last_lost_sequence"], 5)
        self.assertEqual(body["reason"], "CRASH")


class TestOTLPBatchFormat(unittest.TestCase):
    """Verify the resourceLogs structure is valid OTLP."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.chain_path = os.path.join(self.tmpdir, "test.ahp")
        writer = ChainWriter(self.chain_path)
        writer.write_record(BootPayload(agent_name="test"))
        writer.write_record(
            ActionPayload(
                tool_name="tool_a",
                result_status=ResultStatus.SUCCESS,
                protocol=Protocol.MCP,
                action_type=ActionType.TOOL_CALL,
                authorization=Authorization(type=AuthorizationType.AUTH_NONE),
            )
        )
        writer.write_record(
            ActionPayload(
                tool_name="tool_b",
                result_status=ResultStatus.SUCCESS,
                protocol=Protocol.HTTP,
                action_type=ActionType.INFERENCE,
                model_id="claude-3",
                authorization=Authorization(type=AuthorizationType.AUTH_NONE),
            )
        )

        reader = ChainReader(self.chain_path)
        all_bytes = reader.read_all()
        self.log_records = []
        for stored in all_bytes:
            j = record_to_json(stored)
            self.log_records.append(map_record_to_otlp_log(j))

        self.exporter = OTLPExporter(service_name="test-ahp")

    def test_resource_logs_structure(self):
        payload = self.exporter.build_batch_payload(self.log_records)
        self.assertIn("resourceLogs", payload)
        self.assertEqual(len(payload["resourceLogs"]), 1)

    def test_resource_has_service_name(self):
        payload = self.exporter.build_batch_payload(self.log_records)
        resource = payload["resourceLogs"][0]["resource"]
        attrs = {a["key"]: a["value"] for a in resource["attributes"]}
        self.assertEqual(attrs["service.name"]["stringValue"], "test-ahp")

    def test_scope_logs_structure(self):
        payload = self.exporter.build_batch_payload(self.log_records)
        scope_logs = payload["resourceLogs"][0]["scopeLogs"]
        self.assertEqual(len(scope_logs), 1)
        self.assertEqual(scope_logs[0]["scope"]["name"], "ahp")
        self.assertEqual(scope_logs[0]["scope"]["version"], "0.1.0")

    def test_log_records_count(self):
        payload = self.exporter.build_batch_payload(self.log_records)
        records = payload["resourceLogs"][0]["scopeLogs"][0]["logRecords"]
        self.assertEqual(len(records), 3)

    def test_payload_is_valid_json(self):
        payload = self.exporter.build_batch_payload(self.log_records)
        serialized = json.dumps(payload)
        reparsed = json.loads(serialized)
        self.assertEqual(reparsed, payload)

    def test_each_log_record_has_required_fields(self):
        required_fields = [
            "timeUnixNano",
            "severityNumber",
            "severityText",
            "body",
            "attributes",
            "traceId",
            "spanId",
        ]
        for lr in self.log_records:
            for field in required_fields:
                self.assertIn(field, lr, f"Missing field: {field}")


class TestOTLPRealSend(unittest.TestCase):
    """Test OTLP export sending to a real HTTP endpoint."""

    def test_send_to_mock_collector(self):
        """Start a mock OTLP collector, send records, verify they arrive."""
        import json
        import threading
        from http.server import BaseHTTPRequestHandler, HTTPServer

        from ahp.core.chain import ChainWriter
        from ahp.core.records import ActionPayload, Authorization, BootPayload
        from ahp.core.types import ActionType, AuthorizationType, Protocol, ResultStatus
        from ahp.export.otlp import OTLPExporter

        received = []

        class OTLPHandler(BaseHTTPRequestHandler):
            def do_POST(self):
                content_length = int(self.headers.get("Content-Length", 0))
                body = json.loads(self.rfile.read(content_length))
                received.append(body)
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *a):
                pass

        server = HTTPServer(("localhost", 0), OTLPHandler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        try:
            tmpdir = tempfile.mkdtemp()
            chain_path = os.path.join(tmpdir, "otlp_test.ahp")
            writer = ChainWriter(chain_path)
            writer.write_record(BootPayload(agent_name="otlp-test"))
            writer.write_record(
                ActionPayload(
                    tool_name="test_tool",
                    result_status=ResultStatus.SUCCESS,
                    protocol=Protocol.MCP,
                    action_type=ActionType.TOOL_CALL,
                    authorization=Authorization(type=AuthorizationType.AUTH_NONE),
                )
            )
            writer.close()

            exporter = OTLPExporter(
                endpoint=f"http://localhost:{port}/v1/logs",
                service_name="ahp-test",
            )
            result = exporter.export_chain(chain_path)

            self.assertGreater(result["exported"], 0)
            self.assertEqual(result["failed"], 0)
            self.assertGreater(len(received), 0)

            payload = received[0]
            self.assertIn("resourceLogs", payload)
            resource_logs = payload["resourceLogs"]
            self.assertGreater(len(resource_logs), 0)
            scope_logs = resource_logs[0]["scopeLogs"]
            self.assertGreater(len(scope_logs), 0)
            log_records = scope_logs[0]["logRecords"]
            self.assertGreater(len(log_records), 0)

        finally:
            server.shutdown()


if __name__ == "__main__":
    unittest.main()

"""OTLP export -- sends AHP records as OTLP LogRecords via HTTP/JSON.

Maps AHP records to OpenTelemetry LogRecord format for export to
Datadog, Grafana, Splunk, or any OTLP-compatible backend.

Uses HTTP/JSON (not gRPC) for simplicity -- no protobuf dependency needed.
"""

from __future__ import annotations

import json
from typing import List
from urllib.error import URLError
from urllib.request import Request, urlopen

from ahp.core.chain import ChainReader
from ahp.core.json_format import record_to_json


def map_record_to_otlp_log(record_json: dict) -> dict:
    """Map an AHP record JSON to an OTLP LogRecord.

    OTLP LogRecord format:
    https://opentelemetry.io/docs/specs/otel/logs/data-model/
    """
    body_value = json.dumps(record_json.get("payload", {}))
    severity = "INFO"

    if record_json["type"] == "ACTION":
        status = record_json.get("payload", {}).get("result_status", "")
        if status in ("ERROR", "FAILURE", "TIMEOUT"):
            severity = "ERROR"
    elif record_json["type"] == "GAP":
        severity = "WARN"

    severity_number = {"INFO": 9, "WARN": 13, "ERROR": 17}.get(severity, 9)

    attributes = [
        {"key": "ahp.record.type", "value": {"stringValue": record_json["type"]}},
        {"key": "ahp.record.sequence", "value": {"intValue": str(record_json["sequence"])}},
        {"key": "ahp.agent.id", "value": {"stringValue": record_json["agent_id"]}},
        {"key": "ahp.session.id", "value": {"stringValue": record_json["session_id"]}},
        {"key": "ahp.schema.version", "value": {"intValue": str(record_json["schema_version"])}},
    ]

    if record_json["type"] == "ACTION":
        p = record_json.get("payload", {})
        attributes.extend(
            [
                {"key": "ahp.action.tool_name", "value": {"stringValue": p.get("tool_name", "")}},
                {"key": "ahp.action.type", "value": {"stringValue": p.get("action_type", "")}},
                {"key": "ahp.action.protocol", "value": {"stringValue": p.get("protocol", "")}},
                {"key": "ahp.action.status", "value": {"stringValue": p.get("result_status", "")}},
                {"key": "ahp.action.duration_ms", "value": {"intValue": str(p.get("response_time_ms", 0))}},
                {"key": "ahp.auth.type", "value": {"stringValue": p.get("authorization", {}).get("type", "")}},
            ]
        )
        if p.get("model_id"):
            attributes.append({"key": "ahp.inference.model", "value": {"stringValue": p["model_id"]}})
        if p.get("provider"):
            attributes.append({"key": "ahp.inference.provider", "value": {"stringValue": p["provider"]}})
        if p.get("cache_read_tokens"):
            attributes.append(
                {"key": "ahp.usage.cache_read_tokens", "value": {"intValue": str(p["cache_read_tokens"])}}
            )
        if p.get("cache_creation_tokens"):
            attributes.append(
                {"key": "ahp.usage.cache_creation_tokens", "value": {"intValue": str(p["cache_creation_tokens"])}}
            )
        if p.get("reasoning_tokens"):
            attributes.append({"key": "ahp.usage.reasoning_tokens", "value": {"intValue": str(p["reasoning_tokens"])}})
        if p.get("cost_nano_usd"):
            attributes.append({"key": "ahp.usage.cost_nano_usd", "value": {"intValue": str(p["cost_nano_usd"])}})

    return {
        "timeUnixNano": str(record_json["timestamp_ms"] * 1_000_000),
        "severityNumber": severity_number,
        "severityText": severity,
        "body": {"stringValue": body_value},
        "attributes": attributes,
        "traceId": "",
        "spanId": "",
    }


class OTLPExporter:
    """Exports AHP records to an OTLP collector via HTTP/JSON."""

    def __init__(
        self, endpoint: str = "http://localhost:4318/v1/logs", service_name: str = "ahp", batch_size: int = 100
    ):
        self.endpoint = endpoint
        self.service_name = service_name
        self.batch_size = batch_size
        self._exported_offset = 0

    def export_chain(self, chain_path: str) -> dict:
        """Export all un-exported records from a chain file.

        Returns: {"exported": N, "failed": M, "total": T}
        """
        reader = ChainReader(chain_path)
        all_bytes = reader.read_all()

        # Skip already exported
        pending = all_bytes[self._exported_offset :]
        if not pending:
            return {"exported": 0, "failed": 0, "total": len(all_bytes)}

        exported = 0
        failed = 0

        # Process in batches
        for i in range(0, len(pending), self.batch_size):
            batch = pending[i : i + self.batch_size]
            log_records = []

            for stored in batch:
                try:
                    j = record_to_json(stored)
                    otlp_log = map_record_to_otlp_log(j)
                    log_records.append(otlp_log)
                except Exception:
                    failed += 1

            if log_records:
                success = self._send_batch(log_records)
                if success:
                    exported += len(log_records)
                else:
                    failed += len(log_records)

        self._exported_offset += exported
        return {"exported": exported, "failed": failed, "total": len(all_bytes)}

    def _send_batch(self, log_records: List[dict]) -> bool:
        """Send a batch of OTLP LogRecords to the collector."""
        payload = {
            "resourceLogs": [
                {
                    "resource": {
                        "attributes": [
                            {"key": "service.name", "value": {"stringValue": self.service_name}},
                        ]
                    },
                    "scopeLogs": [
                        {
                            "scope": {"name": "ahp", "version": "0.1.0"},
                            "logRecords": log_records,
                        }
                    ],
                }
            ]
        }

        try:
            body = json.dumps(payload).encode()
            req = Request(
                self.endpoint,
                data=body,
                headers={
                    "Content-Type": "application/json",
                },
            )
            with urlopen(req, timeout=10) as resp:
                return resp.status == 200
        except (URLError, OSError):
            return False

    def export_record(self, record_json: dict) -> bool:
        """Export a single record immediately."""
        otlp_log = map_record_to_otlp_log(record_json)
        return self._send_batch([otlp_log])

    def build_batch_payload(self, log_records: List[dict]) -> dict:
        """Build the full OTLP resourceLogs payload without sending.

        Useful for testing and debugging the payload structure.
        """
        return {
            "resourceLogs": [
                {
                    "resource": {
                        "attributes": [
                            {"key": "service.name", "value": {"stringValue": self.service_name}},
                        ]
                    },
                    "scopeLogs": [
                        {
                            "scope": {"name": "ahp", "version": "0.1.0"},
                            "logRecords": log_records,
                        }
                    ],
                }
            ]
        }

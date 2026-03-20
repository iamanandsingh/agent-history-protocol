# AHP -- Agent History Protocol

The Agent History Protocol (AHP) is an open standard for tamper-evident recording of AI agent actions. Every tool call, inference, and delegation is written to a hash-chained log that anyone can verify — a flight recorder for AI agents.

## Documents

1. **This README** — quickstart and CLI reference
2. **[Specification](agent-history-protocol-spec.md)** — normative protocol spec for implementers

## Prerequisites

- Python 3.9+
- Optional: `cryptography` package (for Ed25519 signing, Level 2+)

## Install

```
pip install ahp
```

## Quickstart

Record an agent action and inspect the log:

```python
from ahp.core.chain import ChainWriter
from ahp.core.records import ActionPayload, Authorization, BootPayload
from ahp.core.types import (
    ResultStatus, Protocol, ActionType, AuthorizationType,
)

writer = ChainWriter("my-agent.ahp")
writer.write_record(BootPayload(agent_name="my-agent"))
writer.write_record(ActionPayload(
    tool_name="read_file",
    result_status=ResultStatus.SUCCESS,
    protocol=Protocol.MCP,
    action_type=ActionType.TOOL_CALL,
    authorization=Authorization(type=AuthorizationType.AUTH_NONE),
))
```

Then view the log:

```
$ ahp log --chain my-agent.ahp

   # | Time     | Type       | Tool/Name                 | Status  | Auth                 |  Latency
-----------------------------------------------------------------------------------------------
   1 | 14:32:01 | BOOT       | --                        | --      | --                   |       --
   2 | 14:32:01 | TOOL_CALL  | read_file                 | SUCCESS | AUTH_NONE            |     42ms
```

## CLI Commands

```
ahp log    [--chain FILE] [--last N]         Show records
ahp show   <seq> [--chain FILE] [--tree]     Show record details
ahp verify [--chain FILE]                    Verify chain integrity
ahp export [--chain FILE]                    Export as JSON
ahp trace  <session_prefix> [--chain FILE]   Trace session decisions
ahp gaps   [--chain FILE]                    List gap records
ahp init   [<agent_name>]                    Setup wizard
ahp keygen                                   Generate Ed25519 keypair
```

## Export

Export to JSONL, CSV, or OTLP (OpenTelemetry):

```python
from ahp.export import export_jsonl, export_csv, OTLPExporter

export_jsonl("my-agent.ahp", "audit.jsonl")
export_csv("my-agent.ahp", "audit.csv")

exporter = OTLPExporter(endpoint="http://localhost:4318/v1/logs")
exporter.export_chain("my-agent.ahp")
```

## Verify

```
$ ahp verify --chain my-agent.ahp

Verifying chain: my-agent
Records: 42

Checking hash chain...  ██████████████████████████████ 42/42

CHAIN VALID
   Hash chain:    42 records verified, 0 broken links
   Gaps:          0
```

## Specification

Full protocol specification: [agent-history-protocol-spec.md](agent-history-protocol-spec.md)

## License

Apache 2.0 — see [LICENSE](LICENSE).

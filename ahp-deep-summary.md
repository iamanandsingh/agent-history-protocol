# Agent History Protocol (AHP) — Deep Summary

Version: Based on AHP Spec v1.0-draft-01 and PSD v0.2 · March 2026

---

## 1. What AHP Is

The Agent History Protocol (AHP) is an open standard (Apache 2.0) for recording what AI agents do. Every time an AI agent calls a tool, reasons via an LLM, delegates work to another agent, or takes any action, AHP produces a small, tamper-evident record. These records form a hash-chained, independently verifiable history — a flight recorder for AI agents.

**One-line pitch:** AHP is to agent actions what Git is to code changes — an append-only, hash-chained history that anyone can verify.

AHP is a protocol specification, not a product. The specification defines the record format, hash chain construction, evidence model, witness protocol, and conformance levels. SDKs implement the specification. Anyone can build an SDK, a witness service, or a verification tool.

### The Problem It Solves

AI agents are moving from demos to production at scale. MCP defines how agents talk to tools. A2A defines how agents talk to each other. Neither defines how to record, verify, or query the history of those interactions. Every company deploying AI agents is building custom logging — proprietary formats, no integrity guarantees, no cross-system interoperability, no independent verification.

AHP fills that gap: it provides a single standard for recording agent actions across all protocols and frameworks, with hash chain integrity that anyone can verify without needing the SDK that wrote the records.

### Why Now (2026)

Three forces converge: scale (the agent market is growing rapidly, with broad adoption predicted), regulation (the EU AI Act's high-risk provisions become fully enforceable in August 2026), and incidents (unauthorized account creation, data exfiltration via skills, hundreds of vulnerabilities found in platform audits). Organizations need a standard way to prove what their agents did.

---

## 2. Protocol Specification in Detail

### 2.1 Design Principles

**Protocol vs. Implementation Separation.** The spec defines WHAT (record format, hash chain rules, witness API, conformance levels). SDK guides define HOW (staging files, interceptors, crash recovery, OTLP export). This keeps the normative spec minimal and lets implementations optimize freely.

**Incremental Adoption.** Four conformance levels form a ramp: Level 0 (development, JSON logs), Level 1 (hash chain), Level 2 (Ed25519 signed), Level 3 (externally witnessed). Each level adds security guarantees on top of the previous. The record structure is the same at all levels — upgrading requires changing one config parameter.

**Configurable Recording.** AHP defines the mechanism. The operator defines the policy. A BootRecord documents what was configured, so auditors know exactly what was being recorded (and what wasn't) at any point in time.

**Honest Security Claims.** AHP provides tamper-evidence, not tamper-prevention. The spec explicitly documents what each level defends against and what it does not.

**Fail-Open.** AHP must never crash or block the agent. If recording fails, the agent continues and a GapRecord is emitted when the SDK recovers.

### 2.2 Data Model

Every AHP record shares a common envelope enabling hash chain verification without needing to understand the payload:

| Field | Type | Description |
|-------|------|-------------|
| `record_id` | UUID v7 (16 bytes) | Unique identifier for this record |
| `agent_id` | UUID v7 (16 bytes) | Which agent produced this record |
| `session_id` | UUID v7 (16 bytes) | Logical session grouping |
| `timestamp_ms` | uint64 | Wall-clock UTC milliseconds |
| `sequence` | uint64 | Monotonic per agent, no gaps except via GapRecords |
| `prev_hash` | bytes[32] | SHA-256 of the previous record's stored bytes |
| `schema_version` | uint32 | Protocol version (v1.0 = 1) |
| `type` | enum | ACTION, GAP, CHECKPOINT, BOOT, RECOVERY, KEY, WITNESS |
| `payload` | oneof | Type-specific data |

The genesis record has `prev_hash` = 32 zero bytes and `sequence` = 1.

### 2.3 Record Types (7 in v1.0)

#### ActionRecord (type = ACTION)

The core record type. Captures one agent action — a tool call, LLM inference, delegation, or message.

Key fields:
- `parent_action_id` (optional UUID v7): Causal parent. Links tool calls back to the INFERENCE that decided to make them, forming a decision tree.
- `tool_name` (string): What was called (e.g., `"read_file"`, `"openai.chat.completions"`, `"anthropic.messages"`).
- `parameters_hash` (bytes[16]): SHA-256 truncated to 128 bits of the filtered input parameters.
- `result_hash` (bytes[16]): SHA-256 truncated to 128 bits of the filtered result.
- `result_status` (enum): SUCCESS, FAILURE, TIMEOUT, ERROR.
- `response_time_ms` (uint32): Request-to-response duration.
- `protocol` (enum): MCP, HTTP, GRPC, A2A, SHELL, CUSTOM.
- `action_type` (enum): TOOL_CALL, INFERENCE, DELEGATION, MESSAGE, CUSTOM.
- `target_entity` (string, optional): What was acted on (e.g., a database name, file path).
- `evidence_uri` (string, optional): Where the full payload content is stored.
- `redacted` (bool): True if PII filters matched and modified the content before hashing.
- `model_id` (string, optional): LLM model identifier. MUST be set when `action_type = INFERENCE`.
- `input_token_count` / `output_token_count` (uint32, optional): Token usage for INFERENCE.
- `authorization` (Authorization): Who approved the action (see Authorization Model below).

**Inference semantics.** When `action_type = INFERENCE`, `parameters_hash` covers the prompt and `result_hash` covers the full response including reasoning/thinking tokens. Tool calls resulting from inference MUST set `parent_action_id` to the INFERENCE record's `record_id`. Sequential INFERENCE records SHOULD chain via `parent_action_id` for conversational continuity. INFERENCE ActionRecords MUST be emitted after the complete response is received (for streaming).

#### GapRecord (type = GAP)

Explicitly documents lost records. Instead of silently having missing sequence numbers, AHP requires a GapRecord explaining what was lost and why.

Fields: `first_lost_sequence`, `last_lost_sequence`, `count`, `reason` (enum: CRASH, DISK_FULL, DISK_CORRUPT, ROTATION, INTERCEPTOR_FAILURE, BACKPRESSURE, MANUAL_PURGE), `detail` (optional string).

The GapRecord's own `sequence` equals `last_lost_sequence + 1`. The constraint `count == last_lost_sequence - first_lost_sequence + 1` must hold.

#### BatchCheckpoint (type = CHECKPOINT)

Periodic chain summary containing: `record_count`, `gap_count`, `chain_hash` (current head hash), optional `merkle_root` (RFC 6962 Merkle tree of records since last checkpoint), optional `signature` (Ed25519 over merkle_root, required at Level 2+), `signing_key_id`, and `evidence_status` counts (available, exported, expired, missing).

#### BootRecord (type = BOOT)

Emitted at SDK startup and whenever configuration changes. Documents the recording policy that was active: SDK name/version, active interceptors, agent framework, agent name, runtime, chain level, fsync mode, whether inference and evidence are being recorded, `filter_config_hash` (SHA-256 of the active filter configuration), whether authorization recording is enabled, and which config source was used.

This means an auditor can look at any BootRecord and know exactly what was being recorded at that point.

#### RecoveryRecord (type = RECOVERY)

Emitted after crash recovery. Documents: `records_verified`, `records_truncated`, `last_valid_seq`, `recovery_method` (CHECKPOINT_FILE, CHAIN_SCAN, FRESH_START), and a human-readable `detail`.

After a crash with data loss, the SDK emits a RecoveryRecord first (documenting findings) and then a GapRecord (documenting the unrecoverable range).

#### KeyGenesisRecord (type = KEY)

Establishes or rotates a signing identity. Contains: Ed25519 `public_key`, `key_id` (SHA-256 of public key), optional `expires_at`, and optional `supersedes_key_id` (for key rotation).

Key rotation handoff protocol: (1) Emit KeyGenesisRecord with new key and `supersedes_key_id`. (2) Next BatchCheckpoint signed by OLD key (covers the rotation record). (3) Following BatchCheckpoint signed by NEW key (proves continuity). Both checkpoints create an auditable signed handoff.

#### WitnessReceipt (type = WITNESS)

External attestation stored in the chain. Contains: `witness_id`, `checkpoint_seq`, `checkpoint_hash`, `witness_timestamp` (witness's own clock), `receipt_signature` (Ed25519), `witness_public_key`.

### 2.4 Authorization Model

Authorization answers "who allowed this action?" — distinct from `parent_action_id` which answers "what decided to do it?" Every ActionRecord MUST set `authorization.type` to a valid value.

**Authorization types:**
- `AUTH_NONE`: No authorization required (entries must be empty)
- `AUTH_HUMAN`: Human operator approved (exactly 1 entry)
- `AUTH_AGENT`: Supervisor/peer agent approved (exactly 1 entry)
- `AUTH_POLICY`: Automated policy engine approved (exactly 1 entry)
- `AUTH_MULTI_PARTY`: Multiple authorizers required (2+ entries, may mix types)

Each AuthorizationEntry contains: `authorizer_type` (HUMAN, AGENT, POLICY_ENGINE), `authorizer_id` (human-readable), optional `authorizer_agent_id` (UUID for cross-chain linking), optional `authorizer_seq` (sequence in authorizer's chain), `decision` (APPROVED, REJECTED, CONDITIONAL), optional `condition`, and `timestamp_ms`.

**Cross-chain verification (double-entry bookkeeping).** When agent B authorizes agent A's action, both chains record the event. Agent A's chain references `authorizer_agent_id` + `authorizer_seq` pointing to the approval record in Agent B's chain. The `ahp reconcile` command cross-references these and flags discrepancies.

**Rejected actions.** When authorization is rejected, the agent SHOULD still emit an ActionRecord with `result_status = ERROR` and `decision = REJECTED`, so auditors can count unauthorized action attempts.

### 2.5 Canonical Serialization

Hash chain integrity requires byte-identical output from any conformant implementation. The canonical serialization rules are:

1. All fields in ascending tag number order (per Protobuf schema)
2. Integers as fixed-width little-endian (uint32 = 4 bytes, uint64 = 8 bytes)
3. Strings as UTF-8 with uint32 LE length prefix
4. UUIDs as 16 raw bytes (no dashes)
5. Fixed-length byte arrays as raw bytes (no length prefix): prev_hash = 32B, parameters_hash/result_hash = 16B, signature = 64B
6. Booleans as 1 byte (0x00/0x01)
7. Enums as uint32 LE
8. Every field present, including optionals (zero-filled when unset)
9. Repeated fields with uint32 count prefix
10. Payload as uint32 type tag + payload fields in order
11. Nested messages serialized inline

**stored_bytes = canonical_bytes.** Records are stored in canonical form. Verification only requires hashing the stored bytes — no re-serialization needed. This is critical for forward compatibility: a verifier encountering an unknown record type can still verify the hash chain.

### 2.6 Hash Chain

**Algorithm:** SHA-256 everywhere. Full 256-bit for chain integrity (`prev_hash`). Truncated to 128 bits for content hashes (`parameters_hash`, `result_hash`). FIPS 140-2 compliant.

**Genesis:** First record has `prev_hash` = 32 zero bytes, `sequence` = 1.

**Chaining:** `Record_N.prev_hash = SHA-256(stored_bytes(Record_{N-1}))`

**Verification:** For each record, check that `prev_hash` equals SHA-256 of the previous record's stored bytes. Check sequence monotonicity. Validate GapRecord constraints. Anyone with SHA-256 can verify — no SDK needed.

### 2.7 Evidence Model

The chain stores hashes. The evidence store stores content. They're linked by hash.

```
Chain:     ActionRecord { parameters_hash: 0xa1b2c3d4... }
                              |
Evidence:  evidence/a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6
```

Evidence files are content-addressed: filename = hex of the 128-bit truncated hash. Files contain the raw bytes that were hashed (after PII filtering). `evidence_uri` may point to a retrieval location (local path, S3, HTTP URL). Evidence recording is optional and configurable per-agent.

Evidence statuses: AVAILABLE, EXPORTED (shipped externally, local copy may be deleted), EXPIRED (deleted per retention policy), ERASED (deleted per GDPR/privacy request), MISSING (expected but not found).

### 2.8 Signing (Level 2+)

Before signing, the SDK emits a KeyGenesisRecord. BatchCheckpoints include a Merkle root (RFC 6962) of all records since the last checkpoint, signed with Ed25519. The `signing_key_id` identifies which key signed.

### 2.9 Witness Protocol (Level 3)

Independent services receive chain state and issue signed receipts.

**Checkpoint API:**
- `POST /ahp/v1/checkpoints` — Agent sends: agent_id, chain_hash, sequence, timestamp, signature, signing_key_id. Witness returns: receipt_id, witness_id, witness_timestamp, witness_signature.
- `GET /ahp/v1/receipts/{receipt_id}` — Retrieve full receipt.
- `GET /ahp/v1/agents/{agent_id}/checkpoints?after_seq=N` — List receipts for agent.
- `GET /ahp/v1/identity` — Get witness's public key.

**Guarantees:** Agent's signature prevents witness from fabricating checkpoints. Witness's signature prevents agent from fabricating receipts. A witnessed checkpoint makes it impossible for the operator to reduce record count below N or rewrite history before N without detectable discrepancy. Multiple independent witnesses make collusion harder. Witness timestamps provide independent time anchors against clock manipulation.

If a witness is unavailable, the SDK retries with exponential backoff (3 retries). If all fail, the chain continues without a WitnessReceipt. The gap in witness coverage is detectable by the absence of receipts.

### 2.10 Context Propagation

AHP uses W3C Trace Context for cross-agent linking. The `traceparent` header carries a shared `trace_id` across all agents. The `tracestate` header carries AHP-specific data under key `"ahp"`, encoded as `base64url(agent_id || sequence_uint64_be || chain_hash_16bytes)` — 40 raw bytes, 54 characters encoded. If middleware strips tracestate, records still exist independently; graceful degradation.

### 2.11 Configuration

A single configuration file (YAML/TOML/JSON) controls all recording behavior:

```yaml
defaults:
  level: 2                        # 1=chain, 2=signed, 3=witnessed
  inference:
    record: true                  # emit INFERENCE ActionRecords
    evidence: true                # store full prompts/responses
  evidence:
    record: true                  # store tool call payloads
  authorization:
    record: false                 # record who approved each action
  fsync_mode: batch               # every | batch | none
  checkpoint_interval: 1000       # records between checkpoints
  witness:
    enabled: false
    interval: 1000
    endpoints: []

filters:                          # PII filters applied before hashing
  - name: credit_card
    pattern: '\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b'
    replacement: '[REDACTED:CC]'
    scope: [parameters, results]

agents:                           # Per-agent overrides
  - match: "customer-support-*"
    level: 3
    witness:
      enabled: true
```

**PII filters** run before hashing. Pipeline: classify payload type → apply all matching filters in order → hash the filtered content → store filtered content in evidence. All SDKs must ship identical built-in filter presets: `pci`, `pii-us`, `pii-eu`, `credentials`, `hipaa`. The BootRecord includes `filter_config_hash` so auditors know which filters were active.

**Filter scopes:** `parameters`, `results`, `inference_system_message` (just the system prompt), `inference_prompt`, `inference_response`, `all`.

**Per-agent overrides** use glob matching on agent_name. Agent-level filters are appended (global run first). All other fields override defaults.

When configuration is hot-reloaded, the SDK emits a new BootRecord documenting the change.

---

## 3. Key Concepts and Terminology

- **Record**: A single AHP data unit (envelope + typed payload). ~200 bytes typical.
- **Chain**: Ordered sequence of records with tamper-evident hash linking. Append-only.
- **Evidence**: Full payload content stored separately from the chain, linked by hash.
- **Witness**: Independent third-party service issuing signed receipts for chain state.
- **Operator**: Entity deploying and controlling the agent.
- **Session**: Logical grouping identified by UUID v7 (`session_id`).
- **Inference**: LLM API call captured as ActionRecord with `action_type = INFERENCE`.
- **Gap**: Range of lost records explicitly documented by a GapRecord.
- **Causality**: Determined by `parent_action_id`, not timestamps. Forms a tree.
- **Double-Entry Bookkeeping**: When two agents interact, both record the event independently. Discrepancies are detectable by cross-referencing.
- **Tamper-Evidence**: The property that any modification to the chain is detectable. Not the same as tamper-prevention.

---

## 4. Conformance Levels

### Level 0: Development Mode (Non-Conformant)

Records emitted as JSON. No hash chain, sequence numbers, or structural records required. Provides a low-friction entry point (`pip install ahp && ahp log`). Not conformant — no integrity guarantees.

### Level 1: Hash Chain (Core Conformance)

MUST emit ActionRecord for every intercepted action. MUST maintain SHA-256 hash chain over canonical bytes. MUST use monotonic sequences with GapRecords for any losses. MUST emit BootRecord at startup and on config change. MUST emit RecoveryRecord after crash recovery. MUST apply PII filters before hashing. MUST support inference recording configuration. MUST set parent_action_id to link tool calls to causing inference. MUST set authorization.type on all ActionRecords. MUST provide canonical-to-JSON conversion for human inspection.

### Level 2: Signed Chain (adds to Level 1)

MUST emit KeyGenesisRecord before first signed checkpoint. MUST sign BatchCheckpoints with Ed25519 (Merkle root). MUST follow key rotation handoff protocol. SHOULD checkpoint every 1000 records or 60 seconds.

### Level 3: Witnessed Chain (adds to Level 2)

MUST checkpoint to at least one witness. MUST store WitnessReceipt in chain. MUST sign checkpoints sent to witnesses. MUST NOT rotate chain segments until exported and acknowledged. SHOULD use 2+ independent witnesses. Recommended: gaps < 0.01% of records per 30-day window.

---

## 5. Architecture and How the Pieces Fit Together

### SDK Pipeline

```
Interceptor → Staging File → Single Writer → Chain File + Evidence Store → Exporter
```

**Interceptors** capture protocol-specific events (MCP tool calls, HTTP requests, gRPC calls, A2A tasks) and convert them to ActionPayload records. They monkey-patch or wrap existing client libraries transparently.

**Staging File** absorbs parallel writes from multiple interceptors. Includes monotonic IDs for deduplication after crash recovery.

**Single Writer** reads from staging, applies PII filters, computes hashes, assigns sequence/prev_hash, and writes finalized canonical bytes to the chain file + evidence store.

**Chain File** is the append-only binary file. Format: 16-byte header (magic "AHP\0" + version + creation timestamp), then repeated entries of [4B length][NB canonical_bytes][4B CRC32C]. Segments rotate at 64 MB.

**Evidence Store** is a directory of content-addressed files. Filename = hex of 128-bit truncated SHA-256 hash. Contents = raw bytes after PII filtering.

**Exporter** ships records to external systems. Primary export is OTLP (OpenTelemetry Protocol) for compatibility with Datadog, Grafana, Splunk, etc. Also supports JSONL and CSV.

### Multi-Agent Architecture

Each agent process has its own SDK instance with its own chain file and evidence store. No shared state. Cross-agent linking uses W3C Trace Context headers (`traceparent` + `tracestate`). Backend systems stitch traces via shared `trace_id`.

Cross-agent integrity uses double-entry bookkeeping: both sides record independently and discrepancies are detectable at query time. With Level 3 witnesses, timelines are independently verifiable.

### Crash Recovery

Deterministic 6-step protocol: scan chain for last valid record (CRC32 verification), truncate corrupt trailing data, emit RecoveryRecord, emit GapRecord for lost range, resume normal operation.

Three fsync modes trade durability vs. performance: `every` (~500-2K records/sec, lose 0), `batch` (~50K/sec, lose ≤100), `none` (~200K/sec, lose ~30s data).

---

## 6. Package Structure

### Python SDK (`ahp/`)

The main implementation. Package version 0.1.0-alpha. Python 3.9+. Apache 2.0.

**Core modules (`ahp/core/`):**
- `types.py`: All enums (RecordType, ResultStatus, Protocol, ActionType, AuthorizationType, etc.) and constants (ZERO_HASH_32, ZERO_HASH_16, SCHEMA_VERSION=1).
- `records.py`: Dataclass definitions for all payload types (ActionPayload, GapPayload, CheckpointPayload, BootPayload, RecoveryPayload, KeyPayload, WitnessPayload) plus Authorization and AuthorizationEntry.
- `canonical.py`: Deterministic byte serialization per Section 4 of the spec. `canonical_bytes(record)` produces identical output across implementations.
- `chain.py`: ChainWriter (thread-safe append with hash chain, CRC32, file locking, fsync modes), ChainReader (streaming iterator, range queries, CRC verification), and binary parsers for all payload types (parse_envelope, parse_action_payload, etc.).
- `async_chain.py`: AsyncChainWriter using asyncio.Queue for non-blocking writes.
- `verify.py`: `verify_chain()` — checks hash chain integrity, sequence monotonicity, and GapRecord constraints. Returns VerifyResult.
- `evidence.py`: EvidenceStore — content-addressed file storage (store, retrieve, verify, count).
- `filters.py`: FilterPipeline with built-in presets (pci, pii-us, pii-eu, credentials, hipaa). Applies regex-based PII filters and computes hashes.
- `signing.py`: Ed25519 keypair generation, signing, verification. RFC 6962 Merkle tree computation.
- `context.py`: W3C Trace Context propagation (traceparent/tracestate encoding/decoding).
- `uuid7.py`: UUID v7 generation per RFC 9562.
- `validation.py`: Record validation (field lengths, enum validity, authorization constraints, size limits).
- `recovery.py`: Chain scanning and truncation for crash recovery.
- `rotation.py`: ChainRotator for 64 MB segment management with export-gated deletion.
- `witness_client.py`: HTTP client for witness checkpoints with exponential backoff.
- `json_format.py`: Canonical bytes to human-readable JSON conversion.

**Recorders:**
- `recorder.py`: AHPRecorder — main sync SDK entry point. Thread-safe. Wires together chain writer + evidence + filters + signing + witness + context. Fail-open design. Factory method `from_config()`.
- `async_recorder.py`: AsyncAHPRecorder — async version for asyncio frameworks.
- `_base_recorder.py`: Shared logic (init components, filter-and-hash, store evidence, create payloads).

**Interceptors (`ahp/interceptors/`):**
- `http_auto.py`: Monkey-patches `urllib.request.urlopen` for transparent HTTP capture.
- `http_helper.py`: Creates ActionPayload from HTTP data. Auto-detects LLM APIs (OpenAI, Anthropic, Google, Cohere, Mistral) via URL patterns. Extracts model_id and token counts.
- `mcp_auto.py`: Monkey-patches `mcp.ClientSession.call_tool` for transparent MCP capture.
- `mcp_helper.py`: Creates ActionPayload from MCP tool call data.
- `grpc.py`: gRPC UnaryUnaryClientInterceptor for transparent gRPC capture.

**Protocol implementations (`ahp/protocols/`):**
- `a2a.py`: A2AServer with task management (SUBMITTED, WORKING, AUTH_REQUIRED, COMPLETED, FAILED states) and AHP recording.
- `mcp_client.py`: MCPClient for JSON-RPC tool calls over HTTP with AHP recording.
- `mcp_server.py`: MCPToolServer — JSON-RPC 2.0 server hosting tools.

**Export (`ahp/export/`):**
- `jsonl.py`: Export to JSONL and CSV formats.
- `otlp.py`: OTLPExporter — maps AHP records to OTLP LogRecords. Batched HTTP/JSON export compatible with OpenTelemetry collectors.

**Integrations (`ahp/integrations/`):**
- `langchain.py`: AHPCallbackHandler for LangChain (BaseCallbackHandler). Records tool starts/ends and LLM starts/ends.

**CLI (`ahp/cli/main.py`):**
- `ahp log` — Show records with filtering (agent, session, tool, status, time, authorization).
- `ahp show <seq>` — Full record details. `--tree` for causal tree.
- `ahp verify` — Verify chain integrity.
- `ahp export` — Export as JSONL/CSV.
- `ahp trace <session>` — Trace session decisions.
- `ahp gaps` — List gap records.
- `ahp init` — Setup wizard.
- `ahp keygen` — Generate Ed25519 keypair.

**Configuration (`ahp/config.py`):**
- AHPConfig dataclass with FilterConfig, WitnessConfig.
- `load_config()`: Search order: explicit path → env var → ./ahp.yaml → ~/.ahp/config.yaml → defaults.
- Per-agent overrides via fnmatch glob patterns.

### TypeScript SDK (`packages/sdk-typescript/`)

Version 0.1.0-alpha. Node 18+. Implements the same core protocol for cross-SDK interoperability.

- `types.ts`: Complete data model — all enums and interfaces matching the Python SDK exactly.
- `canonical.ts`: BufferWriter class and `canonicalBytes()` function. Must produce byte-for-byte identical output as the Python implementation.
- `chain.ts`: ChainWriter and ChainReader with the same binary file format (magic, version, CRC32).
- `uuid7.ts`: UUID v7 generation per RFC 9562.
- `verify.ts`: `verifyChain()` with identical logic to Python's verify_chain.
- `conformance.test.ts`: Cross-SDK test vectors ensuring the TypeScript SDK produces the same SHA-256 hash as Python for identical inputs. The test uses a specific ActionRecord test vector and verifies the hash equals `9cdbb99f78a5636458dd7939a5e71a867f9bf5d088bdec415c9cbd520f89ab66`.
- `index.ts`: Barrel export of all public API.

### Witness Server (`witness/server.py`)

Reference implementation (~150 lines). Pure Python HTTP server using stdlib only. Implements all endpoints from Section 8.1. SQLite-like storage via JSON file. Not production-grade — for testing and development.

---

## 7. How the Demo Works

### Simple Demo (`demo/agent.py`)

Creates a realistic customer support agent scenario with hand-crafted records. Demonstrates:

1. **Agent boot**: BootRecord documenting SDK config.
2. **Simple query** (Scenario 1): INFERENCE → TOOL_CALL (search_orders) with AUTH_NONE. Shows basic causal linking.
3. **Refund processing** (Scenario 2): INFERENCE → TOOL_CALL (process_refund) with AUTH_HUMAN. Shows human authorization.
4. **Account deletion** (Scenario 3): INFERENCE → TOOL_CALL (delete_account) with AUTH_MULTI_PARTY requiring both agent and human approval. Shows multi-party authorization.

Writes a real chain file (`support-bot.ahp`) with proper hash chain integrity.

### Full Demo (`demo/run_full_demo.py`)

Orchestrates a 6-act demonstration:
1. Run the agent demo
2. View chain logs (`ahp log`)
3. Show a decision chain (`ahp show --tree`)
4. Demonstrate tamper detection (modifies a record, then `ahp verify` catches it)
5. Show compliance export
6. Verify final chain integrity

### Tamper Demo (`demo/tamper.py`)

Modifies a record in the binary chain file to demonstrate tamper detection. Shows that even if an attacker recalculates the CRC32, the hash chain verification catches the tampering because `prev_hash` values no longer match.

### Showcase Demo (`demo/showcase/`)

A complete multi-agent system with real LLM calls (Google Gemini Flash):

**Three agents:**
- **Support Agent** (`agents/support.py`): Handles customer messages, uses LLM to decide actions, executes real tools.
- **Supervisor Agent** (`agents/supervisor.py`): HTTP server that reviews and approves high-risk actions using LLM-based policy evaluation.
- **Safety Agent**: Referenced in config for additional oversight.

**Real tools** (`tools.py`): search_orders, search_docs, get_customer, process_refund, delete_account, send_reply — all with real file I/O against sandbox data.

**LLM client** (`llm.py`): Real HTTP calls to Gemini API with automatic AHP interception recording inference actions, token counts, and model IDs.

**Three scenarios demonstrated:**
1. Simple order query (no authorization needed)
2. Refund with supervisor approval (AUTH_AGENT → AUTH_HUMAN)
3. Account deletion with multi-party approval (requires both supervisor and human)

Each agent has its own chain file. The demo verifies chains, shows logs, demonstrates tamper detection, and displays cross-agent authorization flows.

---

## 8. Test Suite and Benchmarks

### Test Suite (18 test files)

The tests cover every aspect of the protocol:

**Core protocol tests:**
- `test_core.py`: UUID7 format, canonical serialization determinism, ChainWriter/Reader, hash chain verification, tamper detection, JSON export, authorization serialization.
- `test_serialization.py`: All 7 record types serialize/deserialize correctly (round-trip tests).
- `test_chain_complete.py`: Gaps, recovery, checkpoints, threading (10 threads × 10 records), interleaved sessions, complex gap scenarios.

**Async and concurrency:**
- `test_async.py`: AsyncChainWriter (concurrent 5-thread writes), AsyncAHPRecorder (auto-checkpoint, Level 2 signing, fail-open).
- `test_production.py`: Sustained load (10K records sync and async), 100 threads × 100 records, validation of malformed records, fsync modes.

**Interceptors and protocols:**
- `test_auto_http.py`: Transparent urllib interception, POST data preservation, error handling, response readability, install/uninstall lifecycle.
- `test_grpc_real.py`: Real gRPC server with AHP interception.
- `test_protocols.py`: Real MCP JSON-RPC calls, A2A task protocol.
- `test_integration.py`: LLM API detection (OpenAI/Anthropic/Stripe endpoints), inference vs. tool call classification, token extraction.
- `test_real.py`: Real HTTP calls against mock LLM server, multi-turn interaction.

**Features:**
- `test_context.py`: W3C Trace Context (traceparent/tracestate encoding/decoding, header injection/extraction).
- `test_recorder.py`: AHPRecorder lifecycle, PII filtering with presets.
- `test_rotation.py`: Chain file rotation at size limits, segment independence, export-gated deletion.
- `test_export.py`: OTLP LogRecord mapping, attribute mapping, severity levels.
- `test_sprint1.py`: Streaming reader, file locking, crash recovery, PII presets.
- `test_sprint4.py`: All 5 PII presets exist with correct patterns, MCP auto-patching.
- `test_remaining_gaps.py`: CLI trace/gaps commands with real data.

**Cross-SDK conformance:**
- `conformance.test.ts` (TypeScript): Test vector producing SHA-256 hash `9cdbb99f...` — ensures byte-for-byte compatibility with Python SDK.

### Benchmarks (`benchmarks/bench.py`)

Measures:
- **Serialization speed**: canonical_bytes() calls per second
- **Sync write throughput**: Records/second to disk
- **Async write throughput**: Records/second with asyncio
- **Verification speed**: Records/second for hash chain verification
- **Streaming read speed**: Records/second via iterator
- **Record size**: Bytes per record

### CI Pipeline (`.github/workflows/ci.yml`)

Matrix testing across Python 3.9, 3.10, 3.11, 3.12 on Ubuntu. Runs full test suite, benchmark smoke tests, and syntax validation of core modules.

---

## 9. Chains, Witnesses, and Evidence

### Chain Files

The repository contains example chain files from demo runs:

- `chains/support-bot.ahp`: Binary chain from the support bot agent, containing MCP and HTTP protocol actions (search_docs, send_reply, process_refund), with delegation to supervisor.
- `chains/supervisor-bot.ahp`: Binary chain from the supervisor agent, containing Gemini LLM inference calls and authorization decisions.
- `support-bot.ahp` (top-level): Chain file showing full agent workflow with anthropic.messages protocol (Claude Sonnet model), multi-role authorization, and varied tool calls.

### Evidence Files

The `evidence/` directory contains content-addressed files demonstrating the evidence linkage system. Each file is named by its 128-bit truncated SHA-256 hash and contains the actual payload that was hashed:

- `a20b52fae57cc7a99c9651f1b573950f` → "params"
- `f6a214f7a5fcda0c2cee9660b7fc29f5` → "result"
- `a4c9dc7783f9ae346c45fc33faa94072` → `{"model": "claude"}`
- `a59686a9a4c2e8ad9c1ab86ee13b8df3` → `{"query": "test"}`
- `6cecb20c79fa62eb775e45270a3cb9f2` → `{"results": []}`
- etc.

To verify: SHA-256 of the file contents, truncated to 16 bytes, should equal the filename when hex-encoded.

### Witness Server

The reference witness server (`witness/server.py`) is a minimal HTTP server implementing:

- `POST /ahp/v1/checkpoints`: Accepts checkpoint data, generates Ed25519 receipt signature, stores receipt, returns signed acknowledgment.
- `GET /ahp/v1/receipts/{id}`: Retrieves a specific receipt.
- `GET /ahp/v1/agents/{id}`: Lists all checkpoints for an agent.
- `GET /ahp/v1/identity`: Returns the witness's public key and identity.

Storage is a simple JSON file (`witness_receipts.json`). The witness generates its own Ed25519 keypair on startup. Receipt signatures cover the original checkpoint data plus the witness's own timestamp, making receipts independently verifiable.

### OpenClaw Integration Test

`test_openclaw/` demonstrates AHP integrated with the OpenClaw LLM library and Google Gemini API. The test makes real LLM calls and records them to a JSONL chain (Level 0). The output file (`openclaw_chain.jsonl`) shows three linked records with verified hash chain integrity, real token counts, and real response times.

---

## 10. Security Model Summary

### What AHP Defends Against (by level)

| Threat | Defense | Level |
|--------|---------|-------|
| Post-hoc tampering by third party | Hash chain detects any modification | 1+ |
| Record reordering | Sequence numbers + hash chain | 1+ |
| Silent record deletion | Missing sequence must be explained by GapRecord | 1+ |
| Cross-agent inconsistency | Double-entry: both sides record, discrepancies detectable | 1+ |
| Unauthorized action attempts | Authorization field + rejected action recording | 1+ |
| PII in audit trail | Configurable filters before hashing | 1+ |
| Forged chain authorship | Ed25519 signing identifies author | 2+ |
| Operator rewrites history | Witness has independent copy of chain state | 3 |
| Backdated/future-dated records | Witness timestamps as independent anchor | 3 |

### What AHP Does NOT Defend Against

- Operator not running the SDK (can't record what's not instrumented)
- Operator modifying SDK to skip actions (SDK runs in operator's process)
- Real-time suppression before the chain (interceptor in operator's control)
- Clock manipulation between checkpoints (agent controls own clock)
- Compromised signing keys (key compromise breaks Level 2)
- Witness collusion with operator (witness confirms false state)
- Agent fabricating authorization entries (agent controls own chain)

**Key principle:** AHP provides tamper-evidence, not tamper-prevention. Difficulty of undetected modification is proportional to conformance level.

---

## 11. What AHP Is NOT

- **Not observability**: Doesn't replace OpenTelemetry/Datadog/Prometheus. Exports via OTLP to complement them.
- **Not storage**: Defines record format and integrity model, not long-term storage.
- **Not prevention**: Records what agents did. Doesn't block agents from doing things.
- **Not blockchain**: No consensus, tokens, or distributed ledger. Just a hash chain (like Git) with optional witnesses.
- **Not PII detection**: Provides configurable filter patterns. Operator defines what counts as PII.
- **Not an LLM evaluation tool**: Records LLM calls as actions. Doesn't evaluate prompt quality or output accuracy.

---

## 12. Additional Materials

### Interactive Explainer (`index.html`)

A single-file HTML application using Babylon.js for 3D visualization. Ten animated slides walk through AHP concepts from the problem statement through hash chains, evidence stores, PII filtering, trust levels, witnesses, configuration, and the big picture. Designed for a non-technical audience.

### Explainer Script (`explainer-script.md`)

Detailed script and animation design document for the interactive explainer. Includes narrative strategy, analogies for each concept (flight recorders, receipt chains, notaries), and visual design specifications (color palette, typography, interaction patterns).

### Protocol Specification Document (`ahp-psd.md`)

Comprehensive "how and why" document covering market analysis, target users, design rationale, technical architecture details, CLI command specifications, framework integration points, threat model, pending work items, and open specification questions.

---

## Quick Reference

**Install:** `pip install ahp` (Python) or `npm install @ahp/sdk` (TypeScript)

**Record an action:**
```python
from ahp.recorder import AHPRecorder
recorder = AHPRecorder(agent_name="my-agent")
recorder.record_action(tool_name="search", parameters={"q": "test"}, result={"hits": 5})
```

**View the log:** `ahp log --chain my-agent.ahp`

**Verify integrity:** `ahp verify --chain my-agent.ahp`

**Export:** `ahp export --chain my-agent.ahp --format jsonl`

**Key file locations:**
- Spec: `agent-history-protocol-spec.md`
- PSD: `ahp-psd.md`
- Python SDK: `ahp/`
- TypeScript SDK: `packages/sdk-typescript/`
- Demo: `demo/`
- Tests: `tests/`
- Witness: `witness/`
- Evidence: `evidence/`
- Chains: `chains/`

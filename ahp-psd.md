# Agent History Protocol — Protocol Specification Document

Version 0.2 · March 2026

---

## 1. Protocol Overview

### What It Is

The Agent History Protocol (AHP) is an open standard (Apache 2.0) for recording what AI agents do. Every time an AI agent calls a tool, reasons via an LLM, delegates work to another agent, or takes any action, AHP produces a small, tamper-evident record. These records form a hash-chained, independently verifiable history — a flight recorder for AI agents.

AHP is a protocol specification, not a product. The specification defines the record format, hash chain construction, evidence model, witness protocol, and conformance levels. SDKs implement the specification. Anyone can build an SDK, a witness service, or a verification tool.

### One-Line Pitch

AHP is to agent actions what Git is to code changes — an append-only, hash-chained history that anyone can verify.

### The Problem

AI agents are moving from demos to production. McKinsey runs 25,000 AI agents alongside 40,000 humans. OpenClaw has 300,000-400,000 users running autonomous agents. 62% of organizations are experimenting with AI agents.

There is no standard way to record what these agents did.

MCP defines how agents talk to tools. A2A defines how agents talk to each other. Neither defines how to record, verify, or query the history of those interactions. Every company deploying AI agents is building custom logging — proprietary formats, no integrity guarantees, no cross-system interoperability, no independent verification.

When an agent charges a customer's credit card twice, there is no standardized record of what happened or why the agent decided to do it. When a regulator asks "show me everything your AI did to this customer last month," there is no system that can answer. When a malicious skill exfiltrates data, there is no audit trail proving it happened.

### Why Now

Three forces converging in 2026:

**Scale:** AI agent market $7.84B (2025) -> $52.62B by 2030. 35% of organizations report broad agent usage. McKinsey targets agent-to-human parity by end of 2026.

**Regulation:** EU AI Act high-risk provisions become fully enforceable August 2026. 40% of agentic AI projects predicted to be canceled by 2027 due to inadequate risk controls.

**Incidents:** Agents creating unauthorized accounts, data exfiltration via skills, 512 vulnerabilities in platform security audits. 51% of organizations using AI report at least one negative consequence.

The window is open: agents are deployed at scale, regulations are arriving, incidents are happening, and no standard exists.

---

## 2. Target Users

### Primary: Developers Building AI Agents

Engineers using LangChain, CrewAI, OpenAI Agents SDK, MCP, Mastra, or any agent framework. They need to see what their agents are doing during development and debugging — including the reasoning behind each action.

Entry point: `pip install ahp` / `npm install @ahp/sdk`
Value in 2 minutes: `ahp log --last 20` shows what the agent did and why.

### Secondary: Enterprise Platform Teams

Companies deploying agents at scale in any industry. They need centralized recording policy, PII filtering, per-agent configuration, and verifiable audit trails. They need to prove what their agents did to internal auditors, external regulators, and clients.

Entry point: `ahp.yaml` config file + SDK integration.
Value: consistent recording policy across all agents, PII-safe by default, audit-ready chains.

### Tertiary: Agent Platform Companies

MCP gateway providers, agent frameworks, and agent hosting platforms. They need a standard audit format to offer their users instead of building proprietary logging.

Entry point: integrate AHP SDK as a built-in feature of their platform.
Value: add "audit-grade logging" to their feature list without building it from scratch.

---

## 3. Design Principles

### Protocol vs. Implementation

The protocol specification defines **what** — record format, hash chain rules, evidence linking, witness API, conformance levels. SDK implementation guides define **how** — staging files, interceptors, crash recovery, OTLP export. This separation allows multiple independent implementations from the spec alone.

### Incremental Adoption

Each conformance level adds value independently. Operators adopt only the level they need:

```
Level 0: Development mode       JSON logs, no hash chain, see what your agent does
Level 1: Hash chain             Records are ordered and tamper-evident
Level 2: + Signing              Organizational authorship is provable
Level 3: + Witnessing           Third parties can independently verify
```

The adoption path is designed as a ramp, not a cliff:

```
Day 1:    pip install ahp → ahp.init(mode="dev") → ahp log     (Level 0)
Week 1:   ahp.init(level=1) → hash chain, canonical bytes       (Level 1)
Month 1:  ahp.init(level=2) → add Ed25519 signing               (Level 2)
Month 3:  ahp.init(level=3, witness=...) → external witnesses    (Level 3)
```

Level 0 uses the same record field names and structure as Level 1, so upgrading from development mode to production requires changing one config parameter, not rewriting integration code.

### Configurable Recording

Not all agents need the same recording policy. The protocol defines the mechanism (what CAN be recorded). The operator defines the policy (what IS recorded). The chain documents the policy (BootRecord proves what was configured).

### Honest Security Claims

AHP provides tamper-evidence, not tamper-prevention. The specification explicitly documents what each level defends against and what it does not (see Section 11: Threat Model).

---

## 4. Technical Architecture

### 4.1 Protocol Core

**Hash Algorithm:** SHA-256 everywhere. Full 256 bits for hash chain (prev_hash). Truncated to 128 bits for parameters_hash and result_hash. FIPS 140-2 compliant. One algorithm to implement, one algorithm to audit.

**Canonical Serialization:** Hash chain integrity requires deterministic serialization. The protocol defines a canonical byte representation for hashing, independent of the wire format (Protobuf). All fields are serialized in strictly ascending tag order, with fixed-width little-endian integers, length-prefixed strings as UTF-8 bytes, and UUIDs as 16 raw bytes. Empty fields are explicitly encoded as zero-length. Records MUST be stored in canonical byte order — the stored bytes ARE the canonical representation. This means verification only requires hashing the stored bytes; field-level parsing is only needed when constructing new records.

**Causality:** Determined by parent_action_id, not timestamps. Parallel tool calls share the same parent_action_id. LLM inference records are the causal parents of the tool calls they produce. Sequential inference records chain to each other via parent_action_id, forming a complete decision tree. Cross-agent links via W3C traceparent.

**Context Propagation:** W3C Trace Context (traceparent + tracestate). No custom headers. AHP-specific data encoded as base64url without padding in tracestate under key "ahp". Minimal payload: agent_id + sequence + chain_hash. If tracestate is stripped by middleware, cross-agent linking degrades gracefully — records still exist independently. Compatible with the OTel ecosystem.

### 4.2 Record Data Model

All record types share a common envelope:

```
Record (common envelope)
  record_id        : UUID v7  (16 bytes, unique identifier)
  agent_id         : UUID v7  (16 bytes, which agent)
  session_id       : UUID v7  (16 bytes, which session)
  timestamp_ms     : uint64   (wall-clock UTC milliseconds)
  sequence         : uint64   (monotonic per agent, no gaps except GapRecords)
  prev_hash        : bytes[32](SHA-256 of previous record's stored bytes)
  schema_version   : uint32
  type             : enum     (ACTION, GAP, CHECKPOINT, BOOT, RECOVERY, KEY, WITNESS)
  payload          : oneof    (type-specific payload)
```

The common envelope enables forward compatibility. A verifier that encounters an unknown record type can still verify the hash chain by computing canonical_bytes over the full record's raw bytes. New record types in future versions do not break existing verifiers as long as the canonical serialization rules are followed.

### 4.3 Record Types (v1.0 — 7 types)

**ActionRecord** — one agent action. The core record type.

```
ActionPayload
  parent_action_id   : UUID v7  (optional — causal parent)
  tool_name          : string   (what was called)
  parameters_hash    : bytes[16](SHA-256 truncated, of filtered payload)
  result_hash        : bytes[16](SHA-256 truncated, of filtered payload)
  result_status      : enum     (SUCCESS, FAILURE, TIMEOUT, ERROR)
  response_time_ms   : uint32
  protocol           : enum     (MCP, HTTP, GRPC, A2A, SHELL, CUSTOM)
  action_type        : enum     (TOOL_CALL, INFERENCE, DELEGATION, MESSAGE, CUSTOM)
  target_entity      : string   (optional — what was acted on)
  evidence_uri       : string   (optional — where full payload is stored)
  redacted           : bool     (true = hashes computed over redacted content)
  model_id           : string   (optional — LLM model, for INFERENCE type)
  input_token_count  : uint32   (optional — for INFERENCE type)
  output_token_count : uint32   (optional — for INFERENCE type)
  authorization      : Authorization (who approved this action; AUTH_NONE when no authorization applies)
```

**Authorization model:** The `authorization` field records who approved (or rejected) the action before execution. This is distinct from `parent_action_id` (causation — what triggered the action). Authorization answers "who allowed it?" while causation answers "what decided to do it?"

```
Authorization
  type    : enum (AUTH_NONE, AUTH_HUMAN, AUTH_AGENT, AUTH_POLICY, AUTH_MULTI_PARTY)
  entries : repeated AuthorizationEntry

AuthorizationEntry
  authorizer_type     : enum   (AUTHORIZER_HUMAN, AUTHORIZER_AGENT, AUTHORIZER_POLICY_ENGINE)
  authorizer_id       : string (email, agent name, or policy name)
  authorizer_agent_id : UUID v7 (optional — for cross-chain linking to authorizer agent)
  authorizer_seq      : uint64  (optional — sequence in authorizer's chain where approval lives)
  decision            : enum   (APPROVED, REJECTED, CONDITIONAL)
  condition           : string (optional — for CONDITIONAL decisions)
  timestamp_ms        : uint64  (when the decision was made)
```

In multi-agent systems, agent-to-agent authorization creates **double-entry bookkeeping**: the authorizer's chain records "I approved Agent A's request" and the executor's chain records "Agent B approved my action at B's sequence 4821." `ahp reconcile` cross-references these. If either side is missing or mismatched, the discrepancy is flagged.

Rejected authorizations are still recorded (`decision = REJECTED`, `result_status = ERROR`, `result_hash = zero`) — enabling auditors to answer "how many times did this agent attempt unauthorized actions?"

When `action_type = INFERENCE`, the record captures an LLM reasoning step. The `tool_name` field contains the LLM API identifier — e.g., `"openai.chat.completions"`, `"anthropic.messages"`, or a custom identifier for self-hosted models. The `parameters_hash` covers the prompt sent to the LLM. The `result_hash` covers the full response including thinking/reasoning tokens. Tool calls resulting from the inference set their `parent_action_id` to this record's `record_id`, forming the causal tree from reasoning to action.

**GapRecord** — explicit documentation of lost records.

```
GapPayload
  first_lost_sequence : uint64
  last_lost_sequence  : uint64
  count               : uint64
  reason              : enum    (CRASH, DISK_FULL, DISK_CORRUPT, ROTATION,
                                 INTERCEPTOR_FAILURE, BACKPRESSURE, MANUAL_PURGE)
  detail              : string  (optional — human-readable context)
```

GapRecords use structured reason codes (enum, not free text) so gap analysis can be automated. The `BACKPRESSURE` reason indicates records were intentionally shed due to resource limits — the operator was notified and chose what to drop.

A GapRecord's sequence number (in the common envelope) is set to `last_lost_sequence + 1`. The next regular record after the GapRecord continues from there. For example: if record 4 is the last valid record and records 5-10 are lost, the GapRecord has `sequence=11`, `first_lost_sequence=5`, `last_lost_sequence=10`, `count=6`.

**BatchCheckpoint** — periodic chain summary.

```
CheckpointPayload
  record_count     : uint64
  gap_count        : uint64
  chain_hash       : bytes[32] (current chain head hash)
  merkle_root      : bytes[32] (optional — RFC 6962 Merkle tree)
  signature        : bytes[64] (optional — Ed25519 over merkle_root)
  signing_key_id   : bytes[32] (optional — fingerprint of signing key)
  evidence_status  : { available: uint64, exported: uint64,
                       expired: uint64, missing: uint64 }
```

**BootRecord** — emitted at SDK startup and on config change. Declares what is being monitored and what recording policy is active.

```
BootPayload
  sdk_name             : string   ("ahp-python", "ahp-typescript", etc.)
  sdk_version          : string   (semver)
  interceptors         : repeated string  (["mcp", "http", "grpc"])
  agent_framework      : string   (optional — "langchain", "crewai", etc.)
  agent_name           : string   (human-readable agent identifier)
  runtime              : string   ("python 3.12", "node 22.1")
  chain_level          : enum     (LEVEL_1, LEVEL_2, LEVEL_3)
  fsync_mode           : enum     (EVERY, BATCH, NONE)
  clock_source         : string   (optional — "ntp:pool.ntp.org", "system")
  inference_recording  : bool     (is reasoning being recorded?)
  inference_evidence   : bool     (are prompts/responses being stored?)
  evidence_recording   : bool     (are tool payloads being stored?)
  filter_config_hash   : bytes[32](SHA-256 of canonical filter config; 32 zero bytes if no filters)
  matched_agent_rule   : string   (optional — which config rule matched)
  config_source        : string   (optional — "ahp.yaml", "env", "programmatic")
  authorization_recording : bool  (is authorization context being recorded?)
```

An auditor reading the BootRecord knows exactly what was configured. "This agent records reasoning but not evidence" vs. "This agent does not record reasoning" — no ambiguity, no "missing data" confusion.

**RecoveryRecord** — emitted after crash recovery.

```
RecoveryPayload
  records_verified   : uint64
  records_truncated  : uint64
  last_valid_seq     : uint64
  recovery_method    : enum    (CHECKPOINT_FILE, CHAIN_SCAN, FRESH_START)
  detail             : string
```

**KeyGenesisRecord** — establishes or rotates signing identity.

```
KeyPayload
  public_key          : bytes[32] (Ed25519 public key)
  key_id              : bytes[32] (SHA-256 of public key)
  expires_at          : uint64    (optional — timestamp_ms)
  supersedes_key_id   : bytes[32] (optional — for key rotation)
```

When `supersedes_key_id` is set, this record rotates from an old key to a new key. The BatchCheckpoint immediately following a rotation MUST be signed by the old key. The next BatchCheckpoint after that MUST be signed by the new key. This provides a signed handoff: the old key's last checkpoint covers the rotation record, and the new key's first checkpoint proves continuity.

**WitnessReceipt** — external attestation stored in chain.

```
WitnessPayload
  witness_id          : string    (identifier of the witness service)
  checkpoint_seq      : uint64    (sequence number that was checkpointed)
  checkpoint_hash     : bytes[32] (chain hash that was checkpointed)
  witness_timestamp   : uint64    (witness's own clock, ms UTC)
  receipt_signature   : bytes[64] (witness's Ed25519 signature)
  witness_public_key  : bytes[32] (witness's public key)
```

### 4.4 Hash Chain Construction

```
GENESIS:
  Record_0.prev_hash = 0x00 * 32  (32 zero bytes)

CHAINING:
  Record_N.prev_hash = SHA-256(stored_bytes(Record_{N-1}))

VERIFICATION:
  expected_seq = 1
  For each Record_i where i > 0:
    assert Record_i.prev_hash == SHA-256(stored_bytes(Record_{i-1}))
    if Record_i.type == GAP:
      assert Record_i.sequence > expected_seq
        (GapRecord's sequence = last_lost_sequence + 1;
         the jump from expected_seq documents the gap)
    else:
      assert Record_i.sequence == expected_seq
    expected_seq = Record_i.sequence + 1
```

Since records are stored in canonical byte order, `stored_bytes` and `canonical_bytes` are identical — verification is a simple sequential hash over the raw stored records. Given a chain file, anyone can verify it without the SDK — only SHA-256 is needed.

### 4.5 Evidence Model

The chain records hashes. The evidence store records content. They are linked by hash.

```
Chain:     ActionRecord { parameters_hash: 0xa1b2... }
                              |
Evidence:  evidence/a1b2c3d4e5f6...  (content-addressed file, named by hash)
```

Protocol requirements:
- Evidence files are content-addressed: `filename = hex(hash)` where hash is the same truncated SHA-256 used in the ActionRecord.
- Evidence contains the raw bytes that were hashed (after PII filtering, if configured).
- `evidence_uri` in ActionRecord optionally points to retrieval location (local path, S3 URI, HTTP URL).
- `redacted: true` flag signals the hash was computed over filtered content, not the original.
- Evidence recording is optional. Operators configure it globally and per-agent.

The protocol defines the **linking** — hash in chain, content in store, matched by hash. Storage backend, retention policy, and export mechanism are implementation concerns.

Evidence status tracking:
```
AVAILABLE  — evidence exists locally or at evidence_uri
EXPORTED   — evidence shipped to external store, local copy may be deleted
EXPIRED    — evidence deleted per retention policy, hash remains in chain
ERASED     — evidence deleted per GDPR/privacy request
MISSING    — evidence expected but not found (verification failure)
```

BatchCheckpoints include evidence status counts so operators can monitor evidence health.

### 4.6 Witness Protocol

The witness protocol enables independent third-party verification. Anyone can run a witness — the protocol defines the API, not the operator.

**Checkpoint API (minimal):**

```
POST /ahp/v1/checkpoints
  Request:
    agent_id        : string (UUID)
    chain_hash      : string (hex, 64 chars — current chain head)
    sequence        : uint64 (current sequence number)
    timestamp_ms    : uint64 (agent's clock)
    signature       : string (hex — agent signs the checkpoint)
    signing_key_id  : string (hex — agent's key identifier)

  Response:
    receipt_id          : string (UUID)
    witness_id          : string
    witness_timestamp   : uint64 (witness's own clock)
    witness_signature   : string (hex — witness signs request + witness_timestamp)

GET /ahp/v1/receipts/{receipt_id}
  Response: same as POST response

GET /ahp/v1/agents/{agent_id}/checkpoints?after_seq=N
  Response: array of receipts
```

**Guarantees:**
- A receipt proves: "Witness W observed that Agent A claimed chain state H at sequence N, and W recorded this at time T."
- The agent's signature prevents the witness from fabricating checkpoints.
- The witness's signature prevents the agent from fabricating receipts.
- Both sides have non-repudiable evidence of the exchange.

**Trust properties:**
- A witnessed checkpoint makes it impossible for the agent to reduce its record count below N or rewrite history before sequence N — without the discrepancy being detectable by anyone who checks the witness.
- Multiple independent witnesses make collusion progressively harder.
- Witness timestamps provide an independent time anchor, mitigating agent clock manipulation.

**Witness trust:** The operator configures trusted witness public keys in the AHP config or discovers them via the witness endpoint (`GET /ahp/v1/identity`). The protocol does not define a PKI for witnesses — operators use whatever trust establishment mechanism fits their environment (manual key exchange, TLS certificate pinning, organizational PKI). The `witness_public_key` in the WitnessReceipt allows offline verification without contacting the witness.

The OSS release includes a reference witness implementation (SQLite-backed HTTP server) for testing and local development.

### 4.7 Inference Recording (Agent Reasoning)

LLM inference calls are the most important actions an agent takes — they are where every decision happens. The protocol captures them as ActionRecords with `action_type = INFERENCE`.

When an agent calls an LLM API, the HTTP interceptor captures the request and response at the transport layer. This is ground truth — what was actually sent to the model and what came back, including reasoning/thinking tokens.

**Causal tree:**
```
INFERENCE_1 (user: "find and fix the auth bug")
  |-- TOOL_CALL_1 (grep "auth", parent=INFERENCE_1)
  |-- TOOL_CALL_2 (read_file auth.py, parent=INFERENCE_1)
  |
INFERENCE_2 (LLM sees results, decides to edit, parent=INFERENCE_1)
  |-- TOOL_CALL_3 (edit_file auth.py, parent=INFERENCE_2)
  |
INFERENCE_3 (LLM sees edit success, decides to test, parent=INFERENCE_2)
  |-- TOOL_CALL_4 (run_tests, parent=INFERENCE_3)
  |
INFERENCE_4 (LLM sees tests pass, responds to user, parent=INFERENCE_3)
  |-- MESSAGE_1 (response to user, parent=INFERENCE_4)
```

Every tool call points to the inference that caused it (direct causal parent). Every inference points to the most recent prior inference in the same session (conversational continuity). `parent_action_id` means "the action that most directly caused this action to happen." `ahp trace` reconstructs the full decision chain from these links.

**Inference recording is configurable per agent** (see Section 5: Configuration). Three modes:

| inference.record | inference.evidence | Behavior |
|---|---|---|
| false | N/A | LLM calls not recorded. No INFERENCE records. |
| true | false | INFERENCE record emitted (timing, model_id, token counts, hashes). Full prompts/responses NOT stored. |
| true | true | Full recording. INFERENCE record + full prompt/response in evidence store. |

For streaming LLM responses, the INFERENCE ActionRecord is emitted after the complete response has been received. The result_hash covers the fully assembled response, not individual stream chunks.

### 4.8 Multi-Agent Architecture

Each agent process has its own independent SDK instance — own chain file, own evidence store, own exporter. No shared state between agents. Backend stitches traces via shared trace_id from W3C Trace Context headers.

Cross-agent integrity via double-entry bookkeeping: both sides record independently. Agent A records "I sent request X to Agent B." Agent B records "I received request Y from Agent A." Discrepancies are detectable at query time by cross-referencing parameter/result hashes.

With witnesses, cross-agent discrepancies become more constrained: if both agents checkpoint to the same witness, the timeline of who claimed what and when is independently verifiable.

### 4.9 Export and Storage

Primary export: OTLP (OpenTelemetry Protocol) via gRPC. AHP records map to OTLP LogRecords. This provides compatibility with many backends: Datadog, Grafana, ClickHouse, Splunk, Honeycomb, S3, BigQuery, and more.

**Export integrity boundary:** AHP guarantees chain integrity up to the export boundary. After records are handed to the OTLP collector, the collector and backend are outside AHP's control. The protocol explicitly states:

```
Chain-level guarantee:   Complete, ordered, hash-chained. Source of truth.
Export-level guarantee:  At-least-once delivery. Exporter tracks acknowledged offset.
Backend-level guarantee: Outside AHP's control. Backend behavior is the backend's responsibility.
```

For audit-critical deployments, the implementation guide recommends:
- Dedicated collector (not shared with observability traffic)
- Collector configured with no sampling, no dropping
- Persistent queue enabled with sufficient disk
- Fan-out to 2+ independent backends

File exporter (JSONL) for local development and environments without OTLP infrastructure.

**Export-gated rotation:** Chain segments SHOULD NOT be rotated (deleted) until the segment has been fully exported AND acknowledged by at least one collector (MUST NOT at Level 3). If storage limits are reached before the oldest segment is exported, the SDK emits a GapRecord with `reason=BACKPRESSURE`, alerts the operator, and lets the operator decide how to proceed. The protocol prioritizes explicit data loss documentation over silent data destruction.

---

## 5. Configuration

AHP uses a single configuration file to control recording policy, PII filtering, and per-agent behavior. The protocol defines the configuration **schema** (what fields exist and what they mean). SDKs implement it in their preferred format (YAML, TOML, JSON).

### 5.1 Configuration Schema

```yaml
# ahp.yaml

# --- Global Defaults -----------------------------------------
defaults:
  level: 2                      # 1=chain, 2=signed, 3=witnessed
  inference:
    record: true                # emit INFERENCE ActionRecords
    evidence: true              # store full prompts/responses
  evidence:
    record: true                # store tool call payloads
  authorization:
    record: false               # record who approved each action
  fsync_mode: batch             # every | batch | none
  checkpoint_interval: 1000    # records between BatchCheckpoints
  witness:
    enabled: false              # send checkpoints to witnesses
    interval: 1000              # records between witness checkpoints
    endpoints:                  # witness service URLs (required if level=3)
      - https://witness.example.com/ahp/v1
    # NOTE: level=3 requires witness.enabled=true and at least one endpoint.
    # The SDK MUST reject this config and fail at startup if level=3
    # is set without witness configuration.

# --- PII Filters ---------------------------------------------
# Applied IN ORDER before hashing. All matching filters run.
# Input: canonical JSON string of parameters/result.
# Regex flavor: PCRE2.
# Replacement: literal string, no backreferences.

filters:
  - name: credit_card
    pattern: '\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b'
    replacement: '[REDACTED:CC]'
    scope: [parameters, results]

  - name: ssn
    pattern: '\b\d{3}-\d{2}-\d{4}\b'
    replacement: '[REDACTED:SSN]'
    scope: [parameters, results]

  - name: email
    pattern: '[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'
    replacement: '[REDACTED:EMAIL]'
    scope: [parameters, results]

  - name: bearer_token
    pattern: 'Bearer\s+[A-Za-z0-9\-._~+/]+=*'
    replacement: 'Bearer [REDACTED:TOKEN]'
    scope: [parameters, results]

  - name: system_prompt
    pattern: '.*'
    replacement: '[REDACTED:SYSTEM_PROMPT]'
    scope: [inference_system_message]

# --- Per-Agent Overrides --------------------------------------
# Matched top-down by glob on agent_name. First match wins.
# Unmatched agents use defaults.
# Agent-level filters are APPENDED to global filters (global run first).
# All other agent-level fields OVERRIDE the corresponding default.

agents:
  - match: "customer-support-*"
    inference:
      record: true
      evidence: true
    level: 3
    witness:
      enabled: true
      endpoints:
        - https://witness.example.com/ahp/v1
    filters:
      - name: customer_id
        pattern: 'CUST-\d{8}'
        replacement: '[REDACTED:CUSTOMER_ID]'
        scope: [parameters, results]

  - match: "code-assistant-*"
    inference:
      record: false
    level: 1

  - match: "financial-tx-*"
    inference:
      record: true
      evidence: true
    level: 3
    witness:
      enabled: true
      endpoints:
        - https://witness.example.com/ahp/v1
        - https://witness-backup.example.com/ahp/v1
    filters:
      - name: iban
        pattern: '\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}[A-Z0-9]{0,16}\b'
        replacement: '[REDACTED:IBAN]'
        scope: [parameters, results]

  - match: "data-pipeline-*"
    inference:
      record: false
    evidence:
      record: false
    level: 1

  - match: "internal-*"
    inference:
      record: true
      evidence: false
```

### 5.2 PII Filter Pipeline

Filters affect hashes. If two SDKs apply the same filter differently, they produce different hashes for the same content, and cross-SDK verification breaks. The pipeline is precisely defined:

```
raw payload
    |
    v
classify payload type
    |
    +---> JSON payload:
    |       serialize to canonical JSON string
    |       (deterministic: sorted keys, no trailing whitespace,
    |        UTF-8, no BOM, \uXXXX for non-ASCII)
    |            |
    |            v
    |       apply filters in definition order (ALL matching filters run)
    |            |   each filter: regex replace on the full string
    |            |   regex flavor: PCRE2
    |            |   replacement: literal string (no backreferences)
    |            |
    |            v
    |       filtered string
    |            |
    |            +---> SHA-256 truncated to 128 bits
    |            +---> evidence store (if enabled)
    |
    +---> non-JSON text payload:
    |       treat as raw UTF-8 string, apply filters, then hash
    |
    +---> binary payload (images, protobuf, etc.):
            hash raw bytes directly, PII filters do not apply
            redacted flag MUST NOT be set
```

The hash is ALWAYS computed over filtered content. Changing filters changes hashes. The BootRecord includes `filter_config_hash` (hash of the active filter config) so auditors can verify which filters were active for any record.

### 5.3 Filter Scopes

```
parameters                — tool call parameters (outbound payload)
results                   — tool call results (inbound payload)
inference_system_message  — only the system message in LLM prompt
inference_prompt          — entire LLM prompt (all messages)
inference_response        — LLM response (including thinking tokens)
all                       — everything
```

The `inference_system_message` scope allows enterprises to redact proprietary system prompts without redacting the rest of the conversation.

### 5.4 Built-in Filter Presets

The protocol defines standard presets that all SDKs ship with identical patterns:

```yaml
filters:
  - preset: pci           # credit card numbers, CVVs, expiry dates
  - preset: pii-us        # SSN, driver's license, passport
  - preset: pii-eu        # national ID formats for EU countries
  - preset: credentials   # API keys, tokens, passwords, connection strings
  - preset: hipaa         # PHI identifiers (name, DOB, MRN, etc.)
```

Presets expand to a defined set of patterns specified in the protocol appendix. All SDKs ship the same presets with the same patterns to ensure identical filter behavior.

### 5.5 Config Changes at Runtime

If configuration is hot-reloaded (filter update, policy change), the SDK MUST emit a new BootRecord with the updated state. The chain documents when the policy changed:

```
Record 1:    BootRecord (inference: ON, filters: hash_A)
Record 2-99: ActionRecords (filtered by config A)
Record 100:  BootRecord (inference: OFF, filters: hash_B)  <-- config changed
Record 101+: ActionRecords (filtered by config B, no INFERENCE records)
```

---

## 6. Conformance Levels

Conformance levels use RFC 2119 language (MUST, SHOULD, RECOMMENDED).

### Level 0: Development Mode (Non-Conformant)

```
Records emitted as JSON objects (no canonical serialization)
No hash chain, no sequence numbers, no GapRecords
No BootRecord or RecoveryRecord required
Authorization defaults to AUTH_NONE
Export: JSONL to stdout or file
NOT conformant — no integrity guarantees
Purpose: "pip install ahp && ahp log" in 2 minutes
```

Level 0 uses the same field names as Level 1 so upgrading requires changing the SDK mode, not rewriting integration code. This is the developer's entry point — see what the agent does, then add integrity guarantees when ready.

### Level 1: Hash Chain

```
MUST emit ActionRecord for every intercepted action
MUST maintain prev_hash chain using SHA-256 over canonical_bytes
MUST use monotonic sequence numbers with no gaps
  (except as documented by GapRecords)
MUST emit GapRecord when records are lost, with structured reason code
MUST emit BootRecord at SDK startup and on config change
MUST emit RecoveryRecord after crash recovery
MUST compute parameters_hash and result_hash as SHA-256 truncated to 128 bits
MUST use UUID v7 for record_id, agent_id, session_id
MUST apply PII filters before hashing when filters are configured
MUST support inference.record and inference.evidence configuration
MUST emit INFERENCE ActionRecords when inference.record = true
MUST set parent_action_id on TOOL_CALL records to link to the
  INFERENCE that caused them (when inference recording is enabled)
MUST include model_id on INFERENCE records
MUST record active policy in BootRecord
MUST include authorization_recording in BootRecord
MUST set authorization.type on all ActionRecords
  (AUTH_NONE when no authorization applies)
MUST populate authorization entries with authorizer details when
  authorization.record = true and authorization context is available
MUST set authorizer_agent_id when authorizer_type = AUTHORIZER_AGENT
MUST provide conversion from canonical binary to JSON (Appendix H) for reading
SHOULD emit ActionRecord with result_status = ERROR for rejected authorizations
SHOULD NOT rotate chain segments until exported and acknowledged
SHOULD include token counts on INFERENCE records
SHOULD set authorizer_seq for agent authorizers (enables cross-chain verification)
```

### Level 2: Signed Chain (adds to Level 1)

```
MUST emit KeyGenesisRecord before first signed checkpoint
MUST sign BatchCheckpoints with Ed25519
MUST include signing_key_id in signed records
MUST emit KeyGenesisRecord with supersedes_key_id on key rotation
SHOULD emit BatchCheckpoint at least every 1000 records or 60 seconds
```

### Level 3: Witnessed Chain (adds to Level 2)

```
MUST checkpoint to at least one witness
MUST store WitnessReceipt in chain after each successful checkpoint
MUST sign checkpoints sent to witnesses
MUST NOT rotate chain segments until exported and acknowledged
SHOULD checkpoint every 1000 records or 60 seconds
SHOULD checkpoint to 2+ independent witnesses
RECOMMENDED: gaps < 0.01% of records per 30-day window
```

---

## 7. CLI Commands

### v1.0

```
ahp log              What did my agent do? Filter by agent, session, tool,
                     status, time, action_type. --follow for live streaming.
                     --reasoning to show INFERENCE records with causal links.
                     --authorized-by to filter by authorizer (human, agent, policy).
                     --unauthorized to show only actions with no authorization.

ahp show <id>        Full details of one action. --tree for causal tree
                     showing inference -> tool call relationships.
                     --evidence to display full payload from evidence store.
                     Shows authorization details when present (who approved,
                     decision, timestamp, cross-chain reference).

ahp trace <session>  Full trace across all agents for one user request.
                     Reconstructs the decision chain from INFERENCE records
                     through tool calls and delegations.

ahp verify           Is the chain intact?
                     Level 1: hash chain verification.
                     Level 2: signature verification.
                     Level 3: witness receipt verification.
                     --evidence to verify evidence store matches chain hashes.

ahp export           Dump records for external tools. CSV, JSONL.
                     Filter by entity, agent, time range, action_type.

ahp gaps             List all GapRecords. Where was data lost, how much, why.
                     --compliance-check to validate against recommended
                     gap thresholds per conformance level.

ahp keygen           Generate Ed25519 keypair for Level 2 signing.

ahp export-status    Records in chain, exported, pending, failed.
                     Collector connection status. Evidence store health.

ahp config           Show active configuration. Which agent rule matched.
                     Active filters. Recording policy.
```

### v1.1

```
ahp replay           Human-readable story of a session in causal order.
                     Shows reasoning -> action -> result flow.

ahp status           SDK health: chain length, gaps, buffer usage, uptime.

ahp count            Statistics: records per agent/tool/status/day.
                     Token usage per agent (from INFERENCE records).

ahp init             Setup wizard: agent name, export destination,
                     integrity level, PII filter presets.

ahp reconcile        Cross-agent comparison for A2A exchanges.
                     Reports hash mismatches between sender/receiver records.
                     Verifies authorization cross-chain links: checks that
                     authorizer_agent_id + authorizer_seq references match
                     actual records in the authorizer's chain.

ahp recover          Manual crash recovery with status reporting.

ahp compact          Remove exported segments to free disk.

ahp witness          Manually trigger a witness checkpoint.
                     --verify to check existing receipts against witness.
```

---

## 8. Protocol Integration Points

### How AHP works with each protocol:

```
MCP:      Interceptor wraps ClientSession.call_tool()
          Records: tool_name from MCP, params/result hashes
          Protocol field: MCP
          action_type: TOOL_CALL

A2A:      Interceptor wraps outbound HTTP calls to other agents
          Injects W3C traceparent + tracestate headers
          Protocol field: A2A

          Task submission (send task to remote agent):
            action_type: DELEGATION
            tool_name: "a2a.tasks.send"
            target_entity: "agent:<remote-agent-name>"
            parameters_hash: hash(task request payload)
            result_hash: hash(final task result after COMPLETED)
            response_time_ms: total task duration (submit → complete)

          Auth required (remote agent requests authorization):
            action_type: MESSAGE
            tool_name: "a2a.auth_request"
            target_entity: "agent:<requesting-agent>"
            Records that the remote agent asked for authorization

          Auth fulfilled (client provides authorization):
            action_type: MESSAGE
            tool_name: "a2a.auth_response"
            target_entity: "agent:<requesting-agent>"
            authorization: AUTH_HUMAN or AUTH_AGENT (whoever fulfilled)
            Links via authorizer_seq to the approver's chain

          Auth delegation chain (A → B → C → Human):
            Each agent records its own DELEGATION + auth_request/response
            authorizer_seq links create a verifiable chain across agents
            ahp reconcile validates the full delegation path

HTTP:     Interceptor wraps HTTP client (httpx/requests/fetch)
          Captures URL, method, status, timing, payload hashes
          Intercepts before TLS — SDK sees plaintext at application layer
          Protocol field: HTTP
          action_type: TOOL_CALL or INFERENCE (if target is LLM API)

gRPC:     Interceptor registers as UnaryUnaryClientInterceptor
          Captures service name, method name, metadata
          Injects traceparent into gRPC metadata
          Protocol field: GRPC
          action_type: TOOL_CALL
```

SDK implementations detect LLM API endpoints via configurable URL patterns and automatically set `action_type = INFERENCE` with `model_id` extracted from the request/response. SDKs ship with built-in patterns for common LLM providers and support custom endpoint configuration.

### Agent Framework Integration:

```
LangChain:       BaseCallbackHandler (~50 lines)
CrewAI:          Event handler (~50 lines)
OpenAI Agents:   Tool wrapper
Mastra:          Middleware plugin
Vercel AI SDK:   Middleware plugin
```

Framework integrations can provide richer causal linking than raw HTTP interception — they know when the framework decides to call a tool vs. when the LLM decides. The protocol supports both approaches.

---

## 9. Specification Structure

The protocol specification document is organized as:

```
1.  Introduction
2.  Terminology (RFC 2119)
3.  Data Model (record types, fields, semantics)
4.  Canonical Serialization (deterministic byte representation for hashing)
5.  Hash Chain Construction (genesis, chaining rules, verification algorithm)
6.  Evidence Model (content-addressed linking, evidence status)
7.  Signing (Ed25519, key identification, key rotation)
8.  Witness Protocol (checkpoint API, receipt format, verification)
9.  Context Propagation (W3C Trace Context encoding)
10. Configuration Schema (recording policy, PII filters, per-agent overrides)
11. Conformance Levels (Level 0 development mode, Level 1/2/3 requirements)
12. Security Considerations (threat model)
13. IANA Considerations (tracestate key registration)
```

```
Appendix A: Protobuf Schema
Appendix B: Canonical Serialization Examples
Appendix C: Chain File Format (recommended binary layout)
Appendix D: Evidence Store Format (recommended directory layout)
Appendix E: PII Filter Preset Patterns
Appendix F: Conformance Test Vectors
Appendix G: Reference Witness Server
Appendix H: JSON Record Format (Level 0 and export)
```

Sections 1-13 are normative. Appendices are informative — recommended implementations that are not required for conformance.

---

## 10. SDK Implementation Guide (Separate Document)

The following topics belong in the SDK implementation guide, not the protocol specification:

**SDK Pipeline Architecture:**
```
Interceptor --> Staging File (disk) --> Single Writer --> Chain File (disk) --> Exporter
                                            |
                                      Evidence Store (disk)
```

**Staging File:** Raw records appended to disk by interceptors. Absorbs parallel writes without blocking. Format includes monotonic IDs for deduplication after crash recovery.

**Single Writer:** One loop reads staging file, applies PII filters, computes hashes, adds sequence + prev_hash, writes finalized record to chain file + evidence store.

**Crash Recovery:** Deterministic 6-step protocol using checkpoint file with atomic rename, CRC32C validation, and monotonic ID deduplication.

**fsync Strategy:** Three modes with explicit durability trade-offs:
```
every   — fsync after each record    ~500-2K/sec    lose 0 records
batch   — fsync every 100rec/1sec    ~50K/sec       lose <= 100 records
none    — OS decides                 ~200K/sec      lose ~30s of data
```

**OTLP Export Mapping:** How AHP records map to OTLP LogRecords.

**Interceptor Patterns:** Per-protocol interceptor implementation details.

**Framework Integrations:** Per-framework integration code and patterns.

---

## 11. Threat Model

### What AHP defends against:

| Threat | Defense | Level |
|--------|---------|-------|
| Post-hoc tampering by third party | Hash chain detects any modification | 1+ |
| Record reordering | Sequence numbers + hash chain | 1+ |
| Silent record deletion | Missing sequence = must be GapRecord | 1+ |
| Forged chain authorship | Ed25519 signing identifies author | 2+ |
| Operator rewrites history after checkpoint | Witness has independent copy of chain state | 3 |
| Backdated/future-dated records | Witness timestamp provides independent anchor | 3 |
| Cross-agent record inconsistency | Double-entry: both sides record, discrepancies detectable | 1+ |
| Unauthorized action execution | Authorization field documents who approved each action; rejected attempts recorded | 1+ |
| Forged agent-to-agent approval | Cross-chain verification: authorizer's chain must have matching record at `authorizer_seq` | 1+ |
| PII in audit trail | Configurable filters applied before hashing | 1+ |

### What AHP does NOT defend against:

| Threat | Why | Mitigation (outside protocol) |
|--------|-----|-------------------------------|
| Operator doesn't run the SDK | Can't record what you don't instrument | Organizational policy, deployment requirements |
| Operator modifies SDK to skip actions | SDK runs in operator's process | Code signing, binary attestation, TEE |
| Real-time suppression before chain | Interceptor is in operator's control | Same as above |
| Clock manipulation between checkpoints | Agent controls its own clock | NTP monitoring, shorter witness intervals |
| Compromised signing keys | Key compromise breaks Level 2 | Key rotation, HSM, short-lived keys |
| Witness collusion with operator | Witness confirms false state | Multiple independent witnesses |
| Interceptor bugs producing wrong data | SDK defect, not protocol defect | Conformance tests, fuzzing, multiple SDKs |
| Agent fabricates authorization entries | Agent controls its own chain records | Cross-chain verification via `authorizer_seq`; multiple witnesses |
| Human approval identity spoofing | No cryptographic proof of human identity in protocol | Integration with organizational IdP (SSO, OIDC); outside protocol scope |

**The protocol explicitly states:** AHP provides tamper-evidence, not tamper-prevention. It makes undetected modification difficult in proportion to the conformance level. Level 1 protects against accidental corruption and post-hoc tampering by non-operators. Level 3 protects against deliberate falsification by a single party. No level protects against an operator who controls both the agent and all witnesses.

---

## 12. What AHP Does Not Do

AHP is not observability. It does not replace OpenTelemetry, Datadog, or Prometheus. It exports through OTLP to complement them.

AHP is not storage. It defines the record format and integrity model, not how records are stored long-term.

AHP is not PII detection. It provides configurable filter patterns for redaction. What counts as PII is the operator's decision, defined in the config file.

AHP is not transport security. Use TLS.

AHP is not a prevention system. It records what agents did and why (when inference recording is enabled). It does not block agents from doing things. A policy engine built on AHP records is a product, not part of the protocol.

AHP is not a blockchain. No consensus, no tokens, no distributed ledger. Just a hash chain — the same data structure Git uses — with optional external witnesses for independent verification.

AHP is not an LLM observability tool. It records the LLM call as an action (prompt hash, response hash, timing, model, tokens). It does not evaluate prompt quality, model performance, or output accuracy. Tools like LangSmith and Langfuse serve that purpose. AHP records what the agent decided. Those tools evaluate whether the decision was good.

---

## 13. Conformance Test Vectors

Cross-SDK interoperability requires that given identical inputs, every conformant implementation produces identical hashes. The test vectors file is the interoperability backbone.

```json
{
  "version": "1.0.0",
  "vectors": [
    {
      "name": "genesis_action",
      "description": "First ActionRecord in a new chain",
      "input": {
        "record_id": "01903f5a-0000-7000-8000-000000000001",
        "agent_id": "01903f5a-0000-7000-8000-000000000010",
        "session_id": "01903f5a-0000-7000-8000-000000000020",
        "timestamp_ms": 1710000000000,
        "sequence": 1,
        "schema_version": 1,
        "type": "ACTION",
        "payload": {
          "tool_name": "read_file",
          "parameters": "{\"path\":\"/etc/hosts\"}",
          "result": "127.0.0.1 localhost",
          "result_status": "SUCCESS",
          "response_time_ms": 42,
          "protocol": "MCP",
          "action_type": "TOOL_CALL"
        }
      },
      "expected": {
        "prev_hash": "0000000000000000000000000000000000000000000000000000000000000000",
        "parameters_hash": "<computed>",
        "result_hash": "<computed>",
        "canonical_bytes_hex": "<computed>",
        "record_hash": "<computed>"
      }
    },
    {
      "name": "chained_action",
      "description": "Second ActionRecord chained to genesis"
    },
    {
      "name": "inference_record",
      "description": "INFERENCE ActionRecord with model_id and token counts"
    },
    {
      "name": "inference_with_tool_calls",
      "description": "INFERENCE followed by two TOOL_CALLs with parent_action_id"
    },
    {
      "name": "gap_record",
      "description": "GapRecord with structured reason"
    },
    {
      "name": "filtered_action",
      "description": "ActionRecord with PII filter applied before hashing",
      "filter_config": {
        "filters": [
          {
            "name": "email",
            "pattern": "[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}",
            "replacement": "[REDACTED:EMAIL]",
            "scope": ["parameters"]
          }
        ]
      }
    },
    {
      "name": "boot_record",
      "description": "BootRecord with full policy declaration"
    },
    {
      "name": "signed_checkpoint",
      "description": "Level 2 BatchCheckpoint with Ed25519 signature",
      "signing_key_hex": "<test private key>",
      "expected_signature": "<computed>"
    },
    {
      "name": "key_genesis",
      "description": "KeyGenesisRecord establishing signing identity"
    },
    {
      "name": "key_rotation",
      "description": "KeyGenesisRecord with supersedes_key_id for key rotation"
    },
    {
      "name": "witness_receipt",
      "description": "WitnessReceipt with checkpoint verification"
    }
  ]
}
```

**Rule:** If an SDK does not produce the expected outputs for these inputs, it is not conformant. No exceptions. This is what makes "two independent implementations" meaningful for IETF.

---

## 14. SDK Implementations

### Python SDK (Alpha)

Status: 48 tests passing. Core pipeline: instrument() -> record -> hash chain -> CRC32C buffer -> JSONL/OTLP export. Hash chain verified by CLI. Parallel tool calls, session isolation, GapRecords, no-op mode, graceful shutdown, W3C propagation, Merkle tree, Ed25519 signing.

Pending: refactor to staging file architecture, inference recording, PII filter pipeline, evidence store, config file support, witness client, canonical serialization, conformance test vector validation.

Covers: LangChain, CrewAI, OpenAI Agents SDK, AutoGen, MCP Python SDK.

### TypeScript SDK (Next Priority)

Status: not built.

Required for: IETF standardization (needs 2+ independent implementations), broad agent framework coverage.

Covers: LangChain.js, Mastra, Vercel AI SDK, MCP TypeScript SDK.

### Go SDK (Future)

Covers: enterprise infrastructure, Kubernetes operators, high-performance backends.

### Reference Witness Server (OSS)

SQLite-backed HTTP server implementing the witness checkpoint API. Not production-grade — for testing, local development, and as a reference for witness service implementers.

---

## 15. Risk Analysis

### Protocol Risks

**Canonical serialization is the hardest problem.** Cross-SDK hash consistency requires byte-exact deterministic serialization. One wrong decision and interoperability breaks permanently. Mitigated by: comprehensive test vectors, simple serialization rules (fixed field order, fixed-width integers, explicit zero-length encoding), pseudocode in spec appendix.

**PII filter determinism across SDKs.** PCRE2 regex behavior can vary subtly across language implementations. Mitigated by: restricting to common PCRE2 features, literal-only replacements (no backreferences), filter-specific test vectors.

**Staging file and crash recovery are unbuilt.** The most important SDK architecture change is pending. Edge cases (partial writes, disk full, stale checkpoints) are where bugs live. Mitigated by: well-understood WAL pattern, deterministic recovery protocol, fault injection testing.

**No production usage.** Every protocol has bugs that only real usage reveals. Mitigated by: alpha label, fast iteration, early adopter feedback loop.

### Adoption Risks

**"Too early."** Regulations not yet enforced. Demand may not materialize until 2027. Mitigated by: observability value is immediate (developers need to see what agents do), audit readiness is a bonus.

**"Too late."** MCP could add native audit logging. OTel could add agent-specific semantic conventions. Mitigated by: AHP is cross-protocol (not MCP-only), complementary to OTel (exports via OTLP).

**"Good enough" proprietary logging.** Most companies will use whatever their platform provides. Mitigated by: target multi-platform deployments and regulated industries where independent verification matters.

### Execution Risks

**Single maintainer.** Protocol, SDKs, CLI, spec, community. Mitigated by: minimal v1 scope, open source contributions, early co-maintainer recruitment.

---

## 16. Pending Work (Priority Order)

```
 1. Canonical serialization spec + pseudocode
 2. Conformance test vectors (comprehensive)
 3. Refactor Python SDK to staging file architecture
 4. PII filter pipeline implementation
 5. Config file support (ahp.yaml)
 6. Inference recording (INFERENCE action type)
 7. Evidence store implementation
 8. Crash recovery with fault injection testing
 9. BootRecord with full policy declaration
10. End-to-end OTLP test with real collector
11. Reference witness server
12. Witness client in Python SDK
13. Cross-agent delegation test
14. TypeScript SDK core
15. GitHub repo setup with CI
16. PyPI/npm publish config
17. Spec document (formal, sections 1-13 + appendices)
```

### Open Questions for Spec

The following items are intentionally deferred from this PSD to the formal protocol specification. Each must be resolved before the spec is finalized.

**Verification algorithm:**

1. **GapRecord payload validation.** The verification algorithm accepts GapRecords when `sequence > expected_seq`. It does not validate that `GapPayload.first_lost_sequence == expected_seq` or that `GapPayload.last_lost_sequence == GapRecord.sequence - 1`. Without these checks, a GapRecord could under-report data loss (e.g., claim 4 records lost when 6 were actually skipped). The spec should add these assertions.

2. **RecoveryRecord vs GapRecord ordering.** After a crash, the SDK emits both a RecoveryRecord (documenting recovery state) and a GapRecord (documenting lost records). The spec must define the required ordering: RecoveryRecord first, then GapRecord — or vice versa. This affects sequence numbering.

**Evidence model:**

3. **128-bit evidence hash collisions.** Evidence files are named by truncated 128-bit SHA-256 hashes. Birthday bound collision probability becomes non-negligible at ~2^64 records. The spec's Security Considerations should quantify this risk and recommend full 256-bit naming for high-volume deployments.

4. **`redacted` flag semantics.** When PII filters are configured, is `redacted` set to `true` on every record (because filters were active) or only when a filter actually matched and changed the content? The former is simpler. The latter is more informative. The spec must pick one and add a test vector.

**PII filters:**

5. **`filter_config_hash` computation.** The BootRecord includes `filter_config_hash` (SHA-256 of the active filter config). The spec must define exactly what is hashed — the raw YAML text? A canonical JSON representation of the filter list (names, patterns, replacements, scopes in sorted order)? This must be cross-SDK deterministic.

6. **`inference_system_message` scope requires LLM API parsing.** This filter scope requires the SDK to understand each LLM provider's message format (OpenAI `messages[].role`, Anthropic separate `system` parameter, etc.). The spec should define the canonical message extraction rules or defer this to the SDK implementation guide with provider-specific examples.

7. **Filter preset versioning.** Built-in presets (pci, pii-us, pii-eu, credentials, hipaa) contain specific regex patterns. If a preset is updated in a new SDK version, the same payload produces different hashes. The spec should version presets (e.g., `preset: pci@1`) or mandate that preset patterns are immutable once published.

**Witness protocol:**

8. **Witness GET endpoint response.** The `GET /ahp/v1/receipts/{receipt_id}` response is described as "same as POST response" — but the POST response does not include the original checkpoint data (agent_id, chain_hash, sequence, timestamp). A third-party verifier fetching a receipt needs this data to verify the signature. The spec should define the complete GET response schema including the original checkpoint.

**Signing:**

9. **`chain_hash` in BatchCheckpoint vs `prev_hash` in envelope.** The BatchCheckpoint contains `chain_hash: bytes[32] (current chain head hash)`. The BatchCheckpoint's own `prev_hash` in the envelope also contains the hash of the previous record. These are the same value. The spec should clarify whether `chain_hash` serves a distinct purpose (e.g., for witness checkpoints) or is intentionally redundant for readability.

**Inference recording:**

10. **Behavior when `inference.record = false` and HTTP interceptor is active.** If inference recording is disabled, should the HTTP interceptor silently skip LLM API calls entirely, or record them as regular HTTP `TOOL_CALL` records without the INFERENCE semantics? The former means LLM calls are invisible. The latter means they're visible but not semantically marked. The spec must define the expected behavior.

### Documents

```
Protocol specification:     agent-history-protocol-spec.md (to be updated)
Architecture document:      ahp-oss-architecture-v3.1-final.md
SDK implementation guide:   (to be written)
Python SDK source:          ahp/sdk-python/
Protobuf schema:            ahp/spec/ahp/v1/action_record.proto
Configuration schema:       (to be written)
Conformance test vectors:   (to be written)
This document:              ahp-psd.md
```

---

## 17. The One Question

"If every AI agent in the world recorded its actions — and its reasoning — in one standard format, tamper-evident, independently verifiable, privacy-respecting, and configurable per agent... what would that enable?"

That is what AHP builds toward.

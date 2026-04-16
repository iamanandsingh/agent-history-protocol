# AHP Roadmap

Prioritized list of features. Shipped items marked DONE.

## Priority 1: Decorator-Based Instrumentation -- DONE

**Shipped in v0.2.0.** `@ahp.trace_tool`, `@ahp.trace_agent`, `@ahp.trace_llm` decorators. Sync + async, bare and parameterized, fail-open. Global default recorder via `set_default_recorder()`.

## Priority 2: Live Tail (`ahp tail`) -- DONE

**Shipped in v0.2.0.** `ahp tail [--chain FILE] [--last N] [--format table|json] [--interval S]`. File-watching via polling. Handles partial writes, file rotation, Ctrl+C.

## Priority 3: Token Caching, Cost, Reasoning, and Provider Fields -- DONE

**Shipped.** Five new fields added to `ActionPayload`:

| Field | Type | Description |
|-------|------|-------------|
| `cache_read_tokens` | uint32 | Prompt tokens served from cache (OpenAI, Anthropic, Gemini, Fireworks, DeepSeek) |
| `cache_creation_tokens` | uint32 | Prompt tokens written to cache (Anthropic) |
| `reasoning_tokens` | uint32 | Internal thinking/reasoning tokens (OpenAI o-series, Gemini, DeepSeek-R1) |
| `cost_nano_usd` | uint64 | Pre-calculated cost in nano USD ($0.008 = 8,000,000). Auto-estimated from configurable pricing table |
| `provider` | string | LLM provider, auto-detected from URL. 13 providers supported + custom via config |

Also shipped:
- Configurable pricing table (`ahp.yaml` `pricing` section) with built-in defaults for 30+ models
- Configurable provider URL patterns (`ahp.yaml` `providers` section) for custom LLM endpoints
- Thread-safe pricing with uint64 overflow protection
- `Optional[int] = None` for cost — distinguishes "not provided" (auto-estimate) from "explicitly free" (0)
- Validation bounds checks (uint32/uint64 max) on all new fields

## Priority 4: Session/Span Context Managers

**Gap:** `context.py` handles propagation, but there's no ergonomic API for creating nested spans. Users must manually thread `parent_action_id`.

**Deliverable:** Context managers that auto-manage trace/span IDs and parent-child relationships.

```python
with ahp.session("research-task") as session:
    with session.span("coordinator") as agent:
        agent.log_llm(...)
        with agent.child_span("researcher") as child:
            child.log_tool(...)
```

## Priority 5: OpenAI Client Wrapper

**Gap:** OpenAI is the most-used LLM API. No dedicated adapter exists despite HTTP interceptor being available.

**Deliverable:** Thin wrapper that instruments the OpenAI client, extracts model/token/cost metadata from responses, and emits properly typed INFERENCE records.

```python
from ahp.adapters.openai import instrument
import openai

client = instrument(openai.OpenAI())  # all calls now logged to AHP
```

---

## Already Exists (No Action Needed)

| Feature | Location |
|---|---|
| CLI with 8 commands | `ahp/cli/main.py` |
| Token count fields | `ActionPayload.input_token_count`, `output_token_count` |
| OTel export | `ahp/export/otlp.py` |
| PII filtering | `ahp/core/filters.py` with presets |
| HTTP/MCP/gRPC auto-instrumentation | `ahp/interceptors/` |
| LangChain integration | `ahp/integrations/langchain.py` |
| Context propagation | `ahp/core/context.py` |
| Web viewer | `viewer/serve.py` |

## Explicitly Out of Scope

- **OTel field renaming** — mapping belongs in the exporter, not the core schema
- **W3C trace_id/span_id** — `session_id` + `record_id` + `parent_action_id` already serve this purpose
- **Security event classification (ASI categories)** — analysis concern, not recording concern
- **SIEM export mappings** — enterprise upsell, not core protocol
- **Field-level encryption** — needed eventually, not now
- **Separate adapter packages** — premature at v0.1.0 with 1 integration

---

# Post-v2.0 Work

Known gaps surfaced during the v2.0 integrity-hardening pass. Ordered by load-bearing impact on the tamper-evident claim, not by implementation effort.

## Priority 1: Evidence-hash migration to full 32-byte SHA-256

**Gap:** `parameters_hash` and `result_hash` on `ActionPayload` are 16-byte SHA-256 truncations in the canonical wire format (`canonical.py:65-66`, schema_version=2). A 128-bit truncation gives a 2^64 birthday collision bound — within reach of a well-resourced insider who controls both chain and evidence store, enabling evidence-swap without detection.

**Deliverable:** schema_version=3 with full 32-byte hashes on both fields. Parser retains v1/v2/v3 parse paths for reading legacy chains; writer emits v3 only. Interim mitigation (without schema bump) is a separate evidence-index file committing full hashes that each `CheckpointPayload` merkle-roots; cleaner long-term is the schema change.

**Breaks:** wire format. All third-party producers need updating.

## Priority 2: Cross-SDK conformance tests in CI

**Gap:** Python and TypeScript SDKs are tested independently. No CI job verifies a chain written by Python verifies with TypeScript, or vice versa. Silent serialisation divergence is detectable only by manual testing — this is how the TS `canonical.ts` tag-number comment bugs lingered.

**Deliverable:** CI matrix that writes a fixture chain per SDK, swaps readers, asserts verification passes and byte-compares canonical output on a representative set of records (each of the 7 record types, each `result_status` / `auth_type`, edge-case strings, boundary integers).

## Priority 3: TypeScript SDK witness client

**Gap:** TS SDK defines `WitnessPayload` types (`packages/sdk-typescript/src/types.ts`) but has no client flow — no checkpoint submission, no receipt verification, no chain-side WitnessPayload construction. Level 2+ AHP is Python-only for TS users.

**Deliverable:** TS implementation of `send_witness_checkpoint` using Web Crypto (Ed25519) and the same canonical JSON format (sort keys then `JSON.stringify`). Port the `test_witness_payload_carries_real_signature` regression across SDKs.

## Priority 4: Full RFC 8785 JCS adoption

**Gap:** v2.0 witness-protocol signing uses a strict subset of RFC 8785 (alphabetical-key sort + compact separators) that's correct only because all current fields are ASCII hex/UUID/integer. A future non-ASCII field would diverge between Python (default `ensure_ascii=True` → `\uXXXX`) and JavaScript (`JSON.stringify` → raw UTF-8).

**Deliverable:** normative reference to RFC 8785 in spec §8.1; reference JCS helper in both SDKs; tighten spec to say "all signed-blob string values MUST be ASCII-only OR MUST be canonicalised per RFC 8785."

## Priority 5: Server-side key consistency check

**Gap:** witness accepts any `{signing_key_id, public_key}` pair without verifying `signing_key_id == SHA-256(public_key)`. A malformed but internally-consistent request is accepted; receipts can be issued with mismatched key metadata.

**Deliverable:** three-line defensive check on the witness server; spec §8.1 clause mandating the relationship.

## Priority 6: Cross-session timestamp monotonicity

**Gap:** `ChainWriter` enforces a monotonic non-decreasing timestamp floor within a session (`_last_ts_ms` initialises to 0). Across chain rotation or process restart, the floor resets; if wall clock stepped backward between sessions, the new segment's first record can carry a timestamp earlier than the prior segment's last.

**Deliverable:** `ChainWriter.__init__` accepts an optional `start_ts_ms` parameter seeded by the rotation/recovery path from the prior segment's last record.

## Priority 7: Witness attestation binds signing key identity

**Gap:** the witness's own receipt signature covers `{agent_id, chain_hash, sequence, witness_timestamp}` — only 4 fields. Receipt content echoes `agent_id` but not `signing_key_id`. An auditor with a receipt cannot determine which of an agent's (possibly rotated) keys was used to sign the underlying checkpoint without loading the agent's own chain and cross-referencing `KeyPayload` records.

**Deliverable:** include `signing_key_id` in the receipt body and under the witness signature. Auditor tooling can then verify end-to-end without touching the agent's chain.

## Priority 8: Agent ↔ key PKI binding at the witness

**Gap:** any freshly-generated keypair can sign for any `agent_id`. The witness trusts whatever `public_key` the body provides, so an attacker with their own keypair can issue receipts claiming to be any agent.

**Deliverable:** this is a broader design question. Options: (a) agents register `public_key` with witness out-of-band at first-use, (b) witness requires a chain of trust (KeyPayload in agent's own chain signed by a CA), (c) external PKI/attestation service. Needs design doc before implementation.

## Lower-priority hygiene

- `ChainReader.last_iteration_error` is a mutable attribute; document thread-safety (one reader per thread) or add a `threading.Lock`.
- `_verify_client_signature` short-circuits are not timing-constant; minor side-channel in same-host deployments.
- Body-field type validation on the witness server (currently relies on downstream parsing to catch non-string `signing_key_id` etc.).
- `ChainWriter.close()` relies on `__del__`; a true context manager would be cleaner (previously thought critical, revised down — flock is fd-based so orphan `.lock` files don't block restart).
- CLI `ahp log` uses `iter_records` but does not surface `last_iteration_error`; auditors running `ahp log` on a corrupted chain see a silent truncation.

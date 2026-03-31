# Changelog

All notable changes to the Agent History Protocol (AHP) project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Schema**: Five new fields on `ActionPayload`: `cache_read_tokens` (uint32), `cache_creation_tokens` (uint32), `reasoning_tokens` (uint32), `cost_nano_usd` (uint64), `provider` (string). All fields default to zero/empty for backward compatibility at the API level. Binary format is a breaking change (acceptable at v0.1.0-alpha).
- **Cost estimation**: Configurable pricing table (`ahp.yaml` `pricing` section) with built-in defaults for OpenAI, Anthropic, Google Gemini, Mistral, DeepSeek. Auto-estimates `cost_nano_usd` when recording inferences with token counts. User-supplied `cost_nano_usd=0` is respected (not overridden). Thread-safe with overflow protection (capped at uint64 max).
- **Provider detection**: Auto-detects 13 LLM providers from HTTP endpoint URLs (OpenAI, Azure OpenAI, Anthropic, Google Gemini, Google Vertex, Cohere, Mistral, AWS Bedrock, Groq, Together AI, Fireworks AI, DeepSeek, Perplexity). Configurable via `ahp.yaml` `providers` section for custom endpoints.
- **Reasoning token extraction**: Extracts reasoning/thinking tokens from OpenAI o-series (`completion_tokens_details.reasoning_tokens`), OpenAI Responses API (`output_tokens_details.reasoning_tokens`), Google Gemini (`usageMetadata.thoughtsTokenCount`), and DeepSeek-R1.
- **Cache token extraction**: Extracts cached tokens from OpenAI (`prompt_tokens_details.cached_tokens`), OpenAI Responses API (`input_tokens_details.cached_tokens`), Anthropic (`cache_read_input_tokens`, `cache_creation_input_tokens`), and Google Gemini (`cachedContentTokenCount`).
- **Model ID extraction from URL**: Gemini model IDs extracted from `/models/{model_id}:generateContent` URL pattern when not present in request body.
- **TypeScript SDK**: All five new fields added to types, canonical serialization, parsing, and recorder. Conformance test vectors updated.

### Fixed
- **Critical**: Witness signature verification now checks `verify_signature()` return value (previously accepted any forged signature).
- **Critical**: Recorder signs canonical JSON checkpoint fields (matching witness verification format), and sends `public_key` alongside `signing_key_id`.
- **Critical**: Envelope size guard corrected from 104 to 108 bytes (Python + TypeScript).
- Chain continuity after crash recovery: ChainWriter now receives `prev_hash`/`start_sequence` from recovery result.
- TypeScript ChainWriter supports `prevHash`/`startSequence` for cross-segment hash chain continuity.
- Async recorder gap tracking now properly tracks `_gap_first_lost_seq` range (was always reporting count=1).
- Evidence cleanup failures now logged instead of silently swallowed.
- `export_csv()` uses `csv.DictWriter` instead of f-string interpolation (prevents comma-in-field corruption).
- Witness server rejects negative `Content-Length` values (DoS prevention).
- Protocol servers (A2A, MCP) validate `Content-Length` and handle `JSONDecodeError` with proper 400 responses.
- File descriptor leak in AsyncChainWriter lock acquisition and TS `_writeHeader`.
- HTTP interceptor reentrancy guard prevents infinite recursion with witness client.
- Duplicate dict key removed from `format_action_summary`.
- Config and CLI file I/O uses explicit `encoding="utf-8"` for Windows portability.
- TS test glob changed from `dist/**/*.test.js` to `dist/*.test.js` (bash globstar compatibility).

### Performance
- In-memory evidence file count eliminates O(n) directory scan per checkpoint.
- In-memory chain file size tracking eliminates `stat()` syscall per record.
- Pre-partitioned filter scopes avoid per-filter membership check on every payload.
- Narrowed recorder lock scope: PII filtering and evidence storage run outside lock (20-40% throughput improvement under thread contention).
- TypeScript ChainWriter uses persistent file handle and single batched write per record (was open + 3 writes + close).

### Changed
- Sanitized exception messages in API responses to prevent information disclosure.
- Added security headers (X-Content-Type-Options) to all HTTP server responses.
- Fixed private key file creation to use restricted permissions atomically.
- Added logging to witness client for connection failures.
- AsyncChainWriter now logs pending records when drain loop is cancelled.
- Deduplicated CRC32 implementation in TypeScript SDK.
- Fixed Node.js v25 compatibility (Object.freeze on typed arrays).
- CI: ruff lint/format scope expanded to entire repo; mypy now checks witness/.
- CI: coverage includes witness/; TS tests use `npm test` matching package.json.
- Dynamic SDK version via `importlib.metadata` (falls back to hardcoded).
- Witness server: in-memory dedup index checked before disk I/O on duplicate fast path.
- DER length guards in TS signing tightened to exact Ed25519 sizes (44/48 bytes).
- Added TypeScript SDK README.md and LICENSE for npm publish.
- Added 7 TypeScript signing tests (generateKeypair, sign/verify, Merkle tree).

### Removed
- Removed dead backward-compat shims (`ahp/a2a.py`, `mcp_client.py`, `mcp_server.py`).
- Removed unused `BaseInterceptor` ABC, `ChainRotator` class, `get_receipts_for_agent()`.
- Removed redundant docs (ahp-psd.md, sdk-implementation-guide.md, explainer-script.md, eu-ai-act-compliance.md).
- Removed `test_openclaw/` directory.
- Cleaned 40+ unused imports across Python and TypeScript.

### Added
- CONTRIBUTING.md, SECURITY.md, CODE_OF_CONDUCT.md governance files.

## [0.1.0-alpha] - 2026-03-18

### Added

- **Core Protocol**: Binary chain file format with hash-chained records, CRC32C integrity checks, and three-level recording (Level 1: hash chain, Level 2: Ed25519 signing, Level 3: witness anchoring).
- **Python SDK** (`ahp-python`):
  - `AHPRecorder` — synchronous recorder with fail-open semantics, automatic checkpointing, chain rotation, crash recovery, and PII filter pipeline.
  - `AsyncAHPRecorder` — asyncio-native recorder with background queue-based disk writes.
  - `RecorderBase` — consolidated base class eliminating duplicated logic between sync and async recorders (PII filtering, evidence storage, boot/checkpoint/key payload construction, config resolution, structured logging).
  - `ChainWriter` / `ChainReader` — binary chain file I/O with persistent file handles for reduced syscall overhead, file-level locking, and atomic rollback on write failures.
  - `AsyncChainWriter` — non-blocking chain writer with internal staging queue.
  - `EvidenceStore` — content-addressed evidence storage with lifecycle management (`max_size_bytes`, `max_age_seconds`, automatic cleanup).
  - `FilterPipeline` — PII redaction with preset filters (PCI, credentials) and custom regex patterns.
  - Ed25519 signing via optional `cryptography` dependency with early validation at recorder init.
  - YAML/JSON configuration loading with per-agent overrides, environment variable fallback, and config validation.
  - Callback hooks (`on_record_written`, `on_error`) for metrics integration.
  - Structured logging with agent_id, session_id, and record_count context on warnings.
  - Chain recovery (scan + truncate corrupt tail) on startup.
  - Chain rotation at 64MB segment boundaries.
  - Context propagation support for distributed tracing.
- **TypeScript SDK** (reference implementation): Protocol-compatible TypeScript recorder.
- **Witness Server** (reference implementation): HTTP witness endpoint for Level 3 anchoring.

# Changelog

All notable changes to the Agent History Protocol (AHP) project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- Sanitized exception messages in API responses to prevent information disclosure.
- Added security headers (X-Content-Type-Options) to all HTTP server responses.
- Fixed private key file creation to use restricted permissions atomically.
- Added logging to witness client for connection failures.
- AsyncChainWriter now logs pending records when drain loop is cancelled.
- Removed ~30 unused imports and dead code across Python and TypeScript SDKs.
- Deduplicated CRC32 implementation in TypeScript SDK.
- Fixed Node.js v25 compatibility (Object.freeze on typed arrays).

### Removed
- Removed orphaned benchmarks/ directory.
- Removed redundant documentation files (ahp-deep-summary.md, duplicate index.html).
- Removed broken CI benchmark step.

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

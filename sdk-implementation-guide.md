# AHP SDK Implementation Guide
Version 1.0-draft-01 · March 2026 · Apache 2.0

This guide is for developers building AHP-conformant SDKs in any language. It complements the normative specification (`agent-history-protocol-spec.md`) with architecture guidance, implementation patterns, pseudocode, and practical advice derived from the reference Python SDK.

Throughout this document, "spec Section N" refers to the normative specification. Capitalized keywords (MUST, SHOULD, etc.) are used per RFC 2119.

---

## 1. Architecture Overview

### 1.1 The SDK Pipeline

Every AHP SDK implements the same logical pipeline:

```
Agent Action
    │
    ▼
┌──────────────┐
│  Interceptor  │  ← Protocol-specific capture (HTTP, MCP, gRPC, A2A)
└──────┬───────┘
       │ ActionPayload
       ▼
┌──────────────┐
│  PII Filters  │  ← Regex-based redaction before any hashing
└──────┬───────┘
       │ filtered bytes
       ▼
┌──────────────┐
│   Staging     │  ← Queue/buffer for async SDKs; direct call for sync
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ Single Writer │  ← Serializes to canonical bytes, maintains hash chain
│  (Chain I/O)  │     Exactly one writer per chain file (file-locked)
└──────┬───────┘
       │
       ├───────────────────────┐
       ▼                       ▼
┌──────────────┐       ┌──────────────┐
│  Chain File   │       │Evidence Store│  ← Content-addressed payload storage
│  (.ahp)       │       │  (optional)  │
└───────────────┘       └──────────────┘
```

### 1.2 Why This Architecture

**Single Writer.** Only one process may write to a chain file at a time. This is enforced by an OS-level file lock (e.g., `flock` on POSIX, `LockFileEx` on Windows). The single-writer constraint eliminates the need for distributed consensus or multi-writer conflict resolution. It also guarantees that `prev_hash` and `sequence` are always consistent — there is no window where two writers could race to assign the same sequence number.

**Interceptor → Staging → Writer separation.** Interceptors run in the agent's hot path (inside HTTP calls, tool invocations, etc.). They must never block the agent. The staging layer (a queue in async SDKs, or a direct synchronized call in sync SDKs) decouples the interception latency from disk I/O latency. The writer drains the staging buffer and handles all file operations.

**Evidence is separate from the chain.** The chain stores fixed-size hashes (16 bytes each for parameters and results). Full payloads go to the evidence store. This keeps the chain compact and verifiable without loading megabytes of LLM prompts. Evidence can be exported, expired, or erased independently without breaking chain integrity.

**Fail-open by design.** AHP is an audit system, not a control system. Every component in the pipeline must catch its own exceptions. If any step fails, the agent continues unimpeded and a GapRecord is emitted on recovery (see Section 14).

### 1.3 Component Responsibilities

| Component | Responsibility | Failure mode |
|-----------|---------------|--------------|
| Interceptor | Capture protocol-specific call data | Log warning, skip record |
| PII Filter | Redact sensitive content before hashing | Pass through unfiltered |
| Staging | Buffer records for async drain | Drop oldest on overflow, emit GapRecord |
| Chain Writer | Serialize, hash-chain, write to disk | Rollback in-memory state, emit GapRecord |
| Evidence Store | Store full payloads by content hash | Log warning, record still valid |
| Signing | Ed25519 signatures on checkpoints | Level 2+ only; fail at startup if crypto unavailable |
| Witness Client | Submit checkpoints to external witnesses | Retry with backoff, never block agent |

---

## 2. Chain File I/O

### 2.1 File Format

The chain file is an append-only binary file. It consists of a fixed 16-byte header followed by a sequence of framed records.

**Reference:** Spec Appendix C.

#### Header (16 bytes)

```
Offset  Size  Content
0       4     Magic bytes: 0x41 0x48 0x50 0x00  ("AHP\0")
4       4     File version: uint32 LE (currently 1)
8       8     Creation timestamp: uint64 LE (milliseconds UTC)
```

#### Record Frame

Each record is stored as:

```
┌─────────────┬────────────────────────┬──────────────┐
│ Length (4B)  │ Canonical Bytes (N B)  │ CRC32C (4B)  │
│ uint32 LE   │ (see Section 3)        │ uint32 LE    │
└─────────────┴────────────────────────┴──────────────┘
```

The CRC32C covers `length_bytes + canonical_bytes` (i.e., the 4-byte length prefix concatenated with the payload). This is important — the CRC input includes the length prefix, not just the payload.

#### Pseudocode: Writing a Record Frame

```
function write_record_frame(file, canonical_bytes):
    length = len(canonical_bytes)
    length_bytes = uint32_le(length)

    // CRC covers length prefix + payload
    crc_input = length_bytes + canonical_bytes
    crc = crc32c(crc_input) & 0xFFFFFFFF

    file.append(length_bytes)
    file.append(canonical_bytes)
    file.append(uint32_le(crc))
    file.flush()

    // fsync per policy (see Section 2.3)
```

#### Pseudocode: Reading Record Frames

```
function read_records(file):
    header = file.read(16)
    assert header[0:4] == "AHP\0"

    while not eof:
        length_bytes = file.read(4)
        if len(length_bytes) < 4: break

        length = parse_uint32_le(length_bytes)
        if length > MAX_RECORD_SIZE: break    // corrupt, stop

        stored = file.read(length)
        if len(stored) < length: break        // truncated

        crc_bytes = file.read(4)
        if len(crc_bytes) < 4: break

        expected_crc = parse_uint32_le(crc_bytes)
        actual_crc = crc32c(length_bytes + stored) & 0xFFFFFFFF
        if actual_crc != expected_crc: break  // corrupt, stop

        yield stored
```

### 2.2 File Locking

Only one `ChainWriter` may have a chain file open at a time. Enforce this with an exclusive file lock on a `.lock` companion file:

- **POSIX:** `flock(fd, LOCK_EX | LOCK_NB)` on `{chain_path}.lock`
- **Windows:** `LockFileEx` with `LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY`

If the lock cannot be acquired, fail immediately with an error message identifying the conflict. Do not retry or wait — two writers on the same chain is a data integrity violation.

Clean up the lock file on close: release the lock, close the file descriptor, and `unlink` the `.lock` file.

### 2.3 Fsync Policy

The spec defines three fsync modes (spec Section 10.1):

| Mode | Behavior | Trade-off |
|------|----------|-----------|
| `every` | `fsync()` after every record write | Safest; ~10x slower |
| `batch` | `fsync()` after every 100 records | Good balance for most deployments |
| `none` | No explicit `fsync()`; OS decides | Fastest; data loss window on crash |

The fsync mode is recorded in the BootRecord so auditors know the durability guarantee.

### 2.4 I/O Error Handling and Rollback

If the `write` or `fsync` call fails (e.g., disk full, I/O error), the in-memory chain state (`prev_hash`, `sequence`, `record_count`, `gap_count`) MUST be rolled back to the values before the failed write. This prevents the in-memory state from diverging from what's actually on disk.

```
function write_record_safe(payload):
    // Save state for rollback
    saved_prev_hash = self.prev_hash
    saved_sequence = self.sequence
    saved_record_count = self.record_count

    // Advance state
    self.sequence += 1
    stored = canonical_bytes(build_record(payload))
    self.prev_hash = sha256(stored)
    self.record_count += 1

    try:
        write_record_frame(self.file, stored)
    catch IOError:
        // Rollback
        self.prev_hash = saved_prev_hash
        self.sequence = saved_sequence
        self.record_count = saved_record_count
        raise

    return record
```

---

## 3. Canonical Serialization

Canonical serialization is the most critical correctness requirement for cross-SDK interoperability. Two SDKs given the same logical record MUST produce byte-identical output. Any deviation breaks hash chain verification.

**Reference:** Spec Section 4 and Appendix F (test vectors).

### 3.1 Encoding Primitives

Implement these five primitive encoders. Every field in every record type uses one of these:

| Type | Encoding | Size |
|------|----------|------|
| `uint32` | Fixed-width little-endian | 4 bytes |
| `uint64` | Fixed-width little-endian | 8 bytes |
| `bool` | `0x00` = false, `0x01` = true | 1 byte |
| `string` | `uint32_le(len(utf8_bytes))` + `utf8_bytes` | 4 + N bytes |
| `bytes[N]` | Raw bytes, no length prefix, zero-filled if unset | N bytes |

```
function encode_uint32(value) → bytes:
    return little_endian_bytes(value, 4)

function encode_uint64(value) → bytes:
    return little_endian_bytes(value, 8)

function encode_bool(value) → bytes:
    return 0x01 if value else 0x00

function encode_string(s) → bytes:
    utf8 = s.encode("utf-8")
    return encode_uint32(len(utf8)) + utf8
    // Empty string: 4 zero bytes (length 0) + no content bytes

function encode_fixed_bytes(b, expected_len) → bytes:
    if b is null or unset:
        return zero_bytes(expected_len)
    assert len(b) == expected_len
    return b
```

### 3.2 Enum Encoding

All enums are encoded as `uint32` little-endian using their numeric values from the protobuf schema (Appendix A). Value 0 (`UNSPECIFIED`) MUST NOT appear in valid records.

| Enum | Values |
|------|--------|
| `RecordType` | ACTION=1, GAP=2, CHECKPOINT=3, BOOT=4, RECOVERY=5, KEY=6, WITNESS=7 |
| `ResultStatus` | SUCCESS=1, FAILURE=2, TIMEOUT=3, ERROR=4 |
| `Protocol` | MCP=1, HTTP=2, GRPC=3, A2A=4, SHELL=5, CUSTOM=6 |
| `ActionType` | TOOL_CALL=1, INFERENCE=2, DELEGATION=3, MESSAGE=4, CUSTOM=5 |
| `AuthorizationType` | AUTH_NONE=1, AUTH_HUMAN=2, AUTH_AGENT=3, AUTH_POLICY=4, AUTH_MULTI_PARTY=5 |
| `GapReason` | CRASH=1, DISK_FULL=2, DISK_CORRUPT=3, ROTATION=4, INTERCEPTOR_FAILURE=5, BACKPRESSURE=6, MANUAL_PURGE=7 |

### 3.3 Serialization Order

The envelope is serialized first, always in the same field order (ascending tag number). Then a payload type discriminator (uint32, same value as the envelope's `type` field). Then the payload fields in ascending tag order for that payload type.

#### Envelope (104 bytes minimum)

```
Tag  Field              Encoding         Size
1    record_id          bytes[16]        16
2    agent_id           bytes[16]        16
3    session_id         bytes[16]        16
4    timestamp_ms       uint64 LE        8
5    sequence           uint64 LE        8
6    prev_hash          bytes[32]        32
7    schema_version     uint32 LE        4
8    record_type        uint32 LE        4
--   payload_type_tag   uint32 LE        4   (same as record_type)
```

#### ActionPayload Fields

```
Tag    Field                    Encoding
1      parent_action_id         bytes[16]
2      tool_name                string
3      parameters_hash          bytes[16]
4      result_hash              bytes[16]
5      result_status            uint32 (enum)
6      response_time_ms         uint32
7      protocol                 uint32 (enum)
8      action_type              uint32 (enum)
9      target_entity            string
10     evidence_uri             string
11     redacted                 bool
12     model_id                 string
13     input_token_count        uint32
14     output_token_count       uint32
15.1   authorization.type       uint32 (enum)
15.2   authorization.entries    uint32 count prefix, then for each entry:
15.2.1   authorizer_type        uint32 (enum)
15.2.2   authorizer_id          string
15.2.3   authorizer_agent_id    bytes[16]
15.2.4   authorizer_seq         uint64
15.2.5   decision               uint32 (enum)
15.2.6   condition              string
15.2.7   timestamp_ms           uint64
```

#### Other Payload Types

See the spec Section 4.3 pseudocode for the complete field layout of each payload type. The reference implementation in `ahp/core/canonical.py` provides a line-by-line mapping.

### 3.4 Repeated Fields

Repeated fields (e.g., `interceptors` in BootPayload, `entries` in Authorization) are encoded as:

```
uint32_le(count)
for each element:
    encode(element)   // per the element's type rules
```

For repeated strings: `uint32_le(count)` followed by each string encoded with its own `uint32_le(len) + utf8_bytes`.

### 3.5 Nested Messages

Nested messages (e.g., `Authorization` inside `ActionPayload`, `EvidenceStatus` inside `CheckpointPayload`) are serialized **inline** — their fields appear directly in the byte stream at the parent field's position. There is no length prefix wrapping the nested message.

### 3.6 Verification Against Test Vectors

After implementing `canonical_bytes()`, verify your output against the test vectors in spec Appendix F. The verification process:

1. Construct a record with the exact field values from the test vector.
2. Call your `canonical_bytes()` implementation.
3. Compare the output byte-for-byte with the expected output.
4. Also verify that `SHA-256(your_output)` matches the expected hash.

If any byte differs, your SDK is not interoperable. Common mistakes:

- Wrong endianness (must be little-endian everywhere)
- Missing the payload type discriminator between envelope and payload
- Forgetting to zero-fill optional fields
- Using length-prefixed encoding for fixed-size byte arrays
- Encoding enums as strings instead of uint32

---

## 4. Hash Chain Maintenance

### 4.1 Genesis Record

The first record in a chain MUST have:

```
prev_hash = 0x00 * 32    (32 zero bytes)
sequence  = 1
```

This is typically a BootRecord emitted at SDK startup.

### 4.2 Chaining

For every subsequent record:

```
record_N.sequence  = record_{N-1}.sequence + 1
record_N.prev_hash = SHA-256(stored_bytes(record_{N-1}))
```

Where `stored_bytes` is the canonical serialization (the exact bytes written to disk). The chain writer maintains `prev_hash` and `sequence` as in-memory state, updated after each successful write.

### 4.3 The Write Sequence

For each record, the writer performs these steps atomically (under a lock):

1. Increment `sequence`.
2. Build the `Record` struct with `prev_hash` from current state.
3. Call `canonical_bytes(record)` to produce `stored_bytes`.
4. Compute `new_prev_hash = SHA-256(stored_bytes)`.
5. Write the record frame to disk: `[length][stored_bytes][CRC32C]`.
6. Update in-memory state: `prev_hash = new_prev_hash`.

If step 5 fails, roll back `prev_hash` and `sequence` (see Section 2.4).

### 4.4 What Happens on Gaps

When records are lost (crash, interceptor failure, disk full), the chain documents the gap with a GapRecord. The GapRecord's `sequence` in the envelope equals `last_lost_sequence + 1`. This means sequence numbers may jump, but every jump is explained.

Example: records 1–4 are written successfully. The SDK crashes and records 5–10 are lost. On recovery:

```
Record 4:  sequence=4,  prev_hash=SHA256(record_3_bytes)
[records 5-10 lost]
RecoveryRecord: sequence=5, prev_hash=SHA256(record_4_bytes)
GapRecord:      sequence=11, first_lost=5, last_lost=10, count=6
Record 12: sequence=12, prev_hash=SHA256(gap_record_bytes)
```

The hash chain is unbroken: every record's `prev_hash` points to the previous *written* record. The GapRecord documents the missing sequence range.

See spec Section 3.3 for the formal GapRecord constraints.

---

## 5. Crash Recovery

When an SDK starts and finds an existing chain file, it MUST run the recovery protocol before writing new records. A crash may have left the chain file in an inconsistent state — a partially written record frame at the end of the file.

**Reference:** Spec Section 3.6.

### 5.1 The 6-Step Recovery Protocol

```
Step 1: SCAN
    Open the chain file read-only.
    Read and verify the 16-byte header (magic + version + timestamp).
    If header is invalid, treat as empty chain (FRESH_START).

Step 2: VERIFY RECORDS
    Starting after the header, read record frames sequentially:
        a. Read 4-byte length prefix.
        b. Read `length` bytes of canonical data.
        c. Read 4-byte CRC.
        d. Verify CRC: crc32c(length_bytes + canonical_data) == stored_crc.
        e. If valid, advance to next frame. Track: records_verified,
           last_valid_offset, last_valid_seq, last_stored_bytes.
        f. If invalid (bad CRC, truncated read, length > MAX_RECORD_SIZE),
           stop scanning.

Step 3: DETECT CORRUPT TAIL
    If file_size > last_valid_offset, there are corrupt trailing bytes.
    Estimate records_truncated:
        avg_frame_size = (last_valid_offset - HEADER_SIZE) / records_verified
        records_truncated = max(1, round(corrupt_bytes / avg_frame_size))

Step 4: TRUNCATE
    If records_truncated > 0:
        Truncate the file to last_valid_offset.
        This removes all corrupt trailing data.

Step 5: COMPUTE CONTINUATION STATE
    If last_stored_bytes is not null:
        prev_hash = SHA-256(last_stored_bytes)
    Else:
        prev_hash = 0x00 * 32   (empty chain)

    Initialize the ChainWriter with this prev_hash and
    start_sequence = last_valid_seq.

Step 6: EMIT RECOVERY AND GAP RECORDS
    Emit a RecoveryRecord documenting what was found:
        records_verified, records_truncated, last_valid_seq,
        recovery_method = CHAIN_SCAN

    If records_truncated > 0, emit a GapRecord:
        first_lost = last_valid_seq + 1
        last_lost = first_lost + records_truncated - 1
        reason = CRASH
```

### 5.2 Recovery Methods

| Method | When Used |
|--------|-----------|
| `CHECKPOINT_FILE` | A checkpoint file exists and is more recent than a full scan |
| `CHAIN_SCAN` | Default: sequential CRC scan from the beginning |
| `FRESH_START` | Chain file is missing or has an invalid header |

### 5.3 Checkpoint Files for Fast Recovery

For large chain files (100K+ records), a full CRC scan can be slow. SDKs MAY implement checkpoint files to speed up recovery:

```
Checkpoint file: {chain_path}.checkpoint
Contents (JSON or binary):
    offset:     file offset of last verified record end
    sequence:   last verified sequence number
    prev_hash:  SHA-256 of last verified record's stored bytes
    timestamp:  when checkpoint was written
```

On recovery, the SDK reads the checkpoint file and starts scanning from `offset` instead of from the beginning. The checkpoint file SHOULD be updated periodically (e.g., every 1000 records or at each BatchCheckpoint).

**Important:** The checkpoint file is an optimization hint, not a trust boundary. If the checkpoint file is corrupt or outdated, fall back to a full scan.

---

## 6. Chain Rotation

Chain files are rotated to prevent unbounded growth and enable independent export of historical segments.

**Reference:** Spec Appendix C.

### 6.1 When to Rotate

The recommended maximum segment size is **64 MB** (`DEFAULT_MAX_SEGMENT_BYTES = 64 * 1024 * 1024`). Check the file size after each write. When the current segment exceeds the limit, trigger rotation.

### 6.2 Rotation Procedure

```
function rotate():
    // 1. Save chain state for cross-segment continuity
    prev_hash = writer.prev_hash
    sequence = writer.sequence

    // 2. Close the current writer (releases file lock)
    writer.close()

    // 3. Rename current chain to a timestamped segment
    rename("{chain_path}" → "{chain_path}.{unix_timestamp}.segment")

    // 4. Open a fresh chain writer with continuity
    writer = new ChainWriter(
        path = chain_path,
        prev_hash = prev_hash,        // carries over!
        start_sequence = sequence      // carries over!
    )

    // 5. Emit genesis records in the new segment
    emit_boot_record()
    if level >= 2:
        emit_key_genesis_record()
```

### 6.3 Cross-Segment Continuity

The key principle: **`prev_hash` and `sequence` carry over across segments.** The logical chain is unbroken even though the physical file is new. The first record in the new segment has a `prev_hash` that references the last record in the old segment.

A verifier processing multiple segments concatenates them logically and verifies the hash chain across the boundary.

### 6.4 Segment Naming

The reference implementation uses `{base_name}.{unix_timestamp}.segment` for archived segments and `{base_name}.{NNN}.ahp` for the `ChainRotator`'s indexed segments. Choose a naming scheme that sorts chronologically and is unambiguous.

### 6.5 Export-Gated Deletion

Segments SHOULD NOT be deleted until they have been exported (to OTLP, S3, a SIEM, etc.). At Level 3, segments MUST NOT be deleted until exported and acknowledged. When a segment is deleted, the SDK SHOULD emit a GapRecord with `reason = ROTATION` in the active segment.

---

## 7. PII Filter Pipeline

Filters run **before hashing** — the hash in the chain covers the filtered (redacted) content, not the original. This means PII never enters the chain, even as a hash.

**Reference:** Spec Section 10.2 and Appendix E.

### 7.1 Pipeline Steps

```
function filter_and_hash(raw_payload, scope):
    // 1. Classify payload
    if raw_payload is binary (not valid UTF-8):
        return sha256(raw_payload)[:16], raw_payload, false

    text = utf8_decode(raw_payload)

    // 2. Apply filters in definition order
    redacted = false
    for filter in active_filters:
        if scope in filter.scope or "all" in filter.scope:
            text, matched = regex_replace(filter.pattern, filter.replacement, text)
            if matched:
                redacted = true

    filtered_bytes = utf8_encode(text)

    // 3. Hash the filtered content
    hash_16 = sha256(filtered_bytes)[:16]   // truncated to 128 bits

    // 4. Store in evidence (if enabled)
    if evidence_enabled:
        evidence_store.store(filtered_bytes)

    return hash_16, filtered_bytes, redacted
```

### 7.2 Filter Definition

Each filter has:
- `name`: Human-readable identifier
- `pattern`: PCRE2 regex pattern (fall back to language-native regex if PCRE2 unavailable)
- `replacement`: Literal replacement string (no backreferences)
- `scope`: Array of `["parameters", "results", "inference_system_message", "inference_prompt", "inference_response", "all"]`

### 7.3 Preset Definitions

All SDKs MUST ship these presets with identical patterns (spec Appendix E):

| Preset | Filters |
|--------|---------|
| `pci` | Credit card numbers, CVVs |
| `pii-us` | SSN patterns |
| `pii-eu` | IBAN, national ID, passport |
| `credentials` | Bearer tokens, API keys, passwords |
| `hipaa` | MRN, DOB, phone, email |

Presets are immutable once published. Pattern updates require a new versioned preset name.

### 7.4 Computing `filter_config_hash`

The BootRecord includes a `filter_config_hash` so auditors know exactly which filters were active. Computation:

```
function compute_filter_config_hash(filters):
    if filters is empty:
        return 0x00 * 32

    // Build canonical JSON array
    config_array = []
    for f in filters:    // definition order
        config_array.append({
            "name": f.name,
            "pattern": f.pattern,
            "replacement": f.replacement,
            "scope": sorted(f.scope)    // alphabetical sort within scope
        })

    // JSON with sorted keys within each object
    json_str = json_serialize(config_array, sort_keys=true)
    return sha256(utf8_encode(json_str))
```

### 7.5 Scope Matching

When the SDK calls `filter_and_hash(payload, scope="parameters")`, only filters whose `scope` array contains `"parameters"` or `"all"` are applied. This allows credentials filters to run on all scopes while HIPAA filters only target specific fields.

---

## 8. Evidence Store

The evidence store is a content-addressed filesystem that links chain hashes to full payloads.

**Reference:** Spec Section 6.

### 8.1 Storage Layout

```
evidence/
    a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6   ← filename = hex(hash_16)
    b7e8f9a0c1d2e3f4a5b6c7d8e9f0a1b2
    ...
```

Each file contains the raw bytes that were hashed (after PII filtering). The filename IS the 128-bit truncated SHA-256 hash encoded as hexadecimal.

### 8.2 Hash Computation

```
full_hash = SHA-256(filtered_payload)
hash_16 = full_hash[:16]       // first 16 bytes (128 bits)
filename = hex(hash_16)        // 32 hex characters
```

This same `hash_16` is what goes into `parameters_hash` or `result_hash` in the ActionRecord.

### 8.3 Atomic Writes

Evidence files MUST be written atomically to avoid TOCTOU races. The pattern:

```
function store(payload):
    hash_16 = sha256(payload)[:16]
    target_path = evidence_dir / hex(hash_16)

    if target_path.exists():
        return hash_16    // content-addressed: if it exists, it's correct

    // Atomic write: temp file + rename
    tmp_fd, tmp_path = mkstemp(dir=evidence_dir)
    try:
        write(tmp_fd, payload)
        close(tmp_fd)
        rename(tmp_path, target_path)    // atomic on POSIX
    catch:
        close(tmp_fd)
        unlink(tmp_path)
        raise

    return hash_16
```

### 8.4 Lifecycle Management

| Status | Meaning | Action |
|--------|---------|--------|
| Available | File exists locally | Normal state |
| Exported | Shipped to external store | Local copy may be deleted |
| Expired | Deleted per retention policy | Hash remains in chain |
| Erased | Deleted per privacy/GDPR request | Hash remains in chain |
| Missing | Expected but not found | Verification failure |

BatchCheckpoints include evidence status counts (`available`, `exported`, `expired`, `missing`) so operators can monitor evidence health.

### 8.5 Verification

```
function verify_evidence(hash_16):
    payload = evidence_store.retrieve(hash_16)
    if payload is null:
        return MISSING
    actual_hash = sha256(payload)[:16]
    if actual_hash != hash_16:
        return CORRUPT
    return AVAILABLE
```

---

## 9. Ed25519 Signing (Level 2+)

At Level 2 and above, BatchCheckpoints MUST be cryptographically signed.

**Reference:** Spec Section 7.

### 9.1 Key Generation

Generate an Ed25519 keypair at SDK startup:

```
function generate_keypair():
    private_key = ed25519_generate_private_key()
    public_key = ed25519_derive_public_key(private_key)
    key_id = sha256(public_key_bytes)    // full 32-byte SHA-256

    return {
        private_key_bytes: 32 bytes,
        public_key_bytes:  32 bytes,
        key_id:            32 bytes
    }
```

If the Ed25519 library is not available, the SDK MUST fail at startup (not silently downgrade to Level 1). Level 2+ is an explicit security commitment.

### 9.2 KeyGenesisRecord

Before signing any checkpoint, emit a `KeyGenesisRecord`:

```
KeyPayload {
    public_key:         32-byte Ed25519 public key
    key_id:             SHA-256(public_key)
    expires_at:         0 (no expiry for session keys)
    supersedes_key_id:  0x00 * 32 (initial key, not a rotation)
}
```

### 9.3 Merkle Tree Construction

BatchCheckpoints include a Merkle root over all records since the last checkpoint. The tree follows RFC 6962 Section 2.1:

```
function compute_merkle_root(record_hashes):
    // record_hashes: list of SHA-256(canonical_bytes(record)), each 32 bytes

    if record_hashes is empty:
        return 0x00 * 32

    // Leaf nodes: prefix each hash with 0x00
    nodes = [sha256(0x00 + h) for h in record_hashes]

    if len(nodes) == 1:
        return nodes[0]

    // Build tree bottom-up
    while len(nodes) > 1:
        new_nodes = []
        for i in range(0, len(nodes), 2):
            if i + 1 < len(nodes):
                // Internal node: prefix with 0x01
                combined = 0x01 + nodes[i] + nodes[i+1]
            else:
                // Odd node: duplicate it
                combined = 0x01 + nodes[i] + nodes[i]
            new_nodes.append(sha256(combined))
        nodes = new_nodes

    return nodes[0]
```

**Important:** The leaf prefix is `0x00` and the internal node prefix is `0x01`. This prevents second-preimage attacks per RFC 6962.

### 9.4 Checkpoint Signing

```
function emit_signed_checkpoint():
    // 1. Compute Merkle root of records since last checkpoint
    merkle_root = compute_merkle_root(record_hashes_since_checkpoint)

    // 2. Sign the Merkle root directly (32 bytes, no framing)
    signature = ed25519_sign(merkle_root, private_key_bytes)

    // 3. Build CheckpointPayload
    payload = CheckpointPayload {
        record_count:   chain.record_count + 1,
        gap_count:      chain.gap_count,
        chain_hash:     chain.prev_hash,
        merkle_root:    merkle_root,
        signature:      signature,          // 64 bytes
        signing_key_id: keypair.key_id,     // 32 bytes
        evidence_status: { ... }
    }

    // 4. Write to chain
    chain.write_record(payload)

    // 5. Reset counters
    record_hashes_since_checkpoint = []
```

### 9.5 Key Rotation Handoff

When rotating keys (spec Section 7.3):

```
1. Generate new keypair.
2. Emit KeyGenesisRecord with:
       public_key = new_public_key
       supersedes_key_id = old_keypair.key_id
3. The NEXT BatchCheckpoint is signed with the OLD key.
   (This checkpoint covers the KeyGenesisRecord.)
4. The BatchCheckpoint AFTER THAT is signed with the NEW key.
   (This proves continuity — the new key is now active.)
5. Retire the old key.
```

This two-checkpoint handoff ensures a signed chain of custody. An auditor can verify: the old key signed a checkpoint covering the rotation record, and the new key signed the next checkpoint.

---

## 10. Witness Protocol (Level 3)

At Level 3, the SDK submits checkpoints to independent witness services.

**Reference:** Spec Section 8.

### 10.1 Checkpoint Submission

```
POST /ahp/v1/checkpoints
Content-Type: application/json

{
    "agent_id":       "<UUID hex>",
    "chain_hash":     "<64 hex chars>",
    "sequence":       <uint64>,
    "timestamp_ms":   <uint64>,
    "signature":      "<hex-encoded Ed25519 signature>",
    "signing_key_id": "<hex-encoded key_id>"
}
```

The signature covers `chain_hash` (the `prev_hash` of the chain head). The witness verifies the signature against the agent's known public key.

### 10.2 Receipt Storage

On a successful response (HTTP 200), the witness returns a receipt. Store it as a `WitnessPayload` record in the chain:

```
WitnessPayload {
    witness_id:         receipt["witness_id"],
    checkpoint_seq:     sequence,
    checkpoint_hash:    chain.prev_hash,
    witness_timestamp:  receipt["timestamp_ms"],
    receipt_signature:  bytes.fromhex(receipt["signature"]),
    witness_public_key: bytes.fromhex(receipt["public_key"])
}
```

### 10.3 Retry with Exponential Backoff

Per spec Section 8.5:

```
max_retries = 3
delays = [1s, 2s, 4s]

for attempt in 0..max_retries:
    try:
        receipt = http_post(endpoint, checkpoint_data)
        if receipt is not null:
            write_witness_record(receipt)
            return
    catch:
        if attempt < max_retries:
            sleep(delays[attempt])

// All retries failed
log_warning("Witness checkpoint to {endpoint} failed after {max_retries} retries")
// Do NOT block the agent. The chain continues without this witness receipt.
```

At Level 3, persistent failure (>3 consecutive intervals without a witness receipt) SHOULD trigger an operator alert.

### 10.4 Witness Signature Verification

When verifying a chain, check WitnessReceipt records:

1. Extract `witness_public_key` from the receipt.
2. Reconstruct the signed data (checkpoint fields + `witness_timestamp`).
3. Verify the Ed25519 signature.
4. Cross-reference: the `checkpoint_hash` in the receipt should match the `prev_hash` at `checkpoint_seq` in the chain.

---

## 11. Interceptor Patterns

Interceptors capture protocol-specific call data transparently, without requiring changes to agent code.

**Reference:** `ahp/interceptors/` in the reference implementation.

### 11.1 Approaches

| Approach | Pros | Cons | Used for |
|----------|------|------|----------|
| Monkey-patching | Zero agent code changes | Fragile across library versions | HTTP (`urllib`), MCP (`ClientSession`) |
| Wrapper/Decorator | Explicit, easy to debug | Requires agent code change | gRPC, custom protocols |
| Middleware | Idiomatic for web frameworks | Framework-specific | Express, FastAPI, etc. |
| Import hook | Transparent for any library | Complex to implement | Advanced use cases |

### 11.2 HTTP Interceptor Pattern

The reference HTTP interceptor monkey-patches `urllib.request.urlopen`:

```
function install_http_interceptor(recorder):
    original_urlopen = urllib.request.urlopen

    function intercepted_urlopen(url, data, ...):
        // 1. Extract request metadata
        method = "POST" if data else "GET"
        url_str = extract_url(url)
        request_body = extract_body(data)

        // 2. Execute the real HTTP call
        start = now()
        try:
            response = original_urlopen(url, data, ...)
            response_body = response.read()
            status_code = response.status
        catch error:
            response_body = str(error)
            status_code = 0
        duration_ms = elapsed_ms(start)

        // 3. Record in AHP (fail-open)
        try:
            recorder.safe_record(
                tool_name = url_str,
                parameters = request_body,
                result = response_body,
                protocol = HTTP,
                action_type = TOOL_CALL,
                response_time_ms = duration_ms,
            )
        catch:
            pass    // NEVER crash the agent

        // 4. Return response to caller
        // Wrap the response to allow re-reading the body
        return ReadableResponse(original_response, response_body)

    urllib.request.urlopen = intercepted_urlopen
```

**Critical:** The interceptor reads the full response body for hashing, then wraps the response so the caller can still `read()` it. Without this wrapper, the caller would get an empty response.

### 11.3 MCP Interceptor Pattern

The MCP interceptor patches `mcp.ClientSession.call_tool`:

```
function patch_mcp_client(recorder):
    original_call_tool = ClientSession.call_tool

    async function intercepted_call_tool(self, name, arguments):
        params_bytes = json_serialize(arguments, sort_keys=true)
        start = now()

        try:
            result = await original_call_tool(self, name, arguments)
        catch error:
            record_tool_call(name, params_bytes, str(error), elapsed_ms(start), false)
            raise   // Re-raise to the agent

        result_bytes = extract_result_content(result)
        record_tool_call(name, params_bytes, result_bytes, elapsed_ms(start), true)
        return result

    ClientSession.call_tool = intercepted_call_tool
```

### 11.4 Detecting LLM API Calls

For inference recording, the HTTP interceptor inspects the URL to detect known LLM API endpoints:

- `api.openai.com/v1/chat/completions`
- `api.anthropic.com/v1/messages`
- `generativelanguage.googleapis.com`
- Custom endpoints configured via `inference_endpoints` in config

When a known LLM endpoint is detected, the interceptor sets `action_type = INFERENCE` and extracts `model_id`, `input_token_count`, and `output_token_count` from the response.

### 11.5 gRPC Interceptor Pattern

For gRPC, use a client-side unary interceptor:

```
function grpc_interceptor(request, metadata, client_info, invoker):
    start = now()
    try:
        response = invoker(request, metadata)
    catch error:
        record_action(client_info.method, request, error, elapsed_ms(start), GRPC)
        raise
    record_action(client_info.method, request, response, elapsed_ms(start), GRPC)
    return response
```

### 11.6 A2A Interceptor

For Google's Agent-to-Agent protocol, intercept `tasks/send` and `tasks/sendSubscribe` JSON-RPC calls. Set `protocol = A2A` and `action_type = DELEGATION` or `MESSAGE` as appropriate.

---

## 12. W3C Trace Context

AHP uses W3C Trace Context headers for cross-agent linking, enabling distributed tracing across multi-agent systems.

**Reference:** Spec Section 9.

### 12.1 Header Encoding

**`traceparent`** follows the standard W3C format:

```
{version}-{trace_id}-{parent_id}-{flags}
00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01
```

- `version`: "00"
- `trace_id`: 16 bytes hex (32 chars) — shared across all agents in a request
- `parent_id`: 8 bytes hex (16 chars) — unique per span
- `flags`: "01" for sampled, "00" for not sampled

**`tracestate`** carries AHP-specific data under the `"ahp"` vendor key:

```
tracestate: ahp=<base64url_encoded_data>,other_vendor=value
```

The AHP tracestate value encodes 40 bytes:

```
agent_id (16 bytes) + sequence (8 bytes, big-endian) + chain_hash (16 bytes)
```

Encoded as base64url without padding (54 characters).

### 12.2 Encoding/Decoding

```
function encode_tracestate_ahp(agent_id, sequence, chain_hash):
    data = agent_id                         // 16 bytes
         + uint64_big_endian(sequence)      // 8 bytes (NOTE: big-endian!)
         + chain_hash[:16]                  // first 16 bytes of 32-byte hash
    return base64url_encode_no_padding(data)

function decode_tracestate_ahp(encoded):
    data = base64url_decode(encoded)
    if len(data) != 40: return null
    return {
        agent_id:   data[0:16],
        sequence:   parse_uint64_big_endian(data[16:24]),
        chain_hash: data[24:40]
    }
```

**Important:** The sequence in tracestate uses **big-endian** encoding (for network byte order compatibility), unlike the canonical serialization which uses little-endian.

### 12.3 Injection and Extraction

For outgoing requests (agent → tool, agent → agent):

```
function inject_trace_headers(headers, trace_id, agent_id, sequence, chain_hash):
    span_id = random_bytes(8)
    headers["traceparent"] = format_traceparent(trace_id, span_id)

    ahp_value = encode_tracestate_ahp(agent_id, sequence, chain_hash)
    existing_tracestate = headers.get("tracestate", "")
    headers["tracestate"] = "ahp=" + ahp_value
    if existing_tracestate:
        headers["tracestate"] += "," + existing_tracestate

    return headers
```

For incoming requests:

```
function extract_trace_context(headers):
    traceparent = parse_traceparent(headers["traceparent"])
    if traceparent is null: return null

    tracestate = headers.get("tracestate", "")
    ahp_data = parse_tracestate_ahp(tracestate)

    return {
        trace_id: traceparent.trace_id,
        span_id:  traceparent.span_id,
        sampled:  traceparent.sampled,
        ahp:      ahp_data    // may be null if no AHP data
    }
```

### 12.4 Graceful Degradation

If middleware strips `tracestate`, cross-agent linking degrades gracefully:

| What's Preserved | Capability |
|-----------------|------------|
| Both headers | Full cross-agent linking |
| Only `traceparent` | `trace_id` enables backend stitching |
| Neither header | Records exist independently; no cross-agent correlation |

No data is lost in any case — only correlation capability degrades.

---

## 13. Configuration

### 13.1 Config File Format

AHP configuration is typically YAML, with JSON as a fallback. The reference Python SDK uses `ahp.yaml`.

```yaml
# ahp.yaml — example configuration
defaults:
  level: 2
  inference:
    record: true
    evidence: true
  evidence:
    record: true
  authorization:
    record: false
  fsync_mode: batch
  checkpoint_interval: 1000
  witness:
    enabled: false
    interval: 1000
    endpoints: []

# PII filters (global)
filters:
  - preset: pci
  - preset: credentials
  - name: internal_ids
    pattern: 'ACCT-\d{8}'
    replacement: '[REDACTED:ACCT]'
    scope: [parameters, results]

# Per-agent overrides
agents:
  - match: "payment-*"
    level: 3
    witness:
      enabled: true
      endpoints:
        - https://witness.example.com/ahp/v1
    filters:
      - preset: pii-us

  - match: "dev-*"
    level: 1
    inference:
      evidence: false
```

### 13.2 Search Order

SDKs MUST search for configuration in this order:

1. **Explicit path** — passed as constructor argument
2. **Environment variable** — `AHP_CONFIG` points to a file path
3. **Working directory** — `./ahp.yaml`, `./ahp.yml`, `./ahp.json`
4. **Home directory** — `~/.ahp/config.yaml`
5. **Defaults** — built-in defaults (Level 1, no filters, no witness)

First match wins. If no config file is found, build config from environment variables.

### 13.3 Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AHP_CONFIG` | (none) | Path to config file |
| `AHP_LEVEL` | `"1"` | Conformance level (1, 2, or 3) |
| `AHP_INFERENCE_RECORD` | `"true"` | Record inference calls |
| `AHP_EVIDENCE_RECORD` | `"true"` | Store evidence payloads |
| `AHP_AUTH_RECORD` | `"false"` | Record authorization context |
| `AHP_FSYNC_MODE` | `"batch"` | Fsync policy: every, batch, none |

### 13.4 Per-Agent Overrides

Per-agent rules are matched top-down by glob pattern on `agent_name`. First match wins. Unmatched agents use defaults.

Override behavior:
- `filters` at agent level are **appended** to global filters (global filters run first)
- All other fields **override** the corresponding default

### 13.5 Validation

SDKs MUST validate configuration at startup and reject invalid configs:

- `level` must be 1, 2, or 3
- `level=3` requires `witness.enabled=true` and at least one endpoint
- `fsync_mode` must be one of: `every`, `batch`, `none`
- `checkpoint_interval` must be >= 1

### 13.6 Hot-Reload Considerations

If the SDK supports hot-reloading configuration (e.g., watching the config file for changes), it MUST emit a new BootRecord with the updated configuration state. This ensures the chain documents when the policy changed.

The BootRecord serves as a "configuration boundary" — records before the BootRecord were produced under the old config, records after it under the new config.

---

## 14. Fail-Open Design

AHP MUST NEVER crash the agent. This is the single most important design principle. A recording failure is always less important than the agent continuing to function.

**Reference:** Spec Section 3.2 (Interceptor failure).

### 14.1 The `safe_record` Pattern

Every public recording method should have a fail-open wrapper:

```
function safe_record(**kwargs):
    try:
        return record_action(**kwargs)
    catch Exception as exc:
        // Remember the gap for later documentation
        if not pending_gap:
            gap_first_lost_seq = chain.sequence + 1
        pending_gap = true
        gap_reason = INTERCEPTOR_FAILURE
        gap_detail = str(exc)

        log_warning("AHP safe_record failed: " + str(exc))
        return null
```

### 14.2 Deferred GapRecord Emission

When `safe_record` catches an exception, it sets a `pending_gap` flag. On the **next successful** call to `record_action()`, the pending gap is flushed first:

```
function record_action(**kwargs):
    // Flush any pending gap from previous failure
    if pending_gap:
        emit_gap_record(
            first_lost = gap_first_lost_seq,
            last_lost = chain.sequence,    // current tip
            reason = gap_reason,
            detail = gap_detail,
        )
        pending_gap = false

    // Normal recording continues...
```

This ensures that even transient failures are documented in the chain, but only when the SDK has recovered enough to write again.

### 14.3 Where to Catch Exceptions

Every layer in the pipeline has its own error handling:

| Layer | Error Handling |
|-------|---------------|
| Interceptor | Wrap entire intercept in try/catch; on failure, call `safe_record` |
| `safe_record` | Catch all exceptions from `record_action`; set pending gap |
| `record_action` | Catches internal errors; validation failures → GapRecord |
| Chain Writer | I/O errors → rollback in-memory state, re-raise to caller |
| Witness Client | All errors caught; logged; never blocks agent |
| Evidence Store | Store failures logged; record still valid without evidence |

### 14.4 Validation Failure Recovery

If a record fails validation (e.g., oversized field, invalid enum value), the chain writer replaces it with a GapRecord:

```
function write_record_unlocked(payload):
    record = build_record(payload)
    errors = validate_record(record)

    if errors:
        // Replace with a GapRecord documenting the validation failure
        gap_payload = GapPayload {
            first_lost = self.sequence,
            last_lost = self.sequence,
            count = 1,
            reason = INTERCEPTOR_FAILURE,
            detail = "Validation failed: " + join(errors, "; ")
        }
        record = build_record(gap_payload)

    // Continue with serialization and writing...
```

This prevents infinite recursion (validation failure on a GapRecord) by checking whether the payload is already a validation-failure GapRecord.

---

## 15. Async/Sync Considerations

### 15.1 Synchronous SDK Design

For sync frameworks (standard threading), the chain writer uses a `threading.Lock` (or language equivalent mutex):

```
class ChainWriter:
    lock = threading.Lock()

    function write_record(payload):
        with lock:
            return write_record_unlocked(payload)
```

The recorder itself uses a separate `RLock` (reentrant lock) for counters and checkpoint logic:

```
Lock hierarchy (acquire in this order to prevent deadlocks):
    1. recorder_lock (RLock)     — protects counters, checkpoint logic
    2. chain._lock (Lock)        — protects chain file I/O

NEVER acquire recorder_lock while holding chain._lock.
```

### 15.2 Asynchronous SDK Design

For async frameworks (asyncio, Tokio, etc.), the key challenge is that disk I/O should not block the event loop.

The reference `AsyncChainWriter` uses a **queue-based staging** pattern:

```
class AsyncChainWriter:
    queue: AsyncQueue[bytes]       // staging buffer
    write_lock: AsyncLock          // protects sequence/prev_hash assignment

    async function write_record(payload):
        async with write_lock:
            // Assign sequence + prev_hash synchronously (correct ordering)
            record = build_record(payload)
            stored = canonical_bytes(record)
            update_chain_state(stored)

            // Queue for background disk write
            await queue.put(stored)
            return record

    async function drain_loop():
        // Background task: drains queue → disk (in a thread)
        while running:
            stored = await queue.get(timeout=0.1)
            await run_in_thread(write_to_file, stored)
```

**Critical design choice:** Sequence assignment and `prev_hash` computation happen synchronously under the async lock. Only the disk I/O is deferred to the background drain task. This ensures the hash chain is always consistent, even if disk writes are batched or reordered.

### 15.3 Queue Overflow

If the queue fills up (agent producing records faster than disk can drain), the SDK has two options:

1. **Block** — `await queue.put()` blocks the caller until space is available. This adds back-pressure to the agent.
2. **Drop** — Drop the oldest entries and emit a GapRecord with `reason = BACKPRESSURE`.

Option 2 is preferred for fail-open design. Set `max_queue` to a reasonable limit (e.g., 10,000 records).

### 15.4 Language-Specific Guidance

| Language | Sync Lock | Async Lock | Queue | Thread Pool |
|----------|-----------|------------|-------|-------------|
| Python | `threading.Lock` | `asyncio.Lock` | `asyncio.Queue` | `asyncio.to_thread` |
| Go | `sync.Mutex` | N/A (goroutines) | `chan` | Built-in |
| Rust | `std::sync::Mutex` | `tokio::sync::Mutex` | `tokio::sync::mpsc` | `tokio::task::spawn_blocking` |
| Java | `ReentrantLock` | `java.util.concurrent.locks` | `LinkedBlockingQueue` | `ExecutorService` |
| TypeScript | N/A (single-threaded) | Mutex library or queue | `Array` + drain | `worker_threads` for I/O |

---

## 16. Conformance Testing

### 16.1 Test Vectors

The spec includes test vectors in Appendix F. Each test vector provides:

1. A record with specific field values.
2. The expected `canonical_bytes` output (hex-encoded).
3. The expected SHA-256 hash of those bytes.

Your SDK is conformant when:

```
for each test_vector:
    record = construct_record(test_vector.fields)
    actual_bytes = canonical_bytes(record)
    assert actual_bytes == test_vector.expected_bytes
    assert sha256(actual_bytes) == test_vector.expected_hash
```

### 16.2 Cross-SDK Compatibility

The primary interoperability requirement is that **canonical_bytes is deterministic and identical across SDKs**. To verify this:

1. Construct the same logical record in two different SDKs.
2. Call `canonical_bytes()` in each.
3. The output must be byte-identical.
4. SHA-256 of the output must match.

If any byte differs, the hash chains will diverge and cross-SDK verification will fail.

### 16.3 Common Conformance Failures

| Failure | Cause | Fix |
|---------|-------|-----|
| Different bytes at offset 72 | Wrong endianness for `sequence` | Use little-endian for all integers |
| Different bytes after envelope | Missing payload type discriminator | Emit `uint32_le(record_type)` between envelope and payload |
| Shorter output | Missing optional fields | Every field must be present; zero-fill unset optionals |
| Longer output | Length prefix on fixed-size fields | `bytes[N]` fields have no length prefix |
| Different hash for same record | String encoding difference | Strings must be UTF-8 with uint32 LE length prefix |
| Enum value 0 in output | Using protobuf default | Value 0 is UNSPECIFIED and MUST NOT appear |

### 16.4 Chain Verification Test

Beyond canonical bytes, test the full chain:

```
function test_chain_verification():
    writer = ChainWriter("test.ahp")

    // Write 10 records
    for i in 1..10:
        writer.write_record(some_payload)

    // Read and verify
    reader = ChainReader("test.ahp")
    prev_hash = 0x00 * 32
    expected_seq = 1

    for stored in reader.iter_records():
        envelope = parse_envelope(stored)
        assert envelope.sequence == expected_seq
        assert envelope.prev_hash == prev_hash

        prev_hash = sha256(stored)
        expected_seq += 1
```

### 16.5 Recovery Test

```
function test_crash_recovery():
    // 1. Write 5 valid records
    // 2. Append garbage bytes to the chain file (simulate crash)
    // 3. Run recover_chain()
    // 4. Assert: records_verified == 5, records_truncated >= 1
    // 5. Assert: file is truncated to valid offset
    // 6. Write new records — chain continues with correct prev_hash
```

### 16.6 Filter Compatibility Test

```
function test_filter_config_hash():
    // Construct the same filter pipeline in your SDK
    // Compute filter_config_hash
    // Assert it matches the expected SHA-256 from the test vector

    // Also test filter application:
    // Apply the "pci" preset to a known input containing a credit card number
    // Assert the output matches the expected redacted text
    // Assert the hash of the redacted text matches the expected hash
```

---

## Appendix: Quick Reference

### Record Type Summary

| Type | Enum Value | When Emitted |
|------|-----------|--------------|
| BOOT | 4 | SDK startup, config change |
| KEY | 6 | Before first signed checkpoint (Level 2+) |
| ACTION | 1 | Every intercepted agent action |
| GAP | 2 | When records are lost |
| CHECKPOINT | 3 | Every N records (default 1000) |
| RECOVERY | 5 | After crash recovery |
| WITNESS | 7 | After successful witness checkpoint |

### SDK Startup Sequence

```
1. Load configuration (search order: explicit → env → ./ahp.yaml → ~/.ahp/config.yaml)
2. Validate configuration (reject invalid combos like level=3 without witness)
3. If chain file exists: run crash recovery protocol
4. Open ChainWriter (acquire file lock)
5. Open EvidenceStore (if configured)
6. Initialize PII FilterPipeline
7. Generate Ed25519 keypair (if level >= 2)
8. Emit BootRecord
9. Emit KeyGenesisRecord (if level >= 2)
10. Emit RecoveryRecord + GapRecord (if recovery found truncated data)
11. Install interceptors
12. Ready to record
```

### Conformance Level Checklist

**Level 1 (Hash Chain):** Canonical serialization, hash chain, BootRecord, GapRecord, RecoveryRecord, PII filters, evidence store, UUID v7, authorization field on all ActionRecords.

**Level 2 (adds):** Ed25519 keypair, KeyGenesisRecord, signed BatchCheckpoints with Merkle root, key rotation handoff.

**Level 3 (adds):** Witness client, WitnessReceipt storage, retry with backoff, export-gated rotation, at least one witness endpoint.

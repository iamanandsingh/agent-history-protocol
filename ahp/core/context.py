"""W3C Trace Context propagation — Section 9 of the AHP specification.

Encodes/decodes AHP data in W3C traceparent + tracestate headers
for cross-agent linking. Compatible with OpenTelemetry.

traceparent: standard W3C format (version-trace_id-parent_id-flags)
tracestate: AHP data under key "ahp" as base64url(agent_id || sequence_be || chain_hash_16)
"""

from __future__ import annotations

import base64
import os
import struct
from typing import Dict, Optional


def generate_trace_id() -> bytes:
    """Generate a 16-byte trace ID (shared across all agents in a request)."""
    return os.urandom(16)


def generate_span_id() -> bytes:
    """Generate an 8-byte span ID."""
    return os.urandom(8)


def create_traceparent(trace_id: bytes, span_id: Optional[bytes] = None, sampled: bool = True) -> str:
    """Create a W3C traceparent header value.

    Format: {version}-{trace_id}-{parent_id}-{flags}
    Example: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01
    """
    version = "00"
    tid = trace_id.hex()
    sid = (span_id or generate_span_id()).hex()
    flags = "01" if sampled else "00"
    return f"{version}-{tid}-{sid}-{flags}"


def parse_traceparent(header: str) -> Optional[Dict[str, bytes]]:
    """Parse a W3C traceparent header.

    Returns dict with trace_id (16 bytes), span_id (8 bytes), sampled (bool)
    or None if invalid.
    """
    parts = header.strip().split("-")
    if len(parts) != 4:
        return None

    try:
        version = parts[0]
        trace_id = bytes.fromhex(parts[1])
        span_id = bytes.fromhex(parts[2])
        flags = int(parts[3], 16)

        if len(trace_id) != 16 or len(span_id) != 8:
            return None

        return {
            "version": version,
            "trace_id": trace_id,
            "span_id": span_id,
            "sampled": bool(flags & 0x01),
        }
    except (ValueError, IndexError):
        return None


def encode_tracestate_ahp(agent_id: bytes, sequence: int, chain_hash: bytes) -> str:
    """Encode AHP data for the tracestate header.

    Format: base64url(agent_id || sequence_uint64_be || chain_hash_16bytes)
    Total: 16 + 8 + 16 = 40 bytes → 54 chars base64url (no padding)

    Per spec Section 9.1.
    """
    # agent_id: 16 bytes
    # sequence: 8 bytes big-endian
    # chain_hash: first 16 bytes of the 32-byte hash
    data = agent_id + struct.pack(">Q", sequence) + chain_hash[:16]
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def decode_tracestate_ahp(encoded: str) -> Optional[Dict]:
    """Decode AHP data from tracestate value.

    Returns dict with agent_id (16 bytes), sequence (int), chain_hash (16 bytes)
    or None if invalid.
    """
    try:
        # Add padding back
        padded = encoded + "=" * (4 - len(encoded) % 4) if len(encoded) % 4 else encoded
        data = base64.urlsafe_b64decode(padded)

        if len(data) != 40:
            return None

        agent_id = data[:16]
        sequence = struct.unpack(">Q", data[16:24])[0]
        chain_hash = data[24:40]

        return {
            "agent_id": agent_id,
            "sequence": sequence,
            "chain_hash": chain_hash,
        }
    except Exception:
        return None


def create_tracestate(ahp_value: str, existing: str = "") -> str:
    """Create or update tracestate header with AHP data.

    Preserves existing vendor entries. AHP key is added/updated.
    Per W3C spec, tracestate is comma-separated key=value pairs.
    """
    pairs = []

    # Parse existing tracestate
    if existing:
        for pair in existing.split(","):
            pair = pair.strip()
            if pair and not pair.startswith("ahp="):
                pairs.append(pair)

    # Add AHP entry at the beginning (most recently modified)
    pairs.insert(0, f"ahp={ahp_value}")

    return ",".join(pairs)


def parse_tracestate_ahp(tracestate: str) -> Optional[Dict]:
    """Extract and decode AHP data from a tracestate header.

    Returns decoded AHP data or None if not present.
    """
    for pair in tracestate.split(","):
        pair = pair.strip()
        if pair.startswith("ahp="):
            return decode_tracestate_ahp(pair[4:])
    return None


def inject_headers(
    headers: Dict[str, str], trace_id: bytes, agent_id: bytes, sequence: int, chain_hash: bytes
) -> Dict[str, str]:
    """Inject W3C Trace Context headers for outgoing requests.

    Adds/updates traceparent and tracestate headers.
    """
    span_id = generate_span_id()
    headers["traceparent"] = create_traceparent(trace_id, span_id)

    ahp_value = encode_tracestate_ahp(agent_id, sequence, chain_hash)
    existing_tracestate = headers.get("tracestate", "")
    headers["tracestate"] = create_tracestate(ahp_value, existing_tracestate)

    return headers


def extract_context(headers: Dict[str, str]) -> Optional[Dict]:
    """Extract trace context from incoming request headers.

    Returns dict with trace_id, span_id, sampled, and optionally
    ahp (agent_id, sequence, chain_hash) from tracestate.
    """
    traceparent = headers.get("traceparent", "")
    if not traceparent:
        return None

    parsed = parse_traceparent(traceparent)
    if not parsed:
        return None

    result = dict(parsed)

    # Try to extract AHP data from tracestate
    tracestate = headers.get("tracestate", "")
    if tracestate:
        ahp_data = parse_tracestate_ahp(tracestate)
        if ahp_data:
            result["ahp"] = ahp_data

    return result

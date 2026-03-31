"""AHP CLI — ahp log, ahp show, ahp verify, ahp export, ahp trace, ahp gaps, ahp tail, ahp init, ahp keygen."""

from __future__ import annotations

import json
import os
import struct
import sys
import time
import zlib
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple  # noqa: F401 (used in annotations)

from ahp.core.chain import (
    HEADER_SIZE,
    MAGIC,
    MAX_RECORD_SIZE,
    ChainReader,
    parse_action_payload,
    parse_envelope,
    parse_gap_payload,
    parse_witness_payload,
)
from ahp.core.json_format import format_action_summary, record_to_json
from ahp.core.types import (
    ZERO_UUID,
    ActionType,
    AuthorizationType,
    GapReason,
    RecordType,
)
from ahp.core.uuid7 import uuid7, uuid7_to_str
from ahp.core.verify import verify_chain


def _ts(ms: int) -> str:
    """Format timestamp_ms to HH:MM:SS."""
    dt = datetime.fromtimestamp(ms / 1000, tz=timezone.utc)
    return dt.strftime("%H:%M:%S")


def _find_chain(chain_arg: Optional[str]) -> str:
    """Find chain file from argument or current directory."""
    if chain_arg:
        return chain_arg
    # Look for .ahp files in current directory
    ahp_files = list(Path(".").glob("*.ahp"))
    if len(ahp_files) == 1:
        return str(ahp_files[0])
    if len(ahp_files) > 1:
        print(f"Multiple chain files found: {[f.name for f in ahp_files]}")
        print("Specify one with: ahp log --chain <file>")
        sys.exit(1)
    print("No .ahp chain file found in current directory.")
    print("Specify one with: ahp log --chain <file>")
    sys.exit(1)


# ---------------------------------------------------------------------------
# cmd_log — with --authorized-by and --unauthorized filters
# ---------------------------------------------------------------------------


def cmd_log(
    chain: Optional[str] = None,
    last: Optional[int] = None,
    authorized_by: Optional[str] = None,
    unauthorized: bool = False,
) -> None:
    """Display records in the chain."""
    path = _find_chain(chain)
    reader = ChainReader(path)
    all_bytes = reader.read_all()

    if last:
        all_bytes = all_bytes[-last:]

    # Apply filters
    if authorized_by or unauthorized:
        filtered = []  # type: List[bytes]
        for stored in all_bytes:
            env = parse_envelope(stored)
            if env["record_type"] != RecordType.ACTION:
                continue
            payload = parse_action_payload(env["payload_bytes"])
            auth_type = AuthorizationType(payload["authorization"]["type"])

            if unauthorized:
                if auth_type == AuthorizationType.AUTH_NONE:
                    filtered.append(stored)
            elif authorized_by:
                for entry in payload["authorization"]["entries"]:
                    if authorized_by.lower() in entry["authorizer_id"].lower():
                        filtered.append(stored)
                        break
        all_bytes = filtered

    if not all_bytes:
        print("Chain is empty." if not (authorized_by or unauthorized) else "No matching records.")
        return

    # Header
    print(
        f"\n{'#':>4} | {'Time':8} | {'Type':10} | {'Proto':6} | {'Tool/Name':25} | {'Status':7} | {'Auth':20} | {'Latency':>8}"
    )
    print("\u2500" * 105)

    for stored in all_bytes:
        summary = format_action_summary(stored)
        seq = summary["sequence"]
        ts = _ts(summary["timestamp_ms"])
        rtype = summary["type"]
        proto = summary["protocol"][:6]
        tool = summary["tool_name"][:25]
        status = summary["result_status"]
        auth = summary["authorization"][:20]
        latency = f"{summary['response_time_ms']}ms" if summary["tool_name"] != "—" else "—"

        print(f"{seq:>4} | {ts:8} | {rtype:10} | {proto:6} | {tool:25} | {status:7} | {auth:20} | {latency:>8}")

    print(f"\n{len(all_bytes)} records displayed.\n")


# ---------------------------------------------------------------------------
# cmd_show — with --tree flag
# ---------------------------------------------------------------------------


def cmd_show(record_seq: int, chain: Optional[str] = None, tree: bool = False) -> None:
    """Show full details of a single record."""
    path = _find_chain(chain)
    reader = ChainReader(path)
    all_bytes = reader.read_all()

    if not tree:
        for stored in all_bytes:
            env = parse_envelope(stored)
            if env["sequence"] == record_seq:
                j = record_to_json(stored)
                print(json.dumps(j, indent=2, default=str))
                return
        print(f"Record with sequence {record_seq} not found.")
        return

    # --tree mode: show the record and all descendants
    # First, find the target record's record_id
    target_record_id = None  # type: Optional[bytes]
    records_by_seq = {}  # type: Dict[int, bytes]
    for stored in all_bytes:
        env = parse_envelope(stored)
        records_by_seq[env["sequence"]] = stored
        if env["sequence"] == record_seq:
            target_record_id = env["record_id"]

    if target_record_id is None:
        print(f"Record with sequence {record_seq} not found.")
        return

    # Build parent_action_id -> children mapping
    children_map = defaultdict(list)  # type: Dict[bytes, List[int]]
    record_id_to_seq = {}  # type: Dict[bytes, int]
    for stored in all_bytes:
        env = parse_envelope(stored)
        record_id_to_seq[env["record_id"]] = env["sequence"]
        if env["record_type"] == RecordType.ACTION:
            payload = parse_action_payload(env["payload_bytes"])
            parent_id = payload["parent_action_id"]
            if parent_id != ZERO_UUID:
                children_map[parent_id].append(env["sequence"])

    # Recursive tree display
    def _print_tree(seq: int, indent: int) -> None:
        stored = records_by_seq.get(seq)
        if stored is None:
            return
        env = parse_envelope(stored)
        prefix = "  " * indent
        if env["record_type"] == RecordType.ACTION:
            payload = parse_action_payload(env["payload_bytes"])
            atype = ActionType(payload["action_type"]).name
            tool = payload["tool_name"]
            print(f"{prefix}[{seq}] {atype}: {tool}")
        else:
            print(f"{prefix}[{seq}] {env['record_type'].name}")

        # Find children of this record
        rid = env["record_id"]
        for child_seq in sorted(children_map.get(rid, [])):
            _print_tree(child_seq, indent + 1)

    print(f"\nCausal tree rooted at record #{record_seq}:\n")
    _print_tree(record_seq, 0)
    print()


# ---------------------------------------------------------------------------
# cmd_verify — with --witness flag
# ---------------------------------------------------------------------------


def cmd_verify(chain: Optional[str] = None, witness: bool = False) -> None:
    """Verify chain integrity."""
    path = _find_chain(chain)
    reader = ChainReader(path)
    all_bytes = reader.read_all()
    total = len(all_bytes)

    if witness:
        # Witness receipt summary
        witness_records = []
        max_checkpoint_seq = 0
        for stored in all_bytes:
            env = parse_envelope(stored)
            if env["record_type"] == RecordType.WITNESS:
                wpayload = parse_witness_payload(env["payload_bytes"])
                witness_records.append(wpayload)
                if wpayload["checkpoint_seq"] > max_checkpoint_seq:
                    max_checkpoint_seq = wpayload["checkpoint_seq"]

        n = len(witness_records)
        if n == 0:
            print("\n0 witness receipts found.\n")
        else:
            print(f"\n{n} witness receipt(s) found, covering sequences up to {max_checkpoint_seq}.\n")
            for i, w in enumerate(witness_records):
                print(
                    f"  [{i + 1}] witness_id={w['witness_id']}, "
                    f"checkpoint_seq={w['checkpoint_seq']}, "
                    f"hash={w['checkpoint_hash'].hex()[:16]}..."
                )
            print()
        return

    print(f"\nVerifying chain: {Path(path).stem}")
    print(f"Records: {total}\n")

    result = verify_chain(path)

    block = "\u2588"
    shade = "\u2591"
    if result.valid:
        full_bar = block * 30
        print("Checking hash chain...  %s %d/%d\n" % (full_bar, result.records_checked, total))
        print("\u2705 CHAIN VALID")
        print("   Hash chain:    %d records verified, 0 broken links" % result.records_checked)
        print("   Gaps:          %d" % result.gaps)
    else:
        # Show progress bar up to the break
        filled = int(30 * (result.records_checked / total)) if total > 0 else 0
        bar = block * filled + shade * (30 - filled)
        print("Checking hash chain...  %s %d/%d\n" % (bar, result.records_checked, total))
        print("\u274c CHAIN BROKEN at record #%s" % result.broken_at)
        if result.expected_hash and result.actual_hash:
            print("   Expected prev_hash: %s..." % result.expected_hash.hex()[:16])
            print("   Actual prev_hash:   %s..." % result.actual_hash.hex()[:16])
        print("\n   %s" % result.error)
        print("\n   \u26a0  TAMPER DETECTED")

    print()


# ---------------------------------------------------------------------------
# cmd_export
# ---------------------------------------------------------------------------


def cmd_export(chain: Optional[str] = None, fmt: str = "json") -> None:
    """Export chain to JSON or JSONL."""
    path = _find_chain(chain)
    reader = ChainReader(path)
    all_bytes = reader.read_all()

    for stored in all_bytes:
        j = record_to_json(stored)
        print(json.dumps(j, default=str))


# ---------------------------------------------------------------------------
# cmd_trace — reconstruct decision chain for a session
# ---------------------------------------------------------------------------


def cmd_trace(session_prefix: str, chain: Optional[str] = None) -> None:
    """Reconstruct decision chain for a session."""
    path = _find_chain(chain)
    reader = ChainReader(path)
    all_bytes = reader.read_all()

    # Collect records matching session prefix
    session_records = []  # type: List[tuple]
    for stored in all_bytes:
        env = parse_envelope(stored)
        session_str = uuid7_to_str(env["session_id"])
        if session_str.startswith(session_prefix) or session_str.replace("-", "").startswith(
            session_prefix.replace("-", "")
        ):
            session_records.append((env, stored))

    if not session_records:
        print(f"No records found for session prefix: {session_prefix}")
        return

    session_id_display = uuid7_to_str(session_records[0][0]["session_id"])
    print(f"\nTrace for session {session_id_display}")
    print(f"Records: {len(session_records)}\n")

    # Build record_id -> sequence mapping and parent -> children mapping
    record_id_to_seq = {}  # type: Dict[bytes, int]
    records_by_seq = {}  # type: Dict[int, tuple]
    children_map = defaultdict(list)  # type: Dict[bytes, List[int]]
    root_seqs = []  # type: List[int]

    for env, stored in session_records:
        seq = env["sequence"]
        record_id_to_seq[env["record_id"]] = seq
        records_by_seq[seq] = (env, stored)

    # Second pass to build parent-child relationships
    for env, stored in session_records:
        seq = env["sequence"]
        if env["record_type"] == RecordType.ACTION:
            payload = parse_action_payload(env["payload_bytes"])
            parent_id = payload["parent_action_id"]
            if parent_id != ZERO_UUID and parent_id in record_id_to_seq:
                children_map[parent_id].append(seq)
            else:
                root_seqs.append(seq)
        else:
            root_seqs.append(seq)

    root_seqs.sort()

    # Recursive display
    def _trace_tree(seq: int, indent: int) -> None:
        entry = records_by_seq.get(seq)
        if entry is None:
            return
        env, stored = entry
        prefix = "  " * indent
        connector = "\u251c\u2500 " if indent > 0 else ""
        ts = _ts(env["timestamp_ms"])

        if env["record_type"] == RecordType.ACTION:
            payload = parse_action_payload(env["payload_bytes"])
            atype = ActionType(payload["action_type"]).name
            tool = payload["tool_name"]
            latency = f"{payload['response_time_ms']}ms" if payload["response_time_ms"] else ""
            print(f"{prefix}{connector}[{seq}] {ts} {atype:10} {tool} {latency}")
        elif env["record_type"] == RecordType.BOOT:
            print(f"{prefix}{connector}[{seq}] {ts} BOOT")
        elif env["record_type"] == RecordType.GAP:
            print(f"{prefix}{connector}[{seq}] {ts} GAP")
        else:
            print(f"{prefix}{connector}[{seq}] {ts} {env['record_type'].name}")

        # Print children
        rid = env["record_id"]
        child_seqs = sorted(children_map.get(rid, []))
        for child_seq in child_seqs:
            _trace_tree(child_seq, indent + 1)

    for seq in root_seqs:
        _trace_tree(seq, 0)

    print()


# ---------------------------------------------------------------------------
# cmd_gaps — list all GapRecords
# ---------------------------------------------------------------------------


def cmd_gaps(chain: Optional[str] = None) -> None:
    """List all GapRecords in the chain."""
    path = _find_chain(chain)
    reader = ChainReader(path)
    all_bytes = reader.read_all()

    gap_records = []
    for stored in all_bytes:
        env = parse_envelope(stored)
        if env["record_type"] == RecordType.GAP:
            gpayload = parse_gap_payload(env["payload_bytes"])
            gap_records.append((env, gpayload))

    if not gap_records:
        print("\nNo gaps found. Chain is contiguous.\n")
        return

    total_lost = 0
    print(f"\n{'#':>4} | {'First Lost':>10} | {'Last Lost':>10} | {'Count':>6} | {'Reason':20} | Detail")
    print("\u2500" * 80)

    for env, gpayload in gap_records:
        seq = env["sequence"]
        first = gpayload["first_lost_sequence"]
        last = gpayload["last_lost_sequence"]
        count = gpayload["count"]
        try:
            reason = GapReason(gpayload["reason"]).name
        except ValueError:
            reason = str(gpayload["reason"])
        detail = gpayload["detail"] or "\u2014"
        total_lost += count

        print(f"{seq:>4} | {first:>10} | {last:>10} | {count:>6} | {reason:20} | {detail}")

    print(f"\n{len(gap_records)} gap(s), {total_lost} record(s) lost.\n")


# ---------------------------------------------------------------------------
# cmd_tail — live tail records
# ---------------------------------------------------------------------------


def _read_frames_from(path: str, offset: int) -> Tuple[List[bytes], int]:
    """Read chain frames starting at a byte offset.

    Returns (list_of_stored_bytes, new_offset). Stops at EOF or first
    corrupt/incomplete frame (safe for partially written files).
    """
    frames = []  # type: List[bytes]
    with open(path, "rb") as f:
        f.seek(offset)
        while True:
            length_bytes = f.read(4)
            if len(length_bytes) < 4:
                break
            length = struct.unpack("<I", length_bytes)[0]
            if length > MAX_RECORD_SIZE:
                break
            stored = f.read(length)
            if len(stored) < length:
                break
            crc_bytes = f.read(4)
            if len(crc_bytes) < 4:
                break
            expected_crc = struct.unpack("<I", crc_bytes)[0]
            actual_crc = zlib.crc32(length_bytes + stored) & 0xFFFFFFFF
            if actual_crc != expected_crc:
                break
            frames.append(stored)
            offset += 4 + length + 4
    return frames, offset


def _print_record(stored: bytes, fmt: str) -> None:
    """Print a single record in the specified format. Skips unparseable records."""
    try:
        if fmt == "json":
            j = record_to_json(stored)
            print(json.dumps(j, default=str), flush=True)
        else:
            summary = format_action_summary(stored)
            seq = summary["sequence"]
            ts = _ts(summary["timestamp_ms"])
            rtype = summary["type"]
            proto = summary["protocol"][:6]
            tool = summary["tool_name"][:25]
            status = summary["result_status"]
            auth = summary["authorization"][:20]
            latency = f"{summary['response_time_ms']}ms" if summary["tool_name"] != "\u2014" else "\u2014"
            print(
                f"{seq:>4} | {ts:8} | {rtype:10} | {proto:6} | {tool:25} | {status:7} | {auth:20} | {latency:>8}",
                flush=True,
            )
    except Exception:
        pass  # Skip unparseable records


def cmd_tail(
    chain: Optional[str] = None,
    last: int = 10,
    fmt: str = "table",
    interval: float = 0.5,
) -> None:
    """Live tail — watch a chain file for new records."""
    path = _find_chain(chain)

    # Wait for file to exist
    printed_waiting = False
    while not Path(path).exists():
        if not printed_waiting:
            print(f"Waiting for {path}...", flush=True)
            printed_waiting = True
        time.sleep(interval)

    # Wait for valid header
    while Path(path).stat().st_size < HEADER_SIZE:
        time.sleep(interval)

    # Validate header
    with open(path, "rb") as f:
        header = f.read(HEADER_SIZE)
        if header[:4] != MAGIC:
            print(f"Invalid chain file: {path}")
            sys.exit(1)

    # Read all existing records to show the last N and find the end offset
    all_frames, end_offset = _read_frames_from(path, HEADER_SIZE)

    # Show last N
    tail_frames = all_frames[-last:] if last > 0 else []
    if tail_frames:
        if fmt == "table":
            print(
                f"\n{'#':>4} | {'Time':8} | {'Type':10} | {'Proto':6} | {'Tool/Name':25}"
                f" | {'Status':7} | {'Auth':20} | {'Latency':>8}"
            )
            print("\u2500" * 105)
        for stored in tail_frames:
            _print_record(stored, fmt)

    print(f"\n\u2500\u2500\u2500 Tailing {Path(path).name} (Ctrl+C to stop) \u2500\u2500\u2500\n", flush=True)

    # Poll loop
    try:
        while True:
            time.sleep(interval)
            try:
                file_size = Path(path).stat().st_size
            except OSError:
                continue

            # File rotation: if file shrunk, reset
            if file_size < end_offset:
                end_offset = HEADER_SIZE

            if file_size > end_offset:
                new_frames, end_offset = _read_frames_from(path, end_offset)
                for stored in new_frames:
                    _print_record(stored, fmt)
    except KeyboardInterrupt:
        print("\n")


# ---------------------------------------------------------------------------
# cmd_init — setup wizard
# ---------------------------------------------------------------------------


def cmd_init(agent_name: Optional[str] = None) -> None:
    """Create ahp.yaml with defaults and generate agent_id."""
    config_path = Path("ahp.yaml")
    if config_path.exists():
        print("ahp.yaml already exists. Remove it first to reinitialize.")
        sys.exit(1)

    if agent_name is None:
        # Prompt for agent name
        try:
            agent_name = input("Agent name: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nAborted.")
            sys.exit(1)

    if not agent_name:
        agent_name = "my-agent"

    agent_id = uuid7_to_str(uuid7())

    config_content = (
        f"# AHP — Agent History Protocol configuration\n"
        f"# Generated by: ahp init\n"
        f"\n"
        f'agent_name: "{agent_name}"\n'
        f"agent_id: {agent_id}\n"
        f"\n"
        f"chain:\n"
        f'  file: "{agent_name}.ahp"\n'
        f"  level: 2\n"
        f"  fsync: every\n"
        f"\n"
        f"recording:\n"
        f"  inference: true\n"
        f"  evidence: true\n"
        f"  authorization: true\n"
        f"\n"
        f"signing:\n"
        f"  enabled: false\n"
        f"  key_file: ahp-key.priv\n"
    )

    config_path.write_text(config_content, encoding="utf-8")
    print(f"Created ahp.yaml for agent: {agent_name}")
    print(f"  agent_id: {agent_id}")
    print(f"  chain file: {agent_name}.ahp")


# ---------------------------------------------------------------------------
# cmd_keygen — generate Ed25519 keypair
# ---------------------------------------------------------------------------


def cmd_keygen() -> None:
    """Generate an Ed25519 keypair for chain signing."""
    try:
        from ahp.core.signing import generate_keypair
    except ImportError:
        print("Error: ahp.core.signing module not found.")
        sys.exit(1)

    pub_path = Path("ahp-key.pub")
    priv_path = Path("ahp-key.priv")

    if pub_path.exists() or priv_path.exists():
        print("Key files already exist (ahp-key.pub / ahp-key.priv).")
        print("Remove them first to generate new keys.")
        sys.exit(1)

    kp = generate_keypair()

    pub_path.write_text(kp.public_key_bytes.hex() + "\n", encoding="utf-8")

    # Create private key with restricted permissions from the start
    fd = os.open(str(priv_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(kp.private_key_bytes.hex() + "\n")

    key_id_hex = kp.key_id.hex()
    print("Ed25519 keypair generated.")
    print("  Public key:  ahp-key.pub")
    print("  Private key: ahp-key.priv")
    print(f"  key_id:      {key_id_hex[:16]}...")


# ---------------------------------------------------------------------------
# cmd_viewer — open web viewer
# ---------------------------------------------------------------------------


def cmd_viewer(chain: Optional[str] = None, port: int = 8080) -> None:
    """Launch the AHP web viewer on localhost."""
    import subprocess

    # Find viewer/serve.py relative to the ahp package
    ahp_root = Path(__file__).parent.parent.parent
    serve_script = ahp_root / "viewer" / "serve.py"

    if not serve_script.exists():
        print("Viewer not found. Expected at: viewer/serve.py")
        sys.exit(1)

    cmd_args = [sys.executable, str(serve_script), str(port)]
    if chain:
        cmd_args.extend(["--chain", chain])

    try:
        subprocess.run(cmd_args)
    except KeyboardInterrupt:
        pass


# ---------------------------------------------------------------------------
# main — argument parser
# ---------------------------------------------------------------------------


def main() -> None:
    """CLI entry point."""
    args = sys.argv[1:]

    if not args or args[0] in ("-h", "--help", "help"):
        print("AHP \u2014 Agent History Protocol CLI\n")
        print("Commands:")
        print("  ahp log    [--chain FILE] [--last N]             Show records")
        print("             [--authorized-by ID] [--unauthorized]")
        print("  ahp show   <seq> [--chain FILE] [--tree]         Show record details")
        print("  ahp verify [--chain FILE] [--witness]            Verify chain integrity")
        print("  ahp export [--chain FILE]                        Export as JSON")
        print("  ahp trace  <session_id_prefix> [--chain FILE]    Trace session decisions")
        print("  ahp gaps   [--chain FILE]                        List gap records")
        print("  ahp tail   [--chain FILE] [--last N]             Live tail records")
        print("             [--format table|json] [--interval S]")
        print("  ahp init   [<agent_name>]                        Setup wizard")
        print("  ahp keygen                                       Generate Ed25519 keypair")
        print("  ahp viewer [--chain FILE] [PORT]                 Open web viewer")
        return

    cmd = args[0]
    chain = None  # type: Optional[str]
    last = None  # type: Optional[int]
    seq = None  # type: Optional[int]
    authorized_by = None  # type: Optional[str]
    unauthorized = False
    tree_flag = False
    witness_flag = False
    fmt_flag = "table"  # type: str
    interval_val = 0.5  # type: float
    positional = None  # type: Optional[str]

    # Parse flags
    i = 1
    while i < len(args):
        if args[i] == "--chain" and i + 1 < len(args):
            chain = args[i + 1]
            i += 2
        elif args[i] == "--last" and i + 1 < len(args):
            last = int(args[i + 1])
            i += 2
        elif args[i] == "--authorized-by" and i + 1 < len(args):
            authorized_by = args[i + 1]
            i += 2
        elif args[i] == "--unauthorized":
            unauthorized = True
            i += 1
        elif args[i] == "--tree":
            tree_flag = True
            i += 1
        elif args[i] == "--witness":
            witness_flag = True
            i += 1
        elif args[i] == "--format" and i + 1 < len(args):
            fmt_flag = args[i + 1]
            i += 2
        elif args[i] == "--interval" and i + 1 < len(args):
            interval_val = float(args[i + 1])
            i += 2
        elif args[i].startswith("--"):
            # Skip unknown flags
            i += 1
        elif args[i].isdigit():
            seq = int(args[i])
            i += 1
        else:
            # Positional argument (session prefix, agent name, etc.)
            if positional is None:
                positional = args[i]
            i += 1

    if cmd == "log":
        cmd_log(chain=chain, last=last, authorized_by=authorized_by, unauthorized=unauthorized)
    elif cmd == "show":
        if seq is None:
            print("Usage: ahp show <sequence_number> [--chain FILE] [--tree]")
            sys.exit(1)
        cmd_show(seq, chain=chain, tree=tree_flag)
    elif cmd == "verify":
        cmd_verify(chain=chain, witness=witness_flag)
    elif cmd == "export":
        cmd_export(chain=chain)
    elif cmd == "trace":
        if positional is None:
            print("Usage: ahp trace <session_id_prefix> [--chain FILE]")
            sys.exit(1)
        cmd_trace(positional, chain=chain)
    elif cmd == "gaps":
        cmd_gaps(chain=chain)
    elif cmd == "tail":
        cmd_tail(chain=chain, last=last if last is not None else 10, fmt=fmt_flag, interval=interval_val)
    elif cmd == "init":
        cmd_init(agent_name=positional)
    elif cmd == "keygen":
        cmd_keygen()
    elif cmd == "viewer":
        cmd_viewer(chain=chain, port=int(positional) if positional and positional.isdigit() else 8080)
    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)


if __name__ == "__main__":
    main()

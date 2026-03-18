"""JSONL file exporter — exports chain records as newline-delimited JSON."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional, Union
from ahp.core.chain import ChainReader
from ahp.core.json_format import record_to_json

def export_jsonl(chain_path: Union[str, Path], output_path: Union[str, Path],
                 last_n: Optional[int] = None) -> int:
    """Export chain to JSONL file. Returns number of records exported."""
    reader = ChainReader(chain_path)
    all_bytes = reader.read_all()

    if last_n:
        all_bytes = all_bytes[-last_n:]

    count = 0
    with open(output_path, 'w') as f:
        for stored in all_bytes:
            j = record_to_json(stored)
            f.write(json.dumps(j, default=str) + '\n')
            count += 1

    return count

def export_csv(chain_path: Union[str, Path], output_path: Union[str, Path]) -> int:
    """Export chain to CSV file. Returns number of records exported."""
    from ahp.core.json_format import format_action_summary

    reader = ChainReader(chain_path)
    all_bytes = reader.read_all()

    count = 0
    with open(output_path, 'w') as f:
        f.write('sequence,timestamp_ms,type,tool_name,result_status,response_time_ms,authorization\n')
        for stored in all_bytes:
            s = format_action_summary(stored)
            f.write(f"{s['sequence']},{s['timestamp_ms']},{s['type']},{s['tool_name']},"
                    f"{s['result_status']},{s['response_time_ms']},{s['authorization']}\n")
            count += 1

    return count

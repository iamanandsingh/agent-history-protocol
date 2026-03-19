"""Witness client — sends checkpoints to witness servers (Section 8)."""

from __future__ import annotations

import json
import logging
import time
from typing import Dict, Optional
from urllib.error import URLError
from urllib.request import Request, urlopen

logger = logging.getLogger("ahp.witness_client")


def send_checkpoint(
    endpoint: str,
    agent_id: str,
    chain_hash: str,
    sequence: int,
    timestamp_ms: int,
    signature: str = "",
    signing_key_id: str = "",
) -> Optional[Dict]:
    """Send a checkpoint to a witness server. Returns receipt or None on failure."""
    if (
        not endpoint.startswith("https://")
        and not endpoint.startswith("http://localhost")
        and not endpoint.startswith("http://127.0.0.1")
    ):
        raise ValueError(f"Witness endpoint must use HTTPS: {endpoint}")
    url = endpoint.rstrip("/") + "/ahp/v1/checkpoints"
    payload = json.dumps(
        {
            "agent_id": agent_id,
            "chain_hash": chain_hash,
            "sequence": sequence,
            "timestamp_ms": timestamp_ms,
            "signature": signature,
            "signing_key_id": signing_key_id,
        }
    ).encode()

    retries = 3
    delays = [1, 2, 4]  # exponential backoff per Section 8.5

    for attempt in range(retries):
        try:
            req = Request(url, data=payload, headers={"Content-Type": "application/json"})
            with urlopen(req, timeout=10) as resp:
                return json.loads(resp.read())
        except (URLError, OSError, json.JSONDecodeError) as e:
            logger.warning("Witness checkpoint attempt %d/%d failed: %s", attempt + 1, retries, e)
            if attempt < retries - 1:
                time.sleep(delays[attempt])
            else:
                return None
    return None


def get_identity(endpoint: str) -> Optional[Dict]:
    """Get witness identity (public key)."""
    if (
        not endpoint.startswith("https://")
        and not endpoint.startswith("http://localhost")
        and not endpoint.startswith("http://127.0.0.1")
    ):
        raise ValueError(f"Witness endpoint must use HTTPS: {endpoint}")
    url = endpoint.rstrip("/") + "/ahp/v1/identity"
    try:
        req = Request(url)
        with urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
    except (URLError, OSError) as e:
        logger.warning("Witness identity request failed: %s", e)
        return None

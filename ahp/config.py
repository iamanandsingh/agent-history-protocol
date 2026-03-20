"""AHP configuration — loads ahp.yaml and applies defaults + per-agent overrides.

Implements Section 10 of the AHP specification.
"""

from __future__ import annotations

import fnmatch
import json
import logging
import os
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("ahp.config")

try:
    import yaml

    HAS_YAML = True
except ImportError:
    HAS_YAML = False


@dataclass
class FilterConfig:
    name: str
    pattern: str
    replacement: str
    scope: List[str] = field(default_factory=lambda: ["parameters", "results"])


@dataclass
class WitnessConfig:
    enabled: bool = False
    interval: int = 1000
    endpoints: List[str] = field(default_factory=list)


@dataclass
class AHPConfig:
    """Complete AHP configuration per Section 10."""

    # Recording policy
    level: int = 1  # 1-3
    inference_record: bool = True
    inference_evidence: bool = True
    evidence_record: bool = True
    authorization_record: bool = False
    fsync_mode: str = "batch"  # every, batch, none
    checkpoint_interval: int = 1000

    # Witness
    witness: WitnessConfig = field(default_factory=WitnessConfig)

    # PII Filters
    filters: List[FilterConfig] = field(default_factory=list)
    filter_presets: List[str] = field(default_factory=list)

    # Agent identity
    agent_name: str = ""
    agent_framework: str = ""

    # Internals
    config_source: str = ""
    matched_agent_rule: str = ""

    def validate(self) -> List[str]:
        """Validate configuration. Returns list of errors (empty = valid)."""
        errors = []
        if self.level not in (1, 2, 3):
            errors.append(f"level must be 1, 2, or 3, got {self.level}")
        if self.level == 3 and not self.witness.enabled:
            errors.append("level=3 requires witness.enabled=true")
        if self.level == 3 and not self.witness.endpoints:
            errors.append("level=3 requires at least one witness endpoint")
        if self.fsync_mode not in ("every", "batch", "none"):
            errors.append(f"fsync_mode must be every/batch/none, got {self.fsync_mode}")
        if self.checkpoint_interval < 1:
            errors.append(f"checkpoint_interval must be >= 1, got {self.checkpoint_interval}")
        return errors


def load_config(path: Optional[str] = None, agent_name: str = "") -> AHPConfig:
    """Load AHP configuration from file or environment.

    Search order:
    1. Explicit path argument
    2. AHP_CONFIG environment variable
    3. ./ahp.yaml
    4. ~/.ahp/config.yaml
    5. Defaults
    """
    config_path = _find_config(path)

    if config_path and HAS_YAML:
        config = _load_from_yaml(config_path, agent_name)
    elif config_path and not HAS_YAML:
        # Try JSON fallback
        config = _load_from_json(config_path, agent_name)
    else:
        config = _from_env(agent_name)

    # Validate before returning — raise on invalid configs
    errors = config.validate()
    if errors:
        raise ValueError("Invalid AHP configuration:\n  - " + "\n  - ".join(errors))

    return config


def _find_config(explicit_path: Optional[str] = None) -> Optional[str]:
    """Find configuration file."""
    if explicit_path and Path(explicit_path).exists():
        return explicit_path

    env_path = os.environ.get("AHP_CONFIG")
    if env_path and Path(env_path).exists():
        return env_path

    if Path("ahp.yaml").exists():
        return "ahp.yaml"
    if Path("ahp.yml").exists():
        return "ahp.yml"
    if Path("ahp.json").exists():
        return "ahp.json"

    home_config = Path.home() / ".ahp" / "config.yaml"
    if home_config.exists():
        return str(home_config)

    return None


def _load_from_yaml(path: str, agent_name: str) -> AHPConfig:
    """Load config from YAML file."""
    with open(path, encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}

    config = _parse_raw_config(raw, agent_name)
    config.config_source = os.path.basename(path)
    return config


def _load_from_json(path: str, agent_name: str) -> AHPConfig:
    """Load config from JSON file."""
    with open(path, encoding="utf-8") as f:
        raw = json.load(f)

    config = _parse_raw_config(raw, agent_name)
    config.config_source = os.path.basename(path)
    return config


def _from_env(agent_name: str) -> AHPConfig:
    """Build config from environment variables."""
    config = AHPConfig(agent_name=agent_name, config_source="env")

    # Parse AHP_LEVEL with validation — default to 1 on bad input
    raw_level = os.environ.get("AHP_LEVEL", "1")
    try:
        config.level = int(raw_level)
    except ValueError:
        warnings.warn(
            f"AHP_LEVEL={raw_level!r} is not a valid integer, defaulting to 1",
            stacklevel=2,
        )
        logger.warning("AHP_LEVEL=%r is not a valid integer, defaulting to 1", raw_level)
        config.level = 1

    config.inference_record = os.environ.get("AHP_INFERENCE_RECORD", "true").lower() == "true"
    config.evidence_record = os.environ.get("AHP_EVIDENCE_RECORD", "true").lower() == "true"
    config.authorization_record = os.environ.get("AHP_AUTH_RECORD", "false").lower() == "true"
    config.fsync_mode = os.environ.get("AHP_FSYNC_MODE", "batch")
    return config


def _parse_raw_config(raw: Dict[str, Any], agent_name: str) -> AHPConfig:
    """Parse raw config dict (from YAML or JSON) into AHPConfig."""
    defaults = raw.get("defaults", {})

    config = AHPConfig(
        level=defaults.get("level", 1),
        inference_record=defaults.get("inference", {}).get("record", True),
        inference_evidence=defaults.get("inference", {}).get("evidence", True),
        evidence_record=defaults.get("evidence", {}).get("record", True),
        authorization_record=defaults.get("authorization", {}).get("record", False),
        fsync_mode=defaults.get("fsync_mode", "batch"),
        checkpoint_interval=defaults.get("checkpoint_interval", 1000),
        agent_name=agent_name,
    )

    # Witness config
    witness_raw = defaults.get("witness", {})
    config.witness = WitnessConfig(
        enabled=witness_raw.get("enabled", False),
        interval=witness_raw.get("interval", 1000),
        endpoints=witness_raw.get("endpoints", []),
    )

    # Global filters
    for f_raw in raw.get("filters", []):
        if "preset" in f_raw:
            config.filter_presets.append(f_raw["preset"])
        else:
            config.filters.append(
                FilterConfig(
                    name=f_raw.get("name", ""),
                    pattern=f_raw.get("pattern", ""),
                    replacement=f_raw.get("replacement", ""),
                    scope=f_raw.get("scope", ["parameters", "results"]),
                )
            )

    # Per-agent overrides (first match wins)
    for agent_rule in raw.get("agents", []):
        match_pattern = agent_rule.get("match", "")
        if fnmatch.fnmatch(agent_name, match_pattern):
            config.matched_agent_rule = match_pattern
            _apply_overrides(config, agent_rule)
            break

    return config


def _apply_overrides(config: AHPConfig, overrides: Dict[str, Any]) -> None:
    """Apply per-agent overrides to config."""
    if "level" in overrides:
        config.level = overrides["level"]
    if "inference" in overrides:
        inf = overrides["inference"]
        if "record" in inf:
            config.inference_record = inf["record"]
        if "evidence" in inf:
            config.inference_evidence = inf["evidence"]
    if "evidence" in overrides:
        if "record" in overrides["evidence"]:
            config.evidence_record = overrides["evidence"]["record"]
    if "authorization" in overrides:
        if "record" in overrides["authorization"]:
            config.authorization_record = overrides["authorization"]["record"]
    if "fsync_mode" in overrides:
        config.fsync_mode = overrides["fsync_mode"]
    if "witness" in overrides:
        w = overrides["witness"]
        if "enabled" in w:
            config.witness.enabled = w["enabled"]
        if "interval" in w:
            config.witness.interval = w["interval"]
        if "endpoints" in w:
            config.witness.endpoints = w["endpoints"]

    # Agent-level filters are APPENDED (not replaced)
    for f_raw in overrides.get("filters", []):
        config.filters.append(
            FilterConfig(
                name=f_raw.get("name", ""),
                pattern=f_raw.get("pattern", ""),
                replacement=f_raw.get("replacement", ""),
                scope=f_raw.get("scope", ["parameters", "results"]),
            )
        )

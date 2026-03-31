"""Global default recorder — shared by decorators, tracing, and adapters."""

from __future__ import annotations

from typing import Any, Optional

_default_recorder: Optional[Any] = None


def set_default_recorder(recorder: Any) -> None:
    """Set the global default recorder used by decorators and adapters.

    Args:
        recorder: An AHPRecorder or AsyncAHPRecorder instance.
    """
    global _default_recorder
    _default_recorder = recorder


def get_default_recorder() -> Optional[Any]:
    """Return the global default recorder, or None if not set."""
    return _default_recorder

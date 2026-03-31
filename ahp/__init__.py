"""Agent History Protocol — tamper-evident recording for AI agents."""

__version__ = "1.0.0"

from ahp._globals import get_default_recorder, set_default_recorder
from ahp.async_recorder import AsyncAHPRecorder
from ahp.config import AHPConfig, load_config
from ahp.core.types import ActionType, AuthorizationType, Protocol, RecordType, ResultStatus
from ahp.decorators import trace_agent, trace_llm, trace_tool
from ahp.recorder import AHPRecorder
from ahp.tracing import Session, Span, get_current_span, session

__all__ = [
    "AHPRecorder",
    "AsyncAHPRecorder",
    "AHPConfig",
    "load_config",
    "Protocol",
    "ActionType",
    "ResultStatus",
    "AuthorizationType",
    "RecordType",
    "set_default_recorder",
    "get_default_recorder",
    "trace_tool",
    "trace_llm",
    "trace_agent",
    "Session",
    "Span",
    "session",
    "get_current_span",
    "__version__",
]

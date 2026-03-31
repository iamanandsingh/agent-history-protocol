"""Session/Span context managers — auto-manage parent_action_id for causal trees.

Usage:
    import ahp

    ahp.set_default_recorder(recorder)

    with ahp.session("research-task") as s:
        with s.span("coordinator") as coord:
            coord.log_llm(tool_name="gpt-4o", model_id="gpt-4o")

            with coord.child_span("researcher") as researcher:
                researcher.log_tool(tool_name="search", parameters=b'...')
                researcher.log_tool(tool_name="fetch", parameters=b'...')

            coord.log_tool(tool_name="summarize")
"""

from __future__ import annotations

import contextvars
import inspect
from typing import Any, Optional

from ahp._globals import get_default_recorder
from ahp.core.types import ZERO_UUID, ActionType

_current_span: contextvars.ContextVar[Optional[Span]] = contextvars.ContextVar("ahp_current_span", default=None)


class Session:
    """Named session context. Holds a recorder reference.

    Use as a context manager::

        with ahp.session("my-task") as s:
            with s.span("agent") as agent:
                agent.log_tool(...)
    """

    def __init__(self, name: str, recorder: Optional[Any] = None) -> None:
        self.name = name
        self._recorder = recorder

    def _get_recorder(self) -> Optional[Any]:
        return self._recorder or get_default_recorder()

    def span(self, name: str) -> "Span":
        """Create a root span within this session."""
        return Span(name, session=self, parent_span=None)

    def __enter__(self) -> "Session":
        return self

    def __exit__(self, *args: Any) -> None:
        pass

    async def __aenter__(self) -> "Session":
        return self

    async def __aexit__(self, *args: Any) -> None:
        pass


class Span:
    """Named span that auto-manages parent_action_id.

    The first action recorded in a span sets the span's ``record_id``.
    Child spans use their parent span's ``record_id`` as ``parent_action_id``,
    building the causal tree that ``ahp trace`` reconstructs.
    """

    def __init__(
        self,
        name: str,
        session: Session,
        parent_span: Optional["Span"] = None,
    ) -> None:
        self.name = name
        self._session = session
        self._parent_span = parent_span
        self._record_id: Optional[bytes] = None
        self._prev_token: Optional[contextvars.Token] = None

    @property
    def _parent_action_id(self) -> bytes:
        """Parent span's record_id, or ZERO_UUID if root span."""
        if self._parent_span is not None and self._parent_span._record_id is not None:
            return self._parent_span._record_id
        return ZERO_UUID

    def _record(self, **kwargs: Any) -> Any:
        """Record an action via the session's recorder (sync, fail-open)."""
        rec = self._session._get_recorder()
        if rec is None:
            return None
        kwargs.setdefault("parent_action_id", self._parent_action_id)
        try:
            result = rec.safe_record(**kwargs)
            if result is not None and self._record_id is None:
                self._record_id = result.record_id
            return result
        except Exception:
            return None

    async def _async_record(self, **kwargs: Any) -> Any:
        """Record an action via the session's recorder (async-aware, fail-open)."""
        rec = self._session._get_recorder()
        if rec is None:
            return None
        kwargs.setdefault("parent_action_id", self._parent_action_id)
        try:
            result = rec.safe_record(**kwargs)
            if inspect.isawaitable(result):
                result = await result
            if result is not None and self._record_id is None:
                self._record_id = result.record_id
            return result
        except Exception:
            return None

    def log_tool(self, tool_name: str, **kwargs: Any) -> Any:
        """Record a TOOL_CALL action in this span."""
        return self._record(tool_name=tool_name, action_type=ActionType.TOOL_CALL, **kwargs)

    def log_llm(self, tool_name: str, **kwargs: Any) -> Any:
        """Record an INFERENCE action in this span."""
        return self._record(tool_name=tool_name, action_type=ActionType.INFERENCE, **kwargs)

    def log_action(self, **kwargs: Any) -> Any:
        """Record a generic action in this span."""
        return self._record(**kwargs)

    def child_span(self, name: str) -> "Span":
        """Create a child span nested under this one."""
        return Span(name, session=self._session, parent_span=self)

    def __enter__(self) -> "Span":
        self._prev_token = _current_span.set(self)
        return self

    def __exit__(self, *args: Any) -> None:
        if self._prev_token is not None:
            _current_span.reset(self._prev_token)

    async def __aenter__(self) -> "Span":
        self._prev_token = _current_span.set(self)
        return self

    async def __aexit__(self, *args: Any) -> None:
        if self._prev_token is not None:
            _current_span.reset(self._prev_token)


def session(name: str, recorder: Optional[Any] = None) -> Session:
    """Create a named session context.

    Convenience function equivalent to ``Session(name, recorder)``.
    """
    return Session(name, recorder)


def get_current_span() -> Optional[Span]:
    """Return the current active span, or None."""
    return _current_span.get()

"""Base interceptor interface for all protocol interceptors."""
from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Optional, Any
from ahp.core.records import ActionPayload

class BaseInterceptor(ABC):
    """Abstract base for protocol interceptors.

    All interceptors must implement create_action() which converts
    protocol-specific call data into an AHP ActionPayload.
    """

    @abstractmethod
    def create_action(self, **kwargs: Any) -> ActionPayload:
        """Create an ActionPayload from intercepted call data."""
        ...

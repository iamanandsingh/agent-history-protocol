"""Real tools for the showcase demo — actual file I/O, search, data operations."""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Optional, Any, Dict, List
from ahp.core.types import ResultStatus, Protocol, ActionType, AuthorizationType, AuthorizationDecision, AuthorizerType
from ahp.core.records import ActionPayload, Authorization, AuthorizationEntry
from ahp.core.chain import ChainWriter
from ahp.core.uuid7 import uuid7
from ahp.interceptors.mcp_helper import create_action_from_mcp


class ToolExecutor:
    """Executes real tools and records them in AHP."""

    def __init__(self, writer: ChainWriter, session_id: Optional[bytes] = None,
                 parent_record_id: Optional[bytes] = None):
        self.writer = writer
        self.session_id = session_id or uuid7()
        self.parent_record_id = parent_record_id

    def set_parent(self, record_id: bytes) -> None:
        self.parent_record_id = record_id

    def run(self, tool_name: str, params: dict,
            authorization: Optional[Authorization] = None) -> Any:
        """Execute a tool and record it in AHP. Returns the tool result."""
        func = TOOL_REGISTRY.get(tool_name)
        if not func:
            return self._record_error(tool_name, params, f"Tool '{tool_name}' not found", authorization)

        start = time.time()
        try:
            result = func(**params)
            success = True
        except Exception as e:
            result = {"error": str(e), "type": type(e).__name__}
            success = False

        duration_ms = int((time.time() - start) * 1000)

        action = create_action_from_mcp(
            tool_name=tool_name,
            parameters=params,
            result=result,
            duration_ms=duration_ms,
            success=success,
        )

        if self.parent_record_id:
            action.parent_action_id = self.parent_record_id
        if authorization:
            action.authorization = authorization

        self.writer.write_record(action, session_id=self.session_id)
        return result

    def _record_error(self, tool_name: str, params: dict, error: str,
                      authorization: Optional[Authorization] = None) -> dict:
        action = create_action_from_mcp(
            tool_name=tool_name,
            parameters=params,
            result={"error": error},
            duration_ms=0,
            success=False,
        )
        if self.parent_record_id:
            action.parent_action_id = self.parent_record_id
        if authorization:
            action.authorization = authorization
        self.writer.write_record(action, session_id=self.session_id)
        return {"error": error}


# ================================================================
# Real Tool Implementations
# ================================================================

def search_orders(customer_id: int, data_dir: str = "demo/showcase/sandbox_data") -> Dict:
    """Search customer orders in the sandbox database."""
    orders_file = Path(data_dir) / "orders.json"
    if not orders_file.exists():
        return {"error": "Orders database not found", "matches": []}
    orders = json.loads(orders_file.read_text())
    matches = [o for o in orders if o.get("customer_id") == customer_id]
    return {"customer_id": customer_id, "matches": matches, "count": len(matches)}


def search_docs(query: str, data_dir: str = "demo/showcase/sandbox_data") -> Dict:
    """Search support documentation."""
    docs_file = Path(data_dir) / "support_docs.json"
    if not docs_file.exists():
        return {"error": "Docs not found", "matches": []}
    docs = json.loads(docs_file.read_text())
    matches = []
    for doc in docs:
        if query.lower() in doc.get("title", "").lower() or query.lower() in doc.get("content", "").lower():
            matches.append(doc)
    return {"query": query, "matches": matches, "count": len(matches)}


def get_customer(customer_id: int, data_dir: str = "demo/showcase/sandbox_data") -> Dict:
    """Get customer details."""
    customers_file = Path(data_dir) / "customers.json"
    if not customers_file.exists():
        return {"error": "Customer database not found"}
    customers = json.loads(customers_file.read_text())
    for c in customers:
        if c.get("id") == customer_id:
            return c
    return {"error": f"Customer {customer_id} not found"}


def process_refund(order_id: int, amount: float,
                   data_dir: str = "demo/showcase/sandbox_data") -> Dict:
    """Process a refund — writes to the refund log."""
    refund_log = Path(data_dir) / "refund_log.json"
    refunds = json.loads(refund_log.read_text()) if refund_log.exists() else []
    refund = {
        "refund_id": f"RF-{int(time.time())}",
        "order_id": order_id,
        "amount": amount,
        "status": "processed",
        "timestamp": int(time.time() * 1000),
    }
    refunds.append(refund)
    refund_log.write_text(json.dumps(refunds, indent=2))
    return refund


def delete_account(user_id: int,
                   data_dir: str = "demo/showcase/sandbox_data") -> Dict:
    """Delete a user account — writes deletion record."""
    deletion_log = Path(data_dir) / "deletion_log.json"
    deletions = json.loads(deletion_log.read_text()) if deletion_log.exists() else []
    record = {
        "user_id": user_id,
        "status": "deleted",
        "gdpr_compliant": True,
        "timestamp": int(time.time() * 1000),
    }
    deletions.append(record)
    deletion_log.write_text(json.dumps(deletions, indent=2))
    return record


def send_reply(customer_id: int, message: str,
               data_dir: str = "demo/showcase/sandbox_data") -> Dict:
    """Send a reply to a customer — writes to message log."""
    msg_log = Path(data_dir) / "messages.json"
    messages = json.loads(msg_log.read_text()) if msg_log.exists() else []
    msg = {
        "customer_id": customer_id,
        "message": message,
        "timestamp": int(time.time() * 1000),
    }
    messages.append(msg)
    msg_log.write_text(json.dumps(messages, indent=2))
    return {"status": "sent", "customer_id": customer_id}


# Tool registry
TOOL_REGISTRY = {
    "search_orders": search_orders,
    "search_docs": search_docs,
    "get_customer": get_customer,
    "process_refund": process_refund,
    "delete_account": delete_account,
    "send_reply": send_reply,
}

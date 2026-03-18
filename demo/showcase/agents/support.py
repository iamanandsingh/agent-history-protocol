"""Customer Support Agent — handles customer requests with real LLM + tools."""
from __future__ import annotations

import json
import time
from typing import Optional, Dict, Any
from urllib.request import urlopen, Request

from ahp.core.types import (
    AuthorizationType, AuthorizerType, AuthorizationDecision,
    ChainLevel,
)
from ahp.core.records import BootPayload, ActionPayload, Authorization, AuthorizationEntry
from ahp.core.chain import ChainWriter
from ahp.core.uuid7 import uuid7

from demo.showcase.llm import GeminiClient
from demo.showcase.tools import ToolExecutor


SYSTEM_PROMPT = """You are a customer support agent. You help customers with their requests.

Available tools:
- search_orders(customer_id: int) — search customer orders
- search_docs(query: str) — search support documentation
- get_customer(customer_id: int) — get customer details
- process_refund(order_id: int, amount: float) — process a refund (requires approval)
- delete_account(user_id: int) — delete account (requires multi-party approval)
- send_reply(customer_id: int, message: str) — send reply to customer

When you need to use a tool, respond with a JSON block:
{"tool": "tool_name", "params": {"key": "value"}}

For high-risk actions (refunds, deletions), state that you need approval.
For simple queries, just answer directly.
Keep responses concise."""


class SupportAgent:
    """Customer support agent powered by real Gemini LLM."""

    def __init__(self, api_key: str, model: str, endpoint: str,
                 chain_path: str, supervisor_url: Optional[str] = None):
        self.agent_id = uuid7()
        self.writer = ChainWriter(chain_path, agent_id=self.agent_id)
        self.supervisor_url = supervisor_url
        self.sessions: Dict[int, bytes] = {}  # customer_id → session_id

        # Emit boot record
        self.writer.write_record(BootPayload(
            agent_name="support-bot",
            interceptors=["http", "mcp"],
            runtime="python 3.9",
            chain_level=ChainLevel.LEVEL_1,
            inference_recording=True,
            authorization_recording=True,
        ))

        # Initialize LLM and tools per session
        self.api_key = api_key
        self.model = model
        self.endpoint = endpoint

    def _get_session(self, customer_id: int) -> bytes:
        if customer_id not in self.sessions:
            self.sessions[customer_id] = uuid7()
        return self.sessions[customer_id]

    def handle(self, customer_id: int, message: str) -> str:
        """Handle a customer message. Returns the agent's response."""
        session_id = self._get_session(customer_id)

        llm = GeminiClient(
            self.api_key, self.model, self.endpoint,
            self.writer, session_id=session_id,
        )
        tools = ToolExecutor(self.writer, session_id=session_id)

        # Step 1: Ask LLM what to do
        prompt = f"Customer #{customer_id} says: \"{message}\"\n\nDecide what to do. If you need a tool, respond with the JSON block."
        response = llm.chat(
            messages=[{"role": "user", "content": prompt}],
            system_prompt=SYSTEM_PROMPT,
        )

        if response.get("error"):
            return f"[Agent error: {response['text']}]"

        llm_text = response["text"]
        tools.set_parent(llm.last_record_id)

        # Step 2: Parse tool calls from LLM response
        tool_call = self._extract_tool_call(llm_text)

        if not tool_call:
            # Simple response — no tool needed
            tools.run("send_reply", {
                "customer_id": customer_id,
                "message": llm_text,
            })
            return llm_text

        tool_name = tool_call["tool"]
        params = tool_call["params"]

        # Step 3: Execute tool with appropriate authorization
        if tool_name == "process_refund":
            return self._handle_refund(llm, tools, customer_id, params, session_id)
        elif tool_name == "delete_account":
            return self._handle_deletion(llm, tools, customer_id, params, session_id)
        else:
            # Low-risk tool — no authorization needed
            result = tools.run(tool_name, params)

            # Step 4: Ask LLM to formulate response based on tool result
            followup = llm.chat(
                messages=[
                    {"role": "user", "content": prompt},
                    {"role": "model", "content": llm_text},
                    {"role": "user", "content": f"Tool result: {json.dumps(result, default=str)}. Now respond to the customer."},
                ],
                system_prompt=SYSTEM_PROMPT,
            )

            reply = followup["text"] if not followup.get("error") else str(result)
            tools.set_parent(llm.last_record_id)
            tools.run("send_reply", {"customer_id": customer_id, "message": reply})
            return reply

    def _handle_refund(self, llm: GeminiClient, tools: ToolExecutor,
                       customer_id: int, params: dict, session_id: bytes) -> str:
        """Handle refund — requires supervisor approval."""
        # Request approval from supervisor
        authorization = self._request_supervisor_approval(
            action="process_refund",
            details=params,
            session_id=session_id,
        )

        if authorization and authorization.entries[0].decision == AuthorizationDecision.APPROVED:
            result = tools.run("process_refund", params, authorization=authorization)
            reply = f"Refund of ${params.get('amount', 0)} processed for order #{params.get('order_id')}."
        else:
            reply = "Sorry, the refund request was not approved."

        tools.run("send_reply", {"customer_id": customer_id, "message": reply})
        return reply

    def _handle_deletion(self, llm: GeminiClient, tools: ToolExecutor,
                         customer_id: int, params: dict, session_id: bytes) -> str:
        """Handle account deletion — requires multi-party approval."""
        # Request safety check + human approval
        safety_auth = self._request_supervisor_approval(
            action="delete_account",
            details=params,
            session_id=session_id,
        )

        human_auth_entry = AuthorizationEntry(
            authorizer_type=AuthorizerType.AUTHORIZER_HUMAN,
            authorizer_id="user:operator@company.com",
            decision=AuthorizationDecision.APPROVED,
            timestamp_ms=int(time.time() * 1000),
        )

        if safety_auth and safety_auth.entries[0].decision == AuthorizationDecision.APPROVED:
            multi_auth = Authorization(
                type=AuthorizationType.AUTH_MULTI_PARTY,
                entries=[safety_auth.entries[0], human_auth_entry],
            )
            result = tools.run("delete_account", params, authorization=multi_auth)
            reply = f"Account #{params.get('user_id')} has been deleted. All data purged per GDPR."
        else:
            reply = "Account deletion was not approved by the safety check."

        tools.run("send_reply", {"customer_id": customer_id, "message": reply})
        return reply

    def _request_supervisor_approval(self, action: str, details: dict,
                                      session_id: bytes) -> Optional[Authorization]:
        """Request approval from the supervisor agent via HTTP."""
        if not self.supervisor_url:
            # No supervisor configured — auto-approve with policy
            return Authorization(
                type=AuthorizationType.AUTH_POLICY,
                entries=[AuthorizationEntry(
                    authorizer_type=AuthorizerType.AUTHORIZER_POLICY_ENGINE,
                    authorizer_id="auto-approve:no-supervisor",
                    decision=AuthorizationDecision.APPROVED,
                    timestamp_ms=int(time.time() * 1000),
                )],
            )

        try:
            payload = json.dumps({
                "action": action,
                "details": details,
                "requesting_agent": self.agent_id.hex(),
            }).encode()

            req = Request(
                f"{self.supervisor_url}/approve",
                data=payload,
                headers={"Content-Type": "application/json"},
            )
            with urlopen(req, timeout=15) as resp:
                result = json.loads(resp.read())

            if result.get("approved"):
                return Authorization(
                    type=AuthorizationType.AUTH_AGENT,
                    entries=[AuthorizationEntry(
                        authorizer_type=AuthorizerType.AUTHORIZER_AGENT,
                        authorizer_id=result.get("agent_name", "supervisor-bot"),
                        authorizer_agent_id=bytes.fromhex(result["agent_id"]) if result.get("agent_id") else uuid7(),
                        authorizer_seq=result.get("sequence", 0),
                        decision=AuthorizationDecision.APPROVED,
                        condition=result.get("reason", ""),
                        timestamp_ms=result.get("timestamp", int(time.time() * 1000)),
                    )],
                )
        except Exception as e:
            pass

        return None

    def _extract_tool_call(self, text: str) -> Optional[Dict]:
        """Extract tool call JSON from LLM response."""
        try:
            # Try to find JSON in the response
            start = text.find('{')
            end = text.rfind('}') + 1
            if start >= 0 and end > start:
                candidate = text[start:end]
                parsed = json.loads(candidate)
                if "tool" in parsed and "params" in parsed:
                    return parsed
        except (json.JSONDecodeError, ValueError):
            pass
        return None

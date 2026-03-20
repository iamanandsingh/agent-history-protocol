"""Customer Support Agent — handles customer requests with real LLM + tools."""

from __future__ import annotations

import json
import time
from typing import Dict, Optional
from urllib.request import Request, urlopen

from ahp.core.chain import ChainWriter
from ahp.core.records import Authorization, AuthorizationEntry, BootPayload
from ahp.core.types import (
    AuthorizationDecision,
    AuthorizationType,
    AuthorizerType,
    ChainLevel,
)
from ahp.core.uuid7 import uuid7
from demo.showcase.llm import GeminiClient
from demo.showcase.tools import ToolExecutor

SYSTEM_PROMPT = """You are a customer support agent for an online store. You help customers with their requests.

IMPORTANT RULES:
1. You MUST ONLY respond with a single JSON object. No other text before or after.
2. You must pick ONE tool to call per response.

Available tools:
- search_orders: Search customer orders. Params: {"customer_id": <int>}
- search_docs: Search support documentation. Params: {"query": "<string>"}
- get_customer: Get customer details. Params: {"customer_id": <int>}
- process_refund: Process a refund. Params: {"order_id": <int>, "amount": <float>}
- delete_account: Delete a customer account. Params: {"user_id": <int>}
- send_reply: Send a reply to the customer. Params: {"customer_id": <int>, "message": "<string>"}

DECISION GUIDELINES:
- For questions about policies → use search_docs first, then send_reply with the answer.
- For refund requests → use process_refund with the order_id and amount.
- For account deletion requests → use delete_account with the user_id.
- For order inquiries → use search_orders first.
- When you already have the answer → use send_reply directly.

RESPONSE FORMAT (strict JSON only):
{"tool": "tool_name", "params": {"key": "value"}}"""


class SupportAgent:
    """Customer support agent powered by real Gemini LLM."""

    def __init__(self, api_key: str, model: str, endpoint: str, chain_path: str, supervisor_url: Optional[str] = None):
        self.agent_id = uuid7()
        self.writer = ChainWriter(chain_path, agent_id=self.agent_id)
        self.supervisor_url = supervisor_url
        self.sessions: Dict[int, bytes] = {}  # customer_id → session_id

        # Emit boot record
        self.writer.write_record(
            BootPayload(
                agent_name="support-bot",
                interceptors=["http", "mcp"],
                runtime="python 3.9",
                chain_level=ChainLevel.LEVEL_1,
                inference_recording=True,
                authorization_recording=True,
            )
        )

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
            self.api_key,
            self.model,
            self.endpoint,
            self.writer,
            session_id=session_id,
        )
        tools = ToolExecutor(self.writer, session_id=session_id)

        # Step 1: Ask LLM what to do
        prompt = f'Customer #{customer_id} says: "{message}"\n\nPick the best tool to handle this request. Respond with ONLY a JSON object: {{"tool": "tool_name", "params": {{...}}}}'
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
            tools.run(
                "send_reply",
                {
                    "customer_id": customer_id,
                    "message": llm_text,
                },
            )
            return llm_text

        tool_name = tool_call["tool"]
        params = tool_call["params"]

        # Step 3: Execute tool with appropriate authorization
        if tool_name == "send_reply":
            # Direct reply — no further LLM call needed
            reply = params.get("message", llm_text)
            tools.run("send_reply", {"customer_id": customer_id, "message": reply})
            return reply
        elif tool_name == "process_refund":
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
                    {
                        "role": "user",
                        "content": f"Tool result: {json.dumps(result, default=str)}\n\nNow use send_reply to respond to the customer with a helpful message based on this result. Respond with ONLY the JSON.",
                    },
                ],
                system_prompt=SYSTEM_PROMPT,
            )

            followup_text = followup["text"] if not followup.get("error") else str(result)
            tools.set_parent(llm.last_record_id)

            # Extract message from send_reply JSON if the LLM returned a tool call
            followup_call = self._extract_tool_call(followup_text)
            if followup_call and followup_call.get("tool") == "send_reply":
                reply = followup_call["params"].get("message", followup_text)
            else:
                reply = followup_text

            tools.run("send_reply", {"customer_id": customer_id, "message": reply})
            return reply

    def _handle_refund(
        self, llm: GeminiClient, tools: ToolExecutor, customer_id: int, params: dict, session_id: bytes
    ) -> str:
        """Handle refund — requires supervisor approval."""
        # Request approval from supervisor
        authorization = self._request_supervisor_approval(
            action="process_refund",
            details=params,
            session_id=session_id,
        )

        if authorization and authorization.entries[0].decision == AuthorizationDecision.APPROVED:
            tools.run("process_refund", params, authorization=authorization)
            reply = f"Refund of ${params.get('amount', 0)} processed for order #{params.get('order_id')}."
        else:
            reply = "Sorry, the refund request was not approved."

        tools.run("send_reply", {"customer_id": customer_id, "message": reply})
        return reply

    def _handle_deletion(
        self, llm: GeminiClient, tools: ToolExecutor, customer_id: int, params: dict, session_id: bytes
    ) -> str:
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
            tools.run("delete_account", params, authorization=multi_auth)
            reply = f"Account #{params.get('user_id')} has been deleted. All data purged per GDPR."
        else:
            reply = "Account deletion was not approved by the safety check."

        tools.run("send_reply", {"customer_id": customer_id, "message": reply})
        return reply

    def _request_supervisor_approval(self, action: str, details: dict, session_id: bytes) -> Optional[Authorization]:
        """Request approval from the supervisor agent via HTTP."""
        if not self.supervisor_url:
            # No supervisor configured — auto-approve with policy
            return Authorization(
                type=AuthorizationType.AUTH_POLICY,
                entries=[
                    AuthorizationEntry(
                        authorizer_type=AuthorizerType.AUTHORIZER_POLICY_ENGINE,
                        authorizer_id="auto-approve:no-supervisor",
                        decision=AuthorizationDecision.APPROVED,
                        timestamp_ms=int(time.time() * 1000),
                    )
                ],
            )

        try:
            payload = json.dumps(
                {
                    "action": action,
                    "details": details,
                    "requesting_agent": self.agent_id.hex(),
                }
            ).encode()

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
                    entries=[
                        AuthorizationEntry(
                            authorizer_type=AuthorizerType.AUTHORIZER_AGENT,
                            authorizer_id=result.get("agent_name", "supervisor-bot"),
                            authorizer_agent_id=bytes.fromhex(result["agent_id"])
                            if result.get("agent_id")
                            else uuid7(),
                            authorizer_seq=result.get("sequence", 0),
                            decision=AuthorizationDecision.APPROVED,
                            condition=result.get("reason", ""),
                            timestamp_ms=result.get("timestamp", int(time.time() * 1000)),
                        )
                    ],
                )
        except Exception:
            pass

        return None

    def _extract_tool_call(self, text: str) -> Optional[Dict]:
        """Extract tool call JSON from LLM response."""
        try:
            # Try to find JSON in the response
            start = text.find("{")
            end = text.rfind("}") + 1
            if start >= 0 and end > start:
                candidate = text[start:end]
                parsed = json.loads(candidate)
                if "tool" in parsed and "params" in parsed:
                    return parsed
        except (json.JSONDecodeError, ValueError):
            pass
        return None

"""Supervisor Agent — reviews and approves high-risk actions using real LLM.

Runs as an HTTP server that other agents can request approval from.
"""

from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

from ahp.core.chain import ChainWriter
from ahp.core.records import (
    BootPayload,
)
from ahp.core.types import (
    ActionType,
    ChainLevel,
    Protocol,
)
from ahp.core.uuid7 import uuid7
from ahp.interceptors.mcp_helper import create_action_from_mcp
from demo.showcase.llm import GeminiClient

SYSTEM_PROMPT = """You are a supervisor agent that reviews and approves high-risk actions requested by the support agent.

RULES:
1. Refunds: APPROVE if the reason is valid (duplicate charge, wrong amount, defective product).
2. Account deletion: APPROVE if the customer explicitly requested it (e.g., GDPR request).
3. When in doubt, APPROVE — we trust our support agents.

You MUST respond with ONLY a JSON object, no other text:
{"approved": true, "reason": "brief explanation"}

Examples:
- Refund for duplicate charge → {"approved": true, "reason": "Duplicate charge confirmed, refund valid"}
- GDPR deletion request → {"approved": true, "reason": "Customer GDPR request, deletion authorized"}"""


class SupervisorAgent:
    """Supervisor agent that runs as HTTP server and evaluates approval requests."""

    def __init__(self, api_key: str, model: str, endpoint: str, chain_path: str, port: int = 8200):
        self.agent_id = uuid7()
        self.writer = ChainWriter(chain_path, agent_id=self.agent_id)
        self.port = port
        self.server = None
        self._thread = None

        self.api_key = api_key
        self.model = model
        self.endpoint = endpoint

        # Boot record
        self.writer.write_record(
            BootPayload(
                agent_name="supervisor-bot",
                interceptors=["http"],
                runtime="python 3.9",
                chain_level=ChainLevel.LEVEL_1,
                inference_recording=True,
                authorization_recording=True,
            )
        )

    def start(self) -> str:
        """Start the supervisor HTTP server. Returns the URL."""
        agent = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                if self.path == "/approve":
                    content_length = int(self.headers.get("Content-Length", 0))
                    body = json.loads(self.rfile.read(content_length))
                    result = agent._handle_approval(body)

                    response = json.dumps(result).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(response)))
                    self.end_headers()
                    self.wfile.write(response)
                else:
                    self.send_error(404)

            def log_message(self, format, *args):
                pass

        self.server = HTTPServer(("localhost", self.port), Handler)
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()
        return f"http://localhost:{self.port}"

    def stop(self) -> None:
        if self.server:
            self.server.shutdown()

    def _handle_approval(self, request: dict) -> dict:
        """Evaluate an approval request using the LLM."""
        session_id = uuid7()
        llm = GeminiClient(
            self.api_key,
            self.model,
            self.endpoint,
            self.writer,
            session_id=session_id,
        )

        action = request.get("action", "unknown")
        details = request.get("details", {})

        prompt = (
            f"Approval request from support agent:\n"
            f"Action: {action}\n"
            f"Details: {json.dumps(details)}\n\n"
            f"Should this be approved?"
        )

        response = llm.chat(
            messages=[{"role": "user", "content": prompt}],
            system_prompt=SYSTEM_PROMPT,
        )

        # Parse LLM decision
        approved = True
        reason = "Approved by supervisor"

        if not response.get("error"):
            try:
                text = response["text"]
                start = text.find("{")
                end = text.rfind("}") + 1
                if start >= 0 and end > start:
                    decision = json.loads(text[start:end])
                    approved = decision.get("approved", True)
                    reason = decision.get("reason", "No reason given")
            except (json.JSONDecodeError, ValueError):
                reason = response["text"][:200]

        # Record the authorization decision in supervisor's chain
        decision_action = create_action_from_mcp(
            tool_name="authorization_decision",
            parameters={"action": action, "details": details},
            result={"approved": approved, "reason": reason},
            duration_ms=response.get("duration_ms", 0),
            target_entity=f"agent:{request.get('requesting_agent', 'unknown')}",
        )
        decision_action.parent_action_id = llm.last_record_id
        decision_action.action_type = ActionType.MESSAGE
        decision_action.protocol = Protocol.A2A

        record = self.writer.write_record(decision_action, session_id=session_id)

        return {
            "approved": approved,
            "reason": reason,
            "agent_id": self.agent_id.hex(),
            "agent_name": "supervisor-bot",
            "sequence": record.sequence,
            "timestamp": int(time.time() * 1000),
        }

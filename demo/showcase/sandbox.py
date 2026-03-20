"""Sandbox environment — creates realistic test data for the demo."""

from __future__ import annotations

import json
from pathlib import Path


def create_sandbox(data_dir: str = "demo/showcase/sandbox_data") -> None:
    """Create the sandbox with realistic customer/order/docs data."""
    d = Path(data_dir)
    d.mkdir(parents=True, exist_ok=True)

    # Customers
    customers = [
        {"id": 442, "name": "Sarah Chen", "email": "sarah@example.com", "status": "active", "since": "2024-03-15"},
        {"id": 589, "name": "Marcus Johnson", "email": "marcus@example.com", "status": "active", "since": "2025-01-20"},
        {"id": 103, "name": "Emma Wilson", "email": "emma@example.com", "status": "active", "since": "2023-11-08"},
    ]
    (d / "customers.json").write_text(json.dumps(customers, indent=2))

    # Orders — customer 442 has a duplicate charge
    orders = [
        {
            "order_id": 7891,
            "customer_id": 442,
            "amount": 49.99,
            "status": "charged",
            "date": "2026-03-15",
            "item": "Premium Plan (Monthly)",
        },
        {
            "order_id": 7891,
            "customer_id": 442,
            "amount": 49.99,
            "status": "charged",
            "date": "2026-03-15",
            "item": "Premium Plan (Monthly) — DUPLICATE",
        },
        {
            "order_id": 8234,
            "customer_id": 589,
            "amount": 29.99,
            "status": "charged",
            "date": "2026-03-14",
            "item": "Basic Plan (Monthly)",
        },
        {
            "order_id": 8567,
            "customer_id": 103,
            "amount": 99.99,
            "status": "charged",
            "date": "2026-03-10",
            "item": "Enterprise Plan (Monthly)",
        },
        {
            "order_id": 8012,
            "customer_id": 442,
            "amount": 15.00,
            "status": "charged",
            "date": "2026-02-28",
            "item": "Add-on: Extra Storage",
        },
    ]
    (d / "orders.json").write_text(json.dumps(orders, indent=2))

    # Support documentation
    docs = [
        {
            "title": "Return and Refund Policy",
            "content": "Customers may request a refund within 30 days of purchase. Duplicate charges are eligible for immediate refund. All refunds require supervisor approval for amounts over $25.",
        },
        {
            "title": "Account Deletion Process",
            "content": "Account deletion is permanent and irreversible. It requires multi-party approval: a safety check by the automated system AND human operator confirmation. All customer data will be purged in compliance with GDPR.",
        },
        {
            "title": "Escalation Procedures",
            "content": "High-risk actions (refunds over $100, account deletions, data exports) must be escalated to a supervisor agent. The supervisor evaluates the request against company policy before approving or rejecting.",
        },
    ]
    (d / "support_docs.json").write_text(json.dumps(docs, indent=2))

    # Clean logs
    for log_file in ["refund_log.json", "deletion_log.json", "messages.json"]:
        (d / log_file).write_text("[]")


def cleanup_chains(chain_dir: str = "chains") -> None:
    """Remove existing chain files."""
    d = Path(chain_dir)
    if d.exists():
        for f in d.glob("*.ahp"):
            f.unlink()
        evidence = d / "evidence"
        if evidence.exists():
            for f in evidence.iterdir():
                f.unlink()
    d.mkdir(parents=True, exist_ok=True)
    (d / "evidence").mkdir(exist_ok=True)

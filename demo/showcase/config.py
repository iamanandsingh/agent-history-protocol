"""Showcase demo configuration.

Set your Gemini API key here or via environment variable GEMINI_API_KEY.
"""
from __future__ import annotations
import os

# Gemini API configuration
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
GEMINI_MODEL = "gemini-2.0-flash"
GEMINI_ENDPOINT = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent"

# Agent names
SUPPORT_AGENT = "support-bot"
SUPERVISOR_AGENT = "supervisor-bot"
SAFETY_AGENT = "safety-checker"

# Chain files
SUPPORT_CHAIN = "chains/support-bot.ahp"
SUPERVISOR_CHAIN = "chains/supervisor-bot.ahp"
SAFETY_CHAIN = "chains/safety-checker.ahp"

# Evidence
EVIDENCE_DIR = "chains/evidence"

# Sandbox data
SANDBOX_DIR = "demo/showcase/sandbox_data"

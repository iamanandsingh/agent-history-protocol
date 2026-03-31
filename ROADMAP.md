# AHP Roadmap

Prioritized list of features. Shipped items marked DONE.

## Priority 1: Decorator-Based Instrumentation -- DONE

**Shipped in v0.2.0.** `@ahp.trace_tool`, `@ahp.trace_agent`, `@ahp.trace_llm` decorators. Sync + async, bare and parameterized, fail-open. Global default recorder via `set_default_recorder()`.

## Priority 2: Live Tail (`ahp tail`) -- DONE

**Shipped in v0.2.0.** `ahp tail [--chain FILE] [--last N] [--format table|json] [--interval S]`. File-watching via polling. Handles partial writes, file rotation, Ctrl+C.

## Priority 3: Token Caching, Cost, Reasoning, and Provider Fields -- DONE

**Shipped.** Five new fields added to `ActionPayload`:

| Field | Type | Description |
|-------|------|-------------|
| `cache_read_tokens` | uint32 | Prompt tokens served from cache (OpenAI, Anthropic, Gemini, Fireworks, DeepSeek) |
| `cache_creation_tokens` | uint32 | Prompt tokens written to cache (Anthropic) |
| `reasoning_tokens` | uint32 | Internal thinking/reasoning tokens (OpenAI o-series, Gemini, DeepSeek-R1) |
| `cost_nano_usd` | uint64 | Pre-calculated cost in nano USD ($0.008 = 8,000,000). Auto-estimated from configurable pricing table |
| `provider` | string | LLM provider, auto-detected from URL. 13 providers supported + custom via config |

Also shipped:
- Configurable pricing table (`ahp.yaml` `pricing` section) with built-in defaults for 30+ models
- Configurable provider URL patterns (`ahp.yaml` `providers` section) for custom LLM endpoints
- Thread-safe pricing with uint64 overflow protection
- `Optional[int] = None` for cost — distinguishes "not provided" (auto-estimate) from "explicitly free" (0)
- Validation bounds checks (uint32/uint64 max) on all new fields

## Priority 4: Session/Span Context Managers

**Gap:** `context.py` handles propagation, but there's no ergonomic API for creating nested spans. Users must manually thread `parent_action_id`.

**Deliverable:** Context managers that auto-manage trace/span IDs and parent-child relationships.

```python
with ahp.session("research-task") as session:
    with session.span("coordinator") as agent:
        agent.log_llm(...)
        with agent.child_span("researcher") as child:
            child.log_tool(...)
```

## Priority 5: OpenAI Client Wrapper

**Gap:** OpenAI is the most-used LLM API. No dedicated adapter exists despite HTTP interceptor being available.

**Deliverable:** Thin wrapper that instruments the OpenAI client, extracts model/token/cost metadata from responses, and emits properly typed INFERENCE records.

```python
from ahp.adapters.openai import instrument
import openai

client = instrument(openai.OpenAI())  # all calls now logged to AHP
```

---

## Already Exists (No Action Needed)

| Feature | Location |
|---|---|
| CLI with 8 commands | `ahp/cli/main.py` |
| Token count fields | `ActionPayload.input_token_count`, `output_token_count` |
| OTel export | `ahp/export/otlp.py` |
| PII filtering | `ahp/core/filters.py` with presets |
| HTTP/MCP/gRPC auto-instrumentation | `ahp/interceptors/` |
| LangChain integration | `ahp/integrations/langchain.py` |
| Context propagation | `ahp/core/context.py` |
| Web viewer | `viewer/serve.py` |

## Explicitly Out of Scope

- **OTel field renaming** — mapping belongs in the exporter, not the core schema
- **W3C trace_id/span_id** — `session_id` + `record_id` + `parent_action_id` already serve this purpose
- **Security event classification (ASI categories)** — analysis concern, not recording concern
- **SIEM export mappings** — enterprise upsell, not core protocol
- **Field-level encryption** — needed eventually, not now
- **Separate adapter packages** — premature at v0.1.0 with 1 integration

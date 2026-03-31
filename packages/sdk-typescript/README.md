# ahp-sdk — Agent History Protocol TypeScript SDK

TypeScript/Node.js implementation of the [Agent History Protocol](../../README.md), producing byte-for-byte identical canonical serialization as the Python SDK.

## Install

```
npm install open-ahp
```

## Quickstart

```typescript
import { AHPRecorder, Protocol, ActionType } from "open-ahp";

const recorder = new AHPRecorder({ agentName: "my-agent" });

recorder.recordAction({
  toolName: "search_docs",
  parameters: Buffer.from('{"query": "return policy"}'),
  result: Buffer.from('{"matches": []}'),
  protocol: Protocol.MCP,
  actionType: ActionType.TOOL_CALL,
});

// Record an LLM inference with token tracking
recorder.recordInference({
  toolName: "openai.chat.completions",
  modelId: "gpt-4o",
  inputTokenCount: 1200,
  outputTokenCount: 340,
  reasoningTokens: 512,
  cacheReadTokens: 800,
  costNanoUsd: 8000000,  // $0.008 in nano USD
  provider: "openai",
});

recorder.close();
```

## Chain Verification

```typescript
import { ChainReader, crc32 } from "open-ahp";
import * as crypto from "crypto";

const reader = new ChainReader("my-agent.ahp");
for (const stored of reader.iterRecords()) {
  const hash = crypto.createHash("sha256").update(stored).digest();
  console.log(`Record: ${hash.toString("hex").slice(0, 16)}...`);
}
```

## API

- `AHPRecorder` — main entry point, records actions with PII filtering, evidence storage, and checkpoints
- `ChainWriter` / `ChainReader` — low-level chain file I/O
- `EvidenceStore` — content-addressed evidence storage
- `FilterPipeline` — PII redaction (presets: `pci`, `pii-us`, `pii-eu`, `hipaa`, `credentials`)
- `verifyChain()` — hash chain integrity verification
- `recoverChain()` — crash recovery with chain scan and truncation

## Cross-SDK Compatibility

Canonical serialization is byte-for-byte identical with the Python SDK. Chain files written by either SDK can be read and verified by the other.

## License

Apache 2.0

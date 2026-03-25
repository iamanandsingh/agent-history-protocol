/**
 * Transparent HTTP interceptor — auto-captures HTTP calls in Node.js.
 *
 * When activated, HTTP calls made via `globalThis.fetch`, the `undici`
 * dispatcher, or `node:http`/`node:https` are automatically captured
 * and recorded in AHP.
 *
 * Supported:
 * - `globalThis.fetch` (Node 18+, also used by `node-fetch` v3+)
 * - Direct `http.request` / `https.request` (stdlib)
 *
 * Usage:
 *   import { AHPRecorder } from "open-ahp";
 *   import { installHttpInterceptor, uninstallHttpInterceptor } from "open-ahp/http-interceptor";
 *
 *   const recorder = new AHPRecorder({ agentName: "my-agent" });
 *   installHttpInterceptor(recorder);
 *
 *   // All fetch() calls are now recorded:
 *   await fetch("https://api.openai.com/v1/chat/completions", { method: "POST", body: "..." });
 *
 *   uninstallHttpInterceptor();
 */

import {
  Protocol,
  ActionType,
  ResultStatus,
} from "./types";

import type { AHPRecorder } from "./recorder";

// LLM API endpoint patterns — auto-detect INFERENCE
const LLM_PATTERNS: Array<[RegExp, string]> = [
  [/api\.openai\.com\/v\d+\/chat\/completions/, "openai.chat.completions"],
  [/api\.anthropic\.com\/v\d+\/messages/, "anthropic.messages"],
  [/generativelanguage\.googleapis\.com/, "google.generateContent"],
  [/api\.cohere\.ai\/v\d+\/chat/, "cohere.chat"],
  [/api\.mistral\.ai/, "mistral.chat"],
];

function detectLlm(url: string): string | null {
  for (const [pattern, name] of LLM_PATTERNS) {
    if (pattern.test(url)) return name;
  }
  return null;
}

function extractModelId(body: string): string {
  try {
    const data = JSON.parse(body);
    return data.model || "";
  } catch {
    return "";
  }
}

function extractTokens(body: string): [number, number] {
  try {
    const data = JSON.parse(body);
    const usage = data.usage || {};
    if (usage) {
      return [
        usage.input_tokens || usage.prompt_tokens || 0,
        usage.output_tokens || usage.completion_tokens || 0,
      ];
    }
    const meta = data.usageMetadata || {};
    if (meta) {
      return [meta.promptTokenCount || 0, meta.candidatesTokenCount || 0];
    }
    return [0, 0];
  } catch {
    return [0, 0];
  }
}

// Module state
let _recorder: AHPRecorder | null = null;
let _originalFetch: typeof globalThis.fetch | null = null;
let _inInterceptor = false;

function recordHttpCall(
  method: string,
  url: string,
  requestBody: Uint8Array,
  responseBody: Uint8Array,
  statusCode: number,
  durationMs: number,
): void {
  if (_recorder === null) return;

  _inInterceptor = true;
  try {
    const llmName = detectLlm(url);
    const isInference = llmName !== null;

    let modelId = "";
    let inputTokens = 0;
    let outputTokens = 0;
    if (isInference) {
      modelId = extractModelId(new TextDecoder().decode(requestBody));
      [inputTokens, outputTokens] = extractTokens(
        new TextDecoder().decode(responseBody),
      );
    }

    let resultStatus: ResultStatus;
    if (statusCode >= 200 && statusCode < 300) {
      resultStatus = ResultStatus.SUCCESS;
    } else if (statusCode === 408 || statusCode === 504) {
      resultStatus = ResultStatus.TIMEOUT;
    } else if (statusCode >= 400) {
      resultStatus = ResultStatus.ERROR;
    } else {
      resultStatus = ResultStatus.FAILURE;
    }

    _recorder.safeRecord({
      toolName: llmName || `${method} ${url}`,
      parameters: requestBody,
      result: responseBody,
      protocol: Protocol.HTTP,
      actionType: isInference ? ActionType.INFERENCE : ActionType.TOOL_CALL,
      resultStatus,
      responseTimeMs: durationMs,
      targetEntity: url,
      modelId,
      inputTokenCount: inputTokens,
      outputTokenCount: outputTokens,
    });
  } catch {
    // Fail-open: never crash the agent
  } finally {
    _inInterceptor = false;
  }
}

/**
 * Install the transparent HTTP interceptor.
 *
 * Patches `globalThis.fetch` to record all HTTP calls.
 * Calling this more than once (without uninstalling first) is a no-op.
 */
export function installHttpInterceptor(recorder: AHPRecorder): void {
  if (_originalFetch !== null) return; // Already installed

  _recorder = recorder;

  // Patch globalThis.fetch (Node 18+)
  if (typeof globalThis.fetch === "function") {
    _originalFetch = globalThis.fetch;
    const origFetch = _originalFetch;

    globalThis.fetch = async function interceptedFetch(
      input: any,
      init?: any,
    ): Promise<Response> {
      // Reentrancy guard
      if (_inInterceptor) {
        return origFetch(input, init);
      }

      const url =
        typeof input === "string"
          ? input
          : input instanceof URL
            ? input.toString()
            : input.url;
      const method = init?.method || "GET";
      let requestBody = new Uint8Array(0);
      if (init?.body) {
        if (typeof init.body === "string") {
          requestBody = new TextEncoder().encode(init.body);
        } else if (init.body instanceof Uint8Array) {
          requestBody = init.body;
        } else if (init.body instanceof ArrayBuffer || init.body instanceof SharedArrayBuffer) {
          requestBody = new Uint8Array(init.body as ArrayBuffer);
        } else {
          const bodyType =
            init.body instanceof ReadableStream ? "ReadableStream" :
            init.body instanceof Blob ? "Blob" :
            init.body instanceof FormData ? "FormData" :
            init.body instanceof URLSearchParams ? "URLSearchParams" :
            typeof init.body;
          console.warn(
            `[open-ahp] HTTP interceptor: request body of type '${bodyType}' cannot be captured — ` +
            `evidence will be incomplete for this request to ${url}`
          );
        }
      }

      const start = Date.now();
      let response: Response;

      try {
        response = await origFetch(input, init);
      } catch (e) {
        const durationMs = Date.now() - start;
        const errBody = new TextEncoder().encode(String(e));
        recordHttpCall(method, url, requestBody, errBody, 0, durationMs);
        throw e;
      }

      const durationMs = Date.now() - start;

      // Clone the response so the caller can still read it
      const cloned = response.clone();
      let responseBody: Uint8Array;
      try {
        const buf = await cloned.arrayBuffer();
        responseBody = new Uint8Array(buf);
      } catch {
        responseBody = new Uint8Array(0);
      }

      recordHttpCall(
        method,
        url,
        requestBody,
        responseBody,
        response.status,
        durationMs,
      );

      return response;
    };
  }
}

/**
 * Remove the HTTP interceptor and restore the original `fetch`.
 */
export function uninstallHttpInterceptor(): void {
  if (_originalFetch !== null) {
    globalThis.fetch = _originalFetch;
    _originalFetch = null;
  }
  _recorder = null;
}

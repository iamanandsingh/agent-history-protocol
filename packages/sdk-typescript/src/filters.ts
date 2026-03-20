/**
 * PII filter pipeline — Section 10.2 of the AHP specification.
 *
 * Provides regex-based filtering of sensitive data from payloads
 * before they are hashed and stored.
 */

import * as crypto from "crypto";

export interface FilterDefinition {
  name: string;
  pattern: string;
  replacement: string;
  scope: string[];
}

export class Filter {
  readonly name: string;
  readonly pattern: string;
  readonly replacement: string;
  readonly scope: string[];
  private _compiled: RegExp | null = null;

  constructor(
    name: string,
    pattern: string,
    replacement: string,
    scope: string[] = ["parameters", "results"]
  ) {
    this.name = name;
    this.pattern = pattern;
    this.replacement = replacement;
    this.scope = scope;
  }

  compile(): void {
    this._compiled = new RegExp(this.pattern, "g");
  }

  /**
   * Apply filter. Returns [filtered_text, did_match].
   */
  apply(text: string): [string, boolean] {
    if (this._compiled === null) {
      this.compile();
    }
    // Reset lastIndex for global regex
    this._compiled!.lastIndex = 0;
    const result = text.replace(this._compiled!, this.replacement);
    const didMatch = result !== text;
    return [result, didMatch];
  }
}

// Built-in presets (Section 10.3) — EXACT same patterns as Python SDK
export const PRESETS: Record<string, Filter[]> = {
  pci: [
    new Filter(
      "credit_card",
      "\\b\\d{4}[-\\s]?\\d{4}[-\\s]?\\d{4}[-\\s]?\\d{4}\\b",
      "[REDACTED:CC]"
    ),
    new Filter(
      "cvv",
      "\\b\\d{3,4}\\b(?=.{0,40}(?:cvv|cvc|security))",
      "[REDACTED:CVV]"
    ),
  ],
  "pii-us": [
    new Filter("ssn", "\\b\\d{3}-\\d{2}-\\d{4}\\b", "[REDACTED:SSN]"),
  ],
  credentials: [
    new Filter(
      "bearer_token",
      "Bearer\\s+[A-Za-z0-9\\-._~+/]+=*",
      "Bearer [REDACTED:TOKEN]"
    ),
    new Filter(
      "api_key",
      '(?:api[_-]?key|apikey|secret[_-]?key)\\s*[:=]\\s*["\']?[A-Za-z0-9\\-._~+/]{16,}["\']?',
      "[REDACTED:API_KEY]",
      ["all"]
    ),
    new Filter(
      "password",
      '(?:password|passwd|pwd)\\s*[:=]\\s*["\']?[^\\s"\']{4,}["\']?',
      "[REDACTED:PASSWORD]",
      ["all"]
    ),
  ],
  "pii-eu": [
    new Filter(
      "iban",
      "\\b[A-Z]{2}\\d{2}[A-Z0-9]{4}\\d{7}[A-Z0-9]{0,16}\\b",
      "[REDACTED:IBAN]"
    ),
    new Filter(
      "eu_national_id",
      "\\b[A-Z]{1,2}\\d{6,9}[A-Z]?\\b",
      "[REDACTED:EU_ID]"
    ),
    new Filter(
      "eu_passport",
      "\\b[A-Z]{1,2}\\d{7,8}\\b",
      "[REDACTED:PASSPORT]"
    ),
  ],
  hipaa: [
    new Filter(
      "mrn",
      "\\bMRN[-:\\s]*\\d{6,10}\\b",
      "[REDACTED:MRN]"
    ),
    new Filter(
      "dob",
      "\\b(?:DOB|Date of Birth)[-:\\s]*\\d{1,2}[/\\-]\\d{1,2}[/\\-]\\d{2,4}\\b",
      "[REDACTED:DOB]",
      ["all"]
    ),
    new Filter(
      "phone_us",
      "\\b(?:\\+1[-\\.\\s]?)?\\(?\\d{3}\\)?[-\\.\\s]?\\d{3}[-\\.\\s]?\\d{4}\\b",
      "[REDACTED:PHONE]"
    ),
    new Filter(
      "email",
      "[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}",
      "[REDACTED:EMAIL]"
    ),
  ],
};

export class FilterPipeline {
  readonly filters: Filter[];

  constructor(
    filters?: Filter[] | null,
    presets?: string[] | null
  ) {
    this.filters = [];

    if (presets) {
      for (const presetName of presets) {
        const presetFilters = PRESETS[presetName];
        if (presetFilters) {
          this.filters.push(...presetFilters);
        }
      }
    }

    if (filters) {
      this.filters.push(...filters);
    }

    // Pre-compile all filters
    for (const f of this.filters) {
      f.compile();
    }
  }

  /**
   * Apply all matching filters. Returns [filtered_bytes, was_redacted].
   */
  // Maximum payload size for regex filtering (1MB). Larger payloads skip
  // regex processing to prevent ReDoS on adversarial input.
  static readonly MAX_FILTER_SIZE = 1_048_576;

  apply(
    payload: Uint8Array,
    scope: string = "parameters"
  ): [Uint8Array, boolean] {
    if (payload.length > FilterPipeline.MAX_FILTER_SIZE) {
      return [payload, false]; // Too large for safe regex processing
    }
    let text: string;
    try {
      text = new TextDecoder("utf-8", { fatal: true }).decode(payload);
    } catch {
      // Binary payload — filters don't apply
      return [payload, false];
    }

    let redacted = false;
    for (const f of this.filters) {
      if (f.scope.includes(scope) || f.scope.includes("all")) {
        const [filtered, matched] = f.apply(text);
        text = filtered;
        if (matched) {
          redacted = true;
        }
      }
    }

    return [new TextEncoder().encode(text), redacted];
  }

  /**
   * Filter then hash. Returns [hash_16, filtered_bytes, was_redacted].
   */
  hashPayload(
    payload: Uint8Array,
    scope: string = "parameters"
  ): [Uint8Array, Uint8Array, boolean] {
    const [filtered, redacted] = this.apply(payload, scope);
    const hash16 = new Uint8Array(
      crypto.createHash("sha256").update(filtered).digest().subarray(0, 16)
    );
    return [hash16, filtered, redacted];
  }

  /**
   * SHA-256 of canonical filter config for BootRecord.
   */
  configHash(): Uint8Array {
    if (this.filters.length === 0) {
      return new Uint8Array(32);
    }

    const config = JSON.stringify(
      this.filters.map((f) => ({
        name: f.name,
        pattern: f.pattern,
        replacement: f.replacement,
        scope: [...f.scope].sort(),
      }))
    );

    return new Uint8Array(
      crypto.createHash("sha256").update(config).digest()
    );
  }
}

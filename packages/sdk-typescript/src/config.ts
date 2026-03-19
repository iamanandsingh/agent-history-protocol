/**
 * AHP configuration — loads ahp.yaml/JSON and applies defaults + per-agent overrides.
 *
 * Implements Section 10 of the AHP specification.
 */

import * as fs from "fs";
import * as path from "path";
import * as os from "os";

// --- Configuration interfaces ---

export interface FilterConfig {
  name: string;
  pattern: string;
  replacement: string;
  scope: string[];
}

export interface WitnessConfig {
  enabled: boolean;
  interval: number;
  endpoints: string[];
}

export interface AHPConfig {
  // Recording policy
  level: number; // 1-3
  inferenceRecord: boolean;
  inferenceEvidence: boolean;
  evidenceRecord: boolean;
  authorizationRecord: boolean;
  fsyncMode: string; // "every" | "batch" | "none"
  checkpointInterval: number;

  // Witness
  witness: WitnessConfig;

  // PII Filters
  filters: FilterConfig[];
  filterPresets: string[];

  // Agent identity
  agentName: string;
  agentFramework: string;

  // Internals
  configSource: string;
  matchedAgentRule: string;
}

/**
 * Validate an AHPConfig. Returns list of errors (empty = valid).
 */
export function validateConfig(config: AHPConfig): string[] {
  const errors: string[] = [];
  if (config.level < 1 || config.level > 3) {
    errors.push(`level must be 1, 2, or 3, got ${config.level}`);
  }
  if (config.level === 3 && !config.witness.enabled) {
    errors.push("level=3 requires witness.enabled=true");
  }
  if (config.level === 3 && config.witness.endpoints.length === 0) {
    errors.push("level=3 requires at least one witness endpoint");
  }
  if (!["every", "batch", "none"].includes(config.fsyncMode)) {
    errors.push(`fsync_mode must be every/batch/none, got ${config.fsyncMode}`);
  }
  if (config.checkpointInterval < 1) {
    errors.push(
      `checkpoint_interval must be >= 1, got ${config.checkpointInterval}`
    );
  }
  return errors;
}

/**
 * Create a default AHPConfig.
 */
export function defaultConfig(): AHPConfig {
  return {
    level: 1,
    inferenceRecord: true,
    inferenceEvidence: true,
    evidenceRecord: true,
    authorizationRecord: false,
    fsyncMode: "batch",
    checkpointInterval: 1000,
    witness: { enabled: false, interval: 1000, endpoints: [] },
    filters: [],
    filterPresets: [],
    agentName: "",
    agentFramework: "",
    configSource: "",
    matchedAgentRule: "",
  };
}

/**
 * Load AHP configuration from file or environment.
 *
 * Search order:
 * 1. Explicit path argument
 * 2. AHP_CONFIG environment variable
 * 3. ./ahp.yaml or ./ahp.yml or ./ahp.json
 * 4. ~/.ahp/config.yaml
 * 5. Defaults
 */
export function loadConfig(
  configPath?: string,
  agentName: string = ""
): AHPConfig {
  const foundPath = findConfig(configPath);

  let config: AHPConfig;
  if (foundPath) {
    config = loadFromFile(foundPath, agentName);
  } else {
    config = fromEnv(agentName);
  }

  const errors = validateConfig(config);
  if (errors.length > 0) {
    throw new Error(
      "Invalid AHP configuration:\n  - " + errors.join("\n  - ")
    );
  }

  return config;
}

// --- Internal helpers ---

function findConfig(explicitPath?: string): string | null {
  if (explicitPath && fs.existsSync(explicitPath)) {
    return explicitPath;
  }

  const envPath = process.env.AHP_CONFIG;
  if (envPath && fs.existsSync(envPath)) {
    return envPath;
  }

  const candidates = ["ahp.yaml", "ahp.yml", "ahp.json"];
  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) {
      return candidate;
    }
  }

  const homeConfig = path.join(os.homedir(), ".ahp", "config.yaml");
  if (fs.existsSync(homeConfig)) {
    return homeConfig;
  }

  return null;
}

function loadFromFile(filePath: string, agentName: string): AHPConfig {
  const content = fs.readFileSync(filePath, "utf-8");
  let raw: Record<string, unknown>;

  if (filePath.endsWith(".json")) {
    raw = JSON.parse(content) as Record<string, unknown>;
  } else {
    // YAML parsing: try to use a simple JSON-compatible approach
    // For full YAML support, the user would need to install a YAML parser
    try {
      // Try as JSON first (YAML is a superset of JSON)
      raw = JSON.parse(content) as Record<string, unknown>;
    } catch {
      // Basic YAML support: try dynamic require of js-yaml
      try {
        // eslint-disable-next-line @typescript-eslint/no-var-requires
        const yaml = require("js-yaml");
        raw = (yaml.load(content) as Record<string, unknown>) || {};
      } catch {
        throw new Error(
          `Cannot parse ${filePath}: install 'js-yaml' for YAML support, ` +
            `or use a JSON config file`
        );
      }
    }
  }

  const config = parseRawConfig(raw, agentName);
  config.configSource = filePath;
  return config;
}

function fromEnv(agentName: string): AHPConfig {
  const config = defaultConfig();
  config.agentName = agentName;
  config.configSource = "env";

  const rawLevel = process.env.AHP_LEVEL || "1";
  const parsedLevel = parseInt(rawLevel, 10);
  if (isNaN(parsedLevel)) {
    console.warn(
      `AHP_LEVEL=${rawLevel} is not a valid integer, defaulting to 1`
    );
    config.level = 1;
  } else {
    config.level = parsedLevel;
  }

  config.inferenceRecord =
    (process.env.AHP_INFERENCE_RECORD || "true").toLowerCase() === "true";
  config.evidenceRecord =
    (process.env.AHP_EVIDENCE_RECORD || "true").toLowerCase() === "true";
  config.authorizationRecord =
    (process.env.AHP_AUTH_RECORD || "false").toLowerCase() === "true";
  config.fsyncMode = process.env.AHP_FSYNC_MODE || "batch";

  return config;
}

function parseRawConfig(
  raw: Record<string, unknown>,
  agentName: string
): AHPConfig {
  const defaults = (raw.defaults || {}) as Record<string, unknown>;
  const inference = (defaults.inference || {}) as Record<string, unknown>;
  const evidence = (defaults.evidence || {}) as Record<string, unknown>;
  const authorization = (defaults.authorization || {}) as Record<
    string,
    unknown
  >;
  const witnessRaw = (defaults.witness || {}) as Record<string, unknown>;

  const config = defaultConfig();
  config.level = (defaults.level as number) ?? 1;
  config.inferenceRecord = (inference.record as boolean) ?? true;
  config.inferenceEvidence = (inference.evidence as boolean) ?? true;
  config.evidenceRecord = (evidence.record as boolean) ?? true;
  config.authorizationRecord = (authorization.record as boolean) ?? false;
  config.fsyncMode = (defaults.fsync_mode as string) ?? "batch";
  config.checkpointInterval =
    (defaults.checkpoint_interval as number) ?? 1000;
  config.agentName = agentName;

  // Witness config
  config.witness = {
    enabled: (witnessRaw.enabled as boolean) ?? false,
    interval: (witnessRaw.interval as number) ?? 1000,
    endpoints: (witnessRaw.endpoints as string[]) ?? [],
  };

  // Global filters
  const filtersRaw = (raw.filters || []) as Array<Record<string, unknown>>;
  for (const fRaw of filtersRaw) {
    if (fRaw.preset) {
      config.filterPresets.push(fRaw.preset as string);
    } else {
      config.filters.push({
        name: (fRaw.name as string) || "",
        pattern: (fRaw.pattern as string) || "",
        replacement: (fRaw.replacement as string) || "",
        scope: (fRaw.scope as string[]) || ["parameters", "results"],
      });
    }
  }

  // Per-agent overrides (first match wins, using glob/fnmatch style)
  const agents = (raw.agents || []) as Array<Record<string, unknown>>;
  for (const agentRule of agents) {
    const matchPattern = (agentRule.match as string) || "";
    if (matchGlob(agentName, matchPattern)) {
      config.matchedAgentRule = matchPattern;
      applyOverrides(config, agentRule);
      break;
    }
  }

  return config;
}

function applyOverrides(
  config: AHPConfig,
  overrides: Record<string, unknown>
): void {
  if (overrides.level !== undefined) {
    config.level = overrides.level as number;
  }
  if (overrides.inference) {
    const inf = overrides.inference as Record<string, unknown>;
    if (inf.record !== undefined) config.inferenceRecord = inf.record as boolean;
    if (inf.evidence !== undefined)
      config.inferenceEvidence = inf.evidence as boolean;
  }
  if (overrides.evidence) {
    const ev = overrides.evidence as Record<string, unknown>;
    if (ev.record !== undefined) config.evidenceRecord = ev.record as boolean;
  }
  if (overrides.authorization) {
    const auth = overrides.authorization as Record<string, unknown>;
    if (auth.record !== undefined)
      config.authorizationRecord = auth.record as boolean;
  }
  if (overrides.fsync_mode !== undefined) {
    config.fsyncMode = overrides.fsync_mode as string;
  }
  if (overrides.witness) {
    const w = overrides.witness as Record<string, unknown>;
    if (w.enabled !== undefined) config.witness.enabled = w.enabled as boolean;
    if (w.interval !== undefined)
      config.witness.interval = w.interval as number;
    if (w.endpoints !== undefined)
      config.witness.endpoints = w.endpoints as string[];
  }

  // Agent-level filters are APPENDED (not replaced)
  const agentFilters = (overrides.filters || []) as Array<
    Record<string, unknown>
  >;
  for (const fRaw of agentFilters) {
    config.filters.push({
      name: (fRaw.name as string) || "",
      pattern: (fRaw.pattern as string) || "",
      replacement: (fRaw.replacement as string) || "",
      scope: (fRaw.scope as string[]) || ["parameters", "results"],
    });
  }
}

/**
 * Simple glob/fnmatch-style matching supporting * and ?.
 */
function matchGlob(text: string, pattern: string): boolean {
  // Convert glob pattern to regex
  let regex = "^";
  for (const ch of pattern) {
    if (ch === "*") regex += ".*";
    else if (ch === "?") regex += ".";
    else if (
      "+()^$.{}|\\[]".includes(ch)
    )
      regex += "\\" + ch;
    else regex += ch;
  }
  regex += "$";
  return new RegExp(regex).test(text);
}

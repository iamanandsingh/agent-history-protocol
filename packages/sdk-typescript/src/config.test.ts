/**
 * Tests for AHPConfig — defaultConfig, validateConfig, loadConfig (JSON files
 * and env fallback), agent-rule overrides.
 */

import { strict as assert } from "assert";
import { test, describe } from "node:test";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

import {
  AHPConfig,
  defaultConfig,
  validateConfig,
  loadConfig,
} from "./config";

function tmpJson(contents: object): string {
  const p = path.join(
    os.tmpdir(),
    `ahp_cfg_${Date.now()}_${Math.random().toString(36).slice(2)}.json`,
  );
  fs.writeFileSync(p, JSON.stringify(contents));
  return p;
}

describe("defaultConfig", () => {
  test("returns sensible defaults", () => {
    const cfg = defaultConfig();
    assert.equal(cfg.level, 1);
    assert.equal(cfg.fsyncMode, "batch");
    assert.equal(cfg.checkpointInterval, 1000);
    assert.equal(cfg.witness.enabled, false);
    assert.deepEqual(cfg.filters, []);
    assert.deepEqual(cfg.filterPresets, []);
    assert.equal(cfg.inferenceRecord, true);
    assert.equal(cfg.evidenceRecord, true);
    assert.equal(cfg.authorizationRecord, false);
  });
});

describe("validateConfig", () => {
  test("default config is valid", () => {
    assert.deepEqual(validateConfig(defaultConfig()), []);
  });

  test("level out of range produces error", () => {
    const cfg = defaultConfig();
    cfg.level = 5;
    const errs = validateConfig(cfg);
    assert.ok(errs.some((e) => e.includes("level must be 1, 2, or 3")));
  });

  test("level=3 without witness produces errors", () => {
    const cfg = defaultConfig();
    cfg.level = 3;
    const errs = validateConfig(cfg);
    assert.ok(errs.some((e) => e.includes("witness.enabled=true")));
    assert.ok(errs.some((e) => e.includes("witness endpoint")));
  });

  test("level=3 with witness enabled and endpoints is valid", () => {
    const cfg = defaultConfig();
    cfg.level = 3;
    cfg.witness = { enabled: true, interval: 1000, endpoints: ["http://w"] };
    assert.deepEqual(validateConfig(cfg), []);
  });

  test("invalid fsync mode produces error", () => {
    const cfg = defaultConfig();
    cfg.fsyncMode = "weird";
    assert.ok(
      validateConfig(cfg).some((e) => e.includes("fsync_mode must be")),
    );
  });

  test("checkpoint interval below 1 produces error", () => {
    const cfg = defaultConfig();
    cfg.checkpointInterval = 0;
    assert.ok(
      validateConfig(cfg).some((e) =>
        e.includes("checkpoint_interval must be >= 1"),
      ),
    );
  });
});

describe("loadConfig from JSON file", () => {
  test("loads explicit JSON file with defaults", () => {
    const p = tmpJson({
      defaults: {
        level: 2,
        fsync_mode: "every",
        checkpoint_interval: 500,
        evidence: { record: false },
      },
    });
    try {
      const cfg = loadConfig(p, "agent-x");
      assert.equal(cfg.level, 2);
      assert.equal(cfg.fsyncMode, "every");
      assert.equal(cfg.checkpointInterval, 500);
      assert.equal(cfg.evidenceRecord, false);
      assert.equal(cfg.agentName, "agent-x");
      assert.equal(cfg.configSource, path.basename(p));
    } finally {
      fs.unlinkSync(p);
    }
  });

  test("global filter list is parsed and presets pulled out", () => {
    const p = tmpJson({
      filters: [
        { preset: "pci" },
        { name: "custom", pattern: "x+", replacement: "[X]", scope: ["all"] },
      ],
    });
    try {
      const cfg = loadConfig(p, "a");
      assert.deepEqual(cfg.filterPresets, ["pci"]);
      assert.equal(cfg.filters.length, 1);
      assert.equal(cfg.filters[0].name, "custom");
      assert.deepEqual(cfg.filters[0].scope, ["all"]);
    } finally {
      fs.unlinkSync(p);
    }
  });

  test("agent rule overrides apply to matching agent", () => {
    const p = tmpJson({
      defaults: { level: 1 },
      agents: [
        { match: "prod-*", level: 2, fsync_mode: "every" },
        { match: "*", level: 1 },
      ],
    });
    try {
      const cfg = loadConfig(p, "prod-payments");
      assert.equal(cfg.level, 2);
      assert.equal(cfg.fsyncMode, "every");
      assert.equal(cfg.matchedAgentRule, "prod-*");
    } finally {
      fs.unlinkSync(p);
    }
  });

  test("agent rule does not match unrelated agent", () => {
    const p = tmpJson({
      defaults: { level: 1 },
      agents: [{ match: "prod-*", level: 3 }],
    });
    try {
      const cfg = loadConfig(p, "dev-runner");
      assert.equal(cfg.level, 1);
      assert.equal(cfg.matchedAgentRule, "");
    } finally {
      fs.unlinkSync(p);
    }
  });

  test("invalid level in file throws", () => {
    const p = tmpJson({ defaults: { level: 9 } });
    try {
      assert.throws(() => loadConfig(p, "a"), /Invalid AHP configuration/);
    } finally {
      fs.unlinkSync(p);
    }
  });
});

describe("loadConfig env fallback", () => {
  test("returns env-driven config when no file is found", () => {
    // Switch into a tmp empty cwd so no ahp.{yaml,yml,json} is discovered.
    const oldCwd = process.cwd();
    const oldEnv = process.env.AHP_CONFIG;
    const oldHome = process.env.HOME;
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ahp_cfg_env_"));
    delete process.env.AHP_CONFIG;
    process.env.HOME = dir; // ensure ~/.ahp/config.yaml does not exist
    process.chdir(dir);
    try {
      const cfg = loadConfig(undefined, "envy");
      assert.equal(cfg.configSource, "env");
      assert.equal(cfg.agentName, "envy");
    } finally {
      process.chdir(oldCwd);
      if (oldEnv !== undefined) process.env.AHP_CONFIG = oldEnv;
      if (oldHome !== undefined) process.env.HOME = oldHome;
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

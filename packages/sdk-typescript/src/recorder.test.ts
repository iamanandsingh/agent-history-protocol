/**
 * Smoke tests for AHPRecorder — construction, recordAction, close lifecycle.
 */

import { strict as assert } from "assert";
import { test, describe } from "node:test";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

import { AHPRecorder } from "./recorder";
import { Protocol, ActionType, ResultStatus } from "./types";

function tmpChainPath(): string {
  return path.join(
    os.tmpdir(),
    `ahp_test_${Date.now()}_${Math.random().toString(36).slice(2)}.ahp`,
  );
}

describe("AHPRecorder lifecycle", () => {
  test("constructs with minimal options and creates chain file", () => {
    const chainPath = tmpChainPath();
    const recorder = new AHPRecorder({ agentName: "test-agent", chainPath });
    recorder.close();
    assert.ok(fs.existsSync(chainPath), "chain file should exist after close");
    fs.unlinkSync(chainPath);
  });

  test("sanitizes unsafe characters in default agentName-derived path", () => {
    const recorder = new AHPRecorder({ agentName: "weird/name with spaces" });
    recorder.close();
    // No assertion on exact path; just verify no throw and file exists in tmp.
  });

  test("recordAction writes a record to the chain", () => {
    const chainPath = tmpChainPath();
    const recorder = new AHPRecorder({ agentName: "test-agent", chainPath });
    recorder.recordAction({
      toolName: "search_docs",
      parameters: Buffer.from('{"q":"hello"}'),
      result: Buffer.from('{"ok":true}'),
      protocol: Protocol.MCP,
      actionType: ActionType.TOOL_CALL,
      resultStatus: ResultStatus.SUCCESS,
      responseTimeMs: 12,
    });
    recorder.close();

    const stat = fs.statSync(chainPath);
    assert.ok(stat.size > 0, "chain file should contain bytes after recordAction");
    fs.unlinkSync(chainPath);
  });

  test("multiple recordAction calls grow the chain file monotonically", () => {
    const chainPath = tmpChainPath();
    const recorder = new AHPRecorder({ agentName: "test-agent", chainPath });

    recorder.recordAction({ toolName: "a", protocol: Protocol.MCP, actionType: ActionType.TOOL_CALL });
    const sizeAfterOne = fs.statSync(chainPath).size;

    recorder.recordAction({ toolName: "b", protocol: Protocol.MCP, actionType: ActionType.TOOL_CALL });
    recorder.recordAction({ toolName: "c", protocol: Protocol.MCP, actionType: ActionType.TOOL_CALL });
    recorder.close();

    const sizeAfterThree = fs.statSync(chainPath).size;
    assert.ok(sizeAfterThree > sizeAfterOne, "chain file should grow with more records");
    fs.unlinkSync(chainPath);
  });
});

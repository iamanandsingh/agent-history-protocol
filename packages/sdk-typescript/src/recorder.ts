/**
 * AHPRecorder — the main SDK entry point.
 *
 * Wires together: chain writer + evidence store + PII filters + signing +
 * crash recovery into one automated flow.
 *
 * Usage:
 *   import { AHPRecorder } from "@ahp/sdk";
 *
 *   const recorder = new AHPRecorder({ agentName: "my-agent" });
 *
 *   recorder.recordAction({
 *     toolName: "search_docs",
 *     parameters: Buffer.from('{"query": "return policy"}'),
 *     result: Buffer.from('{"matches": [...]}'),
 *     protocol: Protocol.MCP,
 *     actionType: ActionType.TOOL_CALL,
 *   });
 *
 *   recorder.close();
 */

import * as os from "os";
import * as path from "path";
import * as crypto from "crypto";
import * as fs from "fs";

import {
  Record as AHPRecord,
  ResultStatus,
  Protocol,
  ActionType,
  AuthorizationType,
  GapReason,
  ChainLevel,
  FsyncMode,
  ZERO_HASH_32,
  ZERO_UUID,
  createActionPayload,
  createBootPayload,
  createCheckpointPayload,
  createKeyPayload,
  Authorization,
} from "./types";
import { canonicalBytes } from "./canonical";
import { ChainWriter } from "./chain";
import { EvidenceStore } from "./evidence";
import { Filter, FilterPipeline } from "./filters";
import {
  KeyPair,
  generateKeypair,
  sign as ed25519Sign,
  computeMerkleRoot,
} from "./signing";
import { AHPConfig, loadConfig, defaultConfig } from "./config";
import { recoverChain, RecoveryResult } from "./recovery";

// SDK identity constants
const SDK_NAME = "ahp-typescript";
const SDK_VERSION = "0.1.0";

// Map string fsync modes from config to enum values
const FSYNC_MAP: { [key: string]: FsyncMode } = {
  every: FsyncMode.EVERY,
  batch: FsyncMode.BATCH,
  none: FsyncMode.NONE,
};

// Default max segment size: 64MB
const DEFAULT_MAX_SEGMENT_BYTES = 64 * 1024 * 1024;

export interface AHPRecorderOptions {
  agentName: string;
  chainPath?: string;
  level?: number;
  config?: AHPConfig;
  evidencePath?: string;
  checkpointInterval?: number;
  witnessInterval?: number;
  witnessEndpoints?: string[];
  filterPresets?: string[];
  customFilters?: Filter[];
  agentFramework?: string;
  interceptors?: string[];
}

export interface RecordActionOptions {
  toolName: string;
  parameters?: Uint8Array;
  result?: Uint8Array;
  protocol?: Protocol;
  actionType?: ActionType;
  resultStatus?: ResultStatus;
  responseTimeMs?: number;
  targetEntity?: string;
  parentActionId?: Uint8Array;
  authorization?: Authorization;
  modelId?: string;
  inputTokenCount?: number;
  outputTokenCount?: number;
}

export class AHPRecorder {
  private _cfg: AHPConfig;
  private _agentName: string;
  private _level: number;
  private _checkpointInterval: number;
  private _agentFramework: string;
  private _interceptors: string[];

  private _chain: ChainWriter;
  private _chainPath: string;
  private _maxSegmentBytes: number;

  private _evidenceEnabled: boolean;
  private _evidence: EvidenceStore | null;

  private _filters: FilterPipeline;
  private _keypair: KeyPair | null;

  // Internal counters
  private _recordsSinceCheckpoint: number = 0;
  private _recordHashesSinceCheckpoint: Uint8Array[] = [];

  // Fail-open gap state
  private _pendingGap: boolean = false;
  private _gapDetail: string = "";
  private _gapFirstLostSeq: bigint = 0n;

  private _recoveryResult: RecoveryResult | null = null;

  constructor(options: AHPRecorderOptions) {
    const {
      agentName,
      chainPath,
      level = 1,
      config,
      evidencePath,
      checkpointInterval = 1000,
      filterPresets,
      customFilters,
      agentFramework = "",
      interceptors = [],
    } = options;

    // Resolve config
    if (config) {
      this._cfg = config;
    } else {
      this._cfg = defaultConfig();
      this._cfg.level = level;
      this._cfg.agentName = agentName;
      this._cfg.agentFramework = agentFramework;
      this._cfg.checkpointInterval = checkpointInterval;
      if (filterPresets) {
        this._cfg.filterPresets = filterPresets;
      }
    }

    this._agentName = agentName;
    this._level = this._cfg.level;
    this._checkpointInterval = this._cfg.checkpointInterval;
    this._agentFramework = this._cfg.agentFramework || agentFramework;
    this._interceptors = interceptors;
    this._maxSegmentBytes = DEFAULT_MAX_SEGMENT_BYTES;

    // Chain writer (with recovery)
    this._chainPath =
      chainPath ||
      path.join(os.tmpdir(), `ahp_${agentName}.ahp`);

    // Recovery: if chain file already exists, scan and truncate corrupt tail
    if (fs.existsSync(this._chainPath)) {
      try {
        this._recoveryResult = recoverChain(this._chainPath);
      } catch {
        // Recovery failed; proceed with fresh chain
      }
    }

    this._chain = new ChainWriter(this._chainPath);

    // Evidence store
    this._evidenceEnabled = this._cfg.evidenceRecord;
    this._evidence = null;
    if (this._evidenceEnabled) {
      const epath =
        evidencePath ||
        path.join(path.dirname(this._chainPath), "evidence");
      this._evidence = new EvidenceStore(epath);
    }

    // PII filter pipeline
    const presetList = [...this._cfg.filterPresets];
    if (filterPresets) {
      for (const p of filterPresets) {
        if (!presetList.includes(p)) {
          presetList.push(p);
        }
      }
    }

    const customFilterList: Filter[] = [...(customFilters || [])];
    for (const fc of this._cfg.filters) {
      customFilterList.push(
        new Filter(fc.name, fc.pattern, fc.replacement, [...fc.scope])
      );
    }

    this._filters = new FilterPipeline(
      customFilterList.length > 0 ? customFilterList : null,
      presetList.length > 0 ? presetList : null
    );

    // Signing (level >= 2)
    this._keypair = null;
    if (this._level >= 2) {
      this._keypair = generateKeypair();
    }

    // Emit genesis records
    this._emitBootRecord();
    if (this._level >= 2 && this._keypair !== null) {
      this._emitKeyGenesisRecord();
    }

    // Emit recovery + gap records if recovery found corrupt data
    if (
      this._recoveryResult !== null &&
      this._recoveryResult.recordsTruncated > 0
    ) {
      this._emitRecoveryRecords(this._recoveryResult);
    }
  }

  /**
   * Create an AHPRecorder from a YAML/JSON configuration file.
   */
  static fromConfig(
    configPath: string,
    agentName: string,
    chainPath?: string,
    evidencePath?: string
  ): AHPRecorder {
    const cfg = loadConfig(configPath, agentName);
    return new AHPRecorder({
      agentName,
      config: cfg,
      chainPath,
      evidencePath,
    });
  }

  // --- Core recording methods ---

  /**
   * Record a single agent action.
   *
   * Filters PII, hashes content, optionally stores evidence,
   * writes to the chain, and triggers checkpoints when interval reached.
   */
  recordAction(opts: RecordActionOptions): AHPRecord {
    const {
      toolName,
      parameters = new Uint8Array(0),
      result = new Uint8Array(0),
      protocol = Protocol.CUSTOM,
      actionType = ActionType.TOOL_CALL,
      resultStatus = ResultStatus.SUCCESS,
      responseTimeMs = 0,
      targetEntity = "",
      parentActionId = new Uint8Array(ZERO_UUID),
      authorization,
      modelId = "",
      inputTokenCount = 0,
      outputTokenCount = 0,
    } = opts;

    // 0. Flush pending gap from previous failure
    this._flushPendingGap();

    // 1. Apply PII filters
    const [paramHash, filteredParams, paramRedacted] =
      this._filters.hashPayload(parameters, "parameters");
    const [resultHash, filteredResult, resultRedacted] =
      this._filters.hashPayload(result, "results");
    const redacted = paramRedacted || resultRedacted;

    // 2. Store evidence if configured
    let evidenceUri = "";
    if (
      this._evidence !== null &&
      (filteredParams.length > 0 || filteredResult.length > 0)
    ) {
      if (filteredParams.length > 0) {
        this._evidence.store(filteredParams);
      }
      if (filteredResult.length > 0) {
        this._evidence.store(filteredResult);
      }
      evidenceUri = "evidence://" + Buffer.from(paramHash).toString("hex");
    }

    // 3. Build payload
    const payload = createActionPayload({
      parent_action_id: parentActionId,
      tool_name: toolName,
      parameters_hash: paramHash,
      result_hash: resultHash,
      result_status: resultStatus,
      response_time_ms: responseTimeMs,
      protocol,
      action_type: actionType,
      target_entity: targetEntity,
      evidence_uri: evidenceUri,
      redacted,
      model_id: modelId,
      input_token_count: inputTokenCount,
      output_token_count: outputTokenCount,
      authorization: authorization || {
        type: AuthorizationType.AUTH_NONE,
        entries: [],
      },
    });

    // 4. Write to chain
    const record = this._chain.writeRecord(payload);

    // 5. Track checkpoint state
    this._trackRecord(record);

    // 6. Auto-checkpoint
    if (this._recordsSinceCheckpoint >= this._checkpointInterval) {
      this.emitCheckpoint();
    }

    // 7. Auto-rotate if chain exceeds 64MB
    this._checkRotation();

    return record;
  }

  /**
   * Record an inference (LLM) call.
   *
   * Convenience wrapper around recordAction that sets actionType=INFERENCE.
   */
  recordInference(
    opts: Omit<RecordActionOptions, "actionType"> & { actionType?: ActionType }
  ): AHPRecord {
    return this.recordAction({
      ...opts,
      actionType: ActionType.INFERENCE,
    });
  }

  // --- Checkpointing ---

  /**
   * Emit a checkpoint record.
   *
   * Computes the Merkle root of records since the last checkpoint,
   * signs it when level >= 2, and writes a CheckpointPayload.
   */
  emitCheckpoint(): AHPRecord {
    const merkleRoot = computeMerkleRoot(
      this._recordHashesSinceCheckpoint
    );

    let signature: Uint8Array = new Uint8Array(64);
    let signingKeyId: Uint8Array = new Uint8Array(ZERO_HASH_32);
    if (this._level >= 2 && this._keypair !== null) {
      signature = new Uint8Array(ed25519Sign(merkleRoot, this._keypair.privateKeyBytes));
      signingKeyId = new Uint8Array(this._keypair.keyId);
    }

    const evidenceStatus = this._getEvidenceStatus();

    const payload = createCheckpointPayload({
      record_count: BigInt(this._chain.recordCount + 1),
      gap_count: BigInt(this._chain.gapCount),
      chain_hash: new Uint8Array(this._chain.prevHash),
      merkle_root: merkleRoot,
      signature,
      signing_key_id: signingKeyId,
      evidence_available: BigInt(evidenceStatus.available),
      evidence_exported: BigInt(evidenceStatus.exported),
      evidence_expired: BigInt(evidenceStatus.expired),
      evidence_missing: BigInt(evidenceStatus.missing),
    });

    const record = this._chain.writeRecord(payload);

    // Reset counters
    this._recordsSinceCheckpoint = 0;
    this._recordHashesSinceCheckpoint = [];

    return record;
  }

  // --- Fail-open wrapper ---

  /**
   * Fail-open wrapper around recordAction.
   *
   * If recording raises an exception the error is captured and a
   * GapRecord will be emitted on the next successful write.
   */
  safeRecord(opts: RecordActionOptions): AHPRecord | null {
    try {
      return this.recordAction(opts);
    } catch (e) {
      if (!this._pendingGap) {
        this._gapFirstLostSeq = this._chain.sequence + 1n;
      }
      this._pendingGap = true;
      this._gapDetail = String(e);
      return null;
    }
  }

  // --- Resource management ---

  close(): void {
    this._chain.close();
  }

  // --- Read-only accessors ---

  get chainPath(): string {
    return this._chainPath;
  }

  get chain(): ChainWriter {
    return this._chain;
  }

  get level(): number {
    return this._level;
  }

  get keypair(): KeyPair | null {
    return this._keypair;
  }

  get evidenceStore(): EvidenceStore | null {
    return this._evidence;
  }

  get filterPipeline(): FilterPipeline {
    return this._filters;
  }

  // --- Internal helpers ---

  private _emitBootRecord(): void {
    const runtimeInfo = `node ${process.version} / ${process.platform}`;
    const fsyncMode = FSYNC_MAP[this._cfg.fsyncMode] ?? FsyncMode.BATCH;

    const payload = createBootPayload({
      sdk_name: SDK_NAME,
      sdk_version: SDK_VERSION,
      interceptors: this._interceptors,
      agent_framework: this._agentFramework,
      agent_name: this._agentName,
      runtime: runtimeInfo,
      chain_level: this._level as ChainLevel,
      fsync_mode: fsyncMode,
      clock_source: "system",
      inference_recording: this._cfg.inferenceRecord,
      inference_evidence: this._cfg.inferenceEvidence,
      evidence_recording: this._cfg.evidenceRecord,
      filter_config_hash: this._filters.configHash(),
      matched_agent_rule: this._cfg.matchedAgentRule,
      config_source: this._cfg.configSource,
      authorization_recording: this._cfg.authorizationRecord,
    });

    const record = this._chain.writeRecord(payload);
    this._trackRecord(record);
  }

  private _emitKeyGenesisRecord(): void {
    if (this._keypair === null) return;

    const payload = createKeyPayload({
      public_key: this._keypair.publicKeyBytes,
      key_id: this._keypair.keyId,
      expires_at: 0n, // no expiry for session keys
      supersedes_key_id: new Uint8Array(ZERO_HASH_32),
    });

    const record = this._chain.writeRecord(payload);
    this._trackRecord(record);
  }

  private _trackRecord(record: AHPRecord): void {
    this._recordsSinceCheckpoint += 1;

    // Keep the SHA-256 of the canonical bytes for Merkle tree
    const stored = canonicalBytes(record);
    this._recordHashesSinceCheckpoint.push(
      new Uint8Array(crypto.createHash("sha256").update(stored).digest())
    );
  }

  private _flushPendingGap(): void {
    if (!this._pendingGap) return;

    const firstLost = this._gapFirstLostSeq;
    let lastLost = this._chain.sequence;

    if (firstLost > lastLost) {
      lastLost = firstLost;
    }

    const gapRecord = this._chain.writeGap(
      firstLost,
      lastLost,
      GapReason.INTERCEPTOR_FAILURE,
      this._gapDetail
    );
    this._trackRecord(gapRecord);

    this._pendingGap = false;
    this._gapDetail = "";
    this._gapFirstLostSeq = 0n;
  }

  private _emitRecoveryRecords(recoveryResult: RecoveryResult): void {
    const recoveryRecord = this._chain.writeRecovery(
      BigInt(recoveryResult.recordsVerified),
      BigInt(recoveryResult.recordsTruncated),
      recoveryResult.lastValidSeq
    );
    this._trackRecord(recoveryRecord);

    if (recoveryResult.recordsTruncated > 0) {
      const firstLost = recoveryResult.lastValidSeq + 1n;
      const lastLost =
        firstLost + BigInt(recoveryResult.recordsTruncated) - 1n;
      const gapRecord = this._chain.writeGap(
        firstLost,
        lastLost,
        GapReason.CRASH,
        "Records lost during crash recovery"
      );
      this._trackRecord(gapRecord);
    }
  }

  private _checkRotation(): void {
    const chainSize = this._chain.bytesWritten;

    if (chainSize < this._maxSegmentBytes) return;

    // Close persistent file handle before renaming
    this._chain.close();

    // Rename current chain to a timestamped segment
    const timestamp = Math.floor(Date.now() / 1000);
    const segmentPath = this._chainPath + `.${timestamp}.segment`;
    try {
      fs.renameSync(this._chainPath, segmentPath);
    } catch {
      return; // Failed to rename; skip rotation
    }

    // Open a fresh chain writer — note: ChainWriter constructor creates a new file
    this._chain = new ChainWriter(this._chainPath);

    // Emit genesis records in the fresh segment
    this._emitBootRecord();
    if (this._level >= 2 && this._keypair !== null) {
      this._emitKeyGenesisRecord();
    }
  }

  private _getEvidenceStatus(): {
    available: number;
    exported: number;
    expired: number;
    missing: number;
  } {
    if (this._evidence !== null) {
      const counts = this._evidence.count();
      return {
        available: counts.available,
        exported: 0,
        expired: 0,
        missing: counts.missing,
      };
    }
    return { available: 0, exported: 0, expired: 0, missing: 0 };
  }
}

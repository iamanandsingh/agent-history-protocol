# AHP and EU AI Act Compliance Mapping

*Version 1.0 · March 2026*

> **Disclaimer:** This document is for informational purposes only and does not constitute legal advice. Organizations should consult qualified legal counsel to assess their specific EU AI Act compliance obligations. AHP is a technical protocol — regulatory compliance requires organizational, legal, and technical measures beyond any single tool.

---

## Executive Summary

The Agent History Protocol (AHP) provides tamper-evident, hash-chained logging of AI agent actions with built-in support for human oversight tracking, evidence retention, and independent verification. These capabilities directly address the record-keeping (Article 12), human oversight documentation (Article 14), and transparency (Article 13) requirements that the EU AI Act imposes on high-risk AI systems. AHP does not replace a risk management system or bias testing framework, but it provides the auditable logging infrastructure those programs depend on.

## Timeline

The EU AI Act high-risk provisions for Annex III systems (AI used in employment, credit scoring, education, law enforcement, and similar domains) become enforceable on **2 August 2026**. Annex I high-risk systems (regulated products and safety components) follow on 2 August 2027. Organizations deploying AI agents in high-risk categories should have compliant logging infrastructure in place before these dates. The European Commission's proposed "Digital Omnibus" package could adjust Annex III timelines, but prudent planning treats August 2026 as the binding deadline.

---

## Requirement Mapping

| EU AI Act Article | Requirement Summary | How AHP Addresses It | AHP Feature / Conformance Level | Status |
|---|---|---|---|---|
| **Art. 12(1)** — Automatic logging | High-risk AI systems must technically allow for automatic recording of events (logs) over the system's lifetime | AHP's SDK interceptors automatically capture every agent action (tool calls, LLM inferences, delegations) as hash-chained ActionRecords with timestamps, sequence numbers, and result status | ActionRecord, BootRecord, interceptors · Level 1+ | **Fully addressed** |
| **Art. 12(2)(a)** — Risk-relevant event logging | Logs must enable identification of situations that may present a risk or lead to substantial modification | AHP records result_status (SUCCESS, FAILURE, TIMEOUT, ERROR), response times, and GapRecords for any lost data. Anomaly detection can query these structured fields to surface risk indicators | ActionRecord fields, GapRecord · Level 1+ | **Fully addressed** |
| **Art. 12(2)(b)** — Post-market monitoring | Logs must facilitate post-market monitoring per Article 72 | AHP chains are exportable (OTLP, JSONL), queryable via CLI (`ahp log`, `ahp query`), and support evidence linking for full payload retrieval. BatchCheckpoints provide periodic chain summaries | Evidence model, export, BatchCheckpoint · Level 1+ | **Fully addressed** |
| **Art. 12(2)(c)** — Operational monitoring by deployers | Logs must enable deployers to monitor system operation | AHP's JSON export (Appendix H), CLI tools, and structured record format make logs accessible to deployers without requiring access to the underlying agent code | JSON export, CLI tools · Level 1+ | **Fully addressed** |
| **Art. 19(1)** — Log retention by deployers | Deployers of high-risk AI systems must keep automatically generated logs for a period appropriate to the intended purpose, and at least 6 months (unless otherwise provided in EU or national law) | AHP supports configurable retention via chain segment rotation and export policies. Segments can be exported to external storage (S3, etc.) before local deletion. Evidence store supports TTL and max-size lifecycle management. Retention duration is operator-configured | Chain segments, export/rotation policy, evidence lifecycle · Level 1+ | **Complementary** (AHP provides the mechanism; operators must configure retention period to meet the 6-month minimum) |
| **Art. 13(1)** — Transparency of operation | High-risk systems must be sufficiently transparent to enable deployers to interpret outputs and use them appropriately | AHP's BootRecord documents the SDK configuration, active interceptors, agent framework, recording policy, and filter configuration — providing a clear picture of what is being monitored and how | BootRecord, configuration transparency · Level 1+ | **Partially addressed** (AHP covers logging transparency; system-level transparency documentation is out of scope) |
| **Art. 13(3)(b)** — Capabilities and limitations | Instructions must include system capabilities, limitations, and performance levels | AHP records model_id, token counts, response times, and result status on every inference — providing empirical performance data. AHP does not generate capability documentation but supplies the data for it | INFERENCE records, performance fields · Level 1+ | **Partially addressed** (provides data; does not generate documentation) |
| **Art. 14(1)** — Human oversight design | High-risk systems must be designed for effective human oversight during use | AHP's authorization model records who approved each agent action (AUTH_HUMAN, AUTH_AGENT, AUTH_POLICY, AUTH_MULTI_PARTY) with authorizer identity and timestamps. This creates an auditable trail proving human-in-the-loop controls were active | Authorization model (Section 3.9) · Level 1+ | **Fully addressed** |
| **Art. 14(4)(a)** — Understand AI capabilities | Humans assigned oversight must understand the system's relevant capacities and limitations | AHP's BootRecord and INFERENCE records document which models are being used, what interceptors are active, and what actions agents are taking — supporting informed oversight | BootRecord, INFERENCE records · Level 1+ | **Partially addressed** (provides operational visibility; training and documentation are out of scope) |
| **Art. 14(4)(d)** — Ability to intervene | Humans must be able to decide not to use the system or disregard its output | AHP records rejected authorizations (decision = REJECTED) with result_status = ERROR, documenting when humans exercised override authority. Cross-chain verification confirms authorizer decisions match | Authorization rejection tracking, cross-chain verification · Level 1+ | **Partially addressed** (documents intervention; does not implement intervention mechanisms) |
| **Art. 9(1)** — Risk management system | A risk management system must be established, documented, and maintained throughout the AI system lifecycle | AHP does not implement a risk management system. However, AHP's structured audit trail, evidence store, and anomaly-detection-friendly data model provide essential inputs to risk management processes | Evidence model, structured queries · Level 1+ | **Complementary** (provides data for risk management; does not replace it) |
| **Art. 9(2)(a)** — Risk identification and analysis | Known and reasonably foreseeable risks must be identified and analyzed | AHP's historical action data supports post-hoc risk analysis by making all agent behavior queryable. Pattern analysis over AHP chains can surface recurring failures or anomalous behavior | Queryable chain, GapRecords, error tracking · Level 1+ | **Complementary** |

---

## What AHP Covers

- **Automatic, tamper-evident logging** of every AI agent action with hash-chain integrity (Article 12)
- **Human oversight documentation** via the authorization model — records who approved, rejected, or set conditions on each action (Article 14)
- **Evidence retention** with content-addressed linking, configurable retention, and export to external storage (Article 12(3))
- **Independent verification** via the witness protocol — third-party services attest to chain state, preventing unilateral history rewriting (Level 3)
- **PII filtering** applied before hashing, supporting GDPR-compatible audit trails (with evidence erasure status tracking)
- **Cross-agent auditability** through double-entry bookkeeping — when agents authorize each other, both chains record the event and can be cross-verified
- **Structured data model** enabling automated compliance monitoring, anomaly detection, and reporting
- **Conformance levels** that scale with risk: Level 1 (hash chain) for basic logging, Level 2 (signed chain) for organizational attribution, Level 3 (witnessed chain) for high-risk deployments requiring independent attestation

## What AHP Does NOT Cover

- **Risk management systems** (Article 9) — AHP is logging infrastructure, not a risk assessment framework. You still need a documented risk management process.
- **Bias testing and fairness evaluation** — AHP records what agents do, not whether their outputs are fair or unbiased.
- **System-level transparency documentation** (Article 13 instructions for use) — AHP provides operational data but does not generate user-facing capability documentation or instructions.
- **Data governance and training data quality** (Article 10) — AHP covers runtime actions, not training data provenance.
- **Accuracy and robustness testing** (Article 15) — AHP records performance metrics but does not implement testing frameworks.
- **Cybersecurity measures** (Article 15) — AHP provides tamper-evidence for logs but is not a security product.
- **Conformity assessment** — AHP supports the evidence-gathering needed for conformity assessment but does not perform the assessment itself.
- **Intervention mechanisms** — AHP documents that human overrides occurred but does not implement kill switches or override controls.

---

## Getting Started

**Step 1: Assess your risk category.** Determine whether your AI agent deployment falls under Annex III (high-risk) of the EU AI Act. If it does, you need compliant logging infrastructure before August 2026. AHP is designed for this use case.

**Step 2: Deploy AHP at the appropriate conformance level.** For most high-risk deployments, start with Level 2 (signed chain) to establish organizational authorship of audit logs. For deployments where independent verification is critical (regulated industries, multi-party systems), target Level 3 (witnessed chain). Enable `authorization_recording` and `inference_recording` in your AHP configuration to capture human oversight and LLM decision trails.

**Step 3: Integrate AHP data into your compliance program.** Connect AHP's export pipeline (OTLP, JSONL) to your existing compliance monitoring, SIEM, or GRC platform. Use AHP's structured records to generate Article 12 logging reports, Article 14 human oversight evidence, and inputs to your Article 9 risk management documentation. Configure retention policies to meet the minimum 6-month requirement.

---

*For the AHP specification, see [agent-history-protocol-spec.md](../agent-history-protocol-spec.md). AHP is open source under Apache 2.0.*

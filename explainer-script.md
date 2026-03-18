# AHP Interactive Explainer — Script & Animation Design

## Audience
College graduate. Smart but has never heard of hash chains, Ed25519, or protocol specs. Knows what AI assistants are (uses ChatGPT/Claude). Understands basic programming concepts.

## Narrative Strategy
- Tell a STORY, not a lecture
- Start with a problem they can feel ("your AI did something wrong")
- Each step introduces ONE concept with ONE real-world analogy
- Complex terms get hover-tooltips with plain English definitions
- Build understanding progressively — each step needs the previous one

---

## Step 1: The Problem

**Title:** Your AI agent just did something wrong. Can you prove what happened?

**Story:** Your AI email assistant goes rogue — deletes emails, sends unauthorized replies, books wrong meetings. You ask "what happened?" and there's no answer. No log. No history. No proof.

**Analogy:** Airplanes have flight recorders (black boxes). AI agents have nothing.

**Key takeaway:** There's no standard way to record what AI agents do.

**Animation:**
- Center: A glowing box labeled "AI Agent" — gently pulsing
- Scattered around it: 5 action blocks floating randomly ("Delete email", "Send reply", "Book meeting", etc.) — some red (bad actions), some blue (normal)
- No connections between them — visual chaos
- After a pause: Question marks appear below, text: "No record. No order. No proof."
- Camera: Straight on, slight above angle, static
- Feeling: Disordered, concerning

---

## Step 2: The Solution — What AHP Does

**Title:** AHP: A flight recorder for AI agents

**Story:** AHP creates a record every time the agent does something. Each record is small (~200 bytes) and chained to the previous one — so nobody can secretly change the history.

**Analogy:** A receipt from every action. Numbered in order. Each receipt has a seal connecting it to the previous one.

**Key term introduced:** "chained together" (hover tooltip explains hash chain in plain English)

**Animation:**
- Left: AI Agent box
- Right: 5 record blocks appearing one by one, sliding in from left to right
- Each record is color-coded by type:
  - Cyan: BOOT (startup)
  - Purple: INFERENCE (thinking)
  - Blue: TOOL_CALL (action)
  - Green: CHECKPOINT (summary)
- Small connecting lines appear between them as each record arrives
- Sequence numbers (#1, #2, #3...) appear below each
- Each block scales in with a slight bounce animation
- Text below: "Each action = one record, chained in order"
- Camera: Side view, watching the chain grow left to right
- Feeling: Orderly, building, progressive

---

## Step 3: The Hash Chain — How Tampering Becomes Impossible

**Title:** The Hash Chain: How tampering becomes impossible

**Story:** Each record has a SHA-256 hash (fingerprint) of the previous record. Change any record and every fingerprint after it breaks.

**Analogy:** Each page in a notebook has a PHOTO of the previous page taped to it. Replace a page and the photo on the next page won't match.

**Key term introduced:** SHA-256 hash (hover tooltip: "a mathematical function that turns any data into a unique 64-character fingerprint. Change one letter and the fingerprint is completely different.")

**Animation:**
- Three large record blocks arranged left to right with clear space between
- Green text on each showing "prev_hash: SHA256(Record N)"
- First record shows "prev_hash: 0x0000...0000 (genesis — all zeros)"
- Green connecting lines with "SHA-256" label between them
- After 1.5s pause: amber text appears below: "If Record 2 is changed..."
- Red text: "Record 3's prev_hash won't match anymore!"
- A red pulsing sphere appears on the broken link
- Camera: Straight on, eye level
- Feeling: Clear cause-and-effect, "aha moment"

---

## Step 4: Agent Reasoning — Not Just WHAT But WHY

**Title:** Not just WHAT the agent did — but WHY

**Story:** Most logging records actions. AHP also records the LLM thinking step (INFERENCE). Each tool call points back to the inference that caused it, building a decision tree.

**Analogy:** Not just "the suspect was at the scene" but "here's the full interrogation transcript showing their reasoning."

**Key term introduced:** INFERENCE record (hover tooltip: "captures the LLM API call — what prompt was sent, what response came back, which model was used")

**Animation:**
- Tree layout (top to bottom):
  - Top: Large purple INFERENCE node ("User: fix the bug")
  - Three blue TOOL_CALL nodes branching below it (grep, read_file, read_file)
  - Below: Another INFERENCE node ("Found bug on line 42")
  - Two more TOOL_CALLs branching from it (edit, run tests)
- Curved connecting lines from parent to children
- Nodes appear top-down with slight delays
- INFERENCE nodes are larger than TOOL_CALL nodes (visually more important)
- Label: "parent_action_id" with subtitle "(who caused me)"
- Camera: Slightly above, looking down at the tree
- Feeling: Organized, logical, "of course you'd want this"

---

## Step 5: Evidence Store — Content Behind the Hashes

**Title:** The chain has fingerprints. But where's the actual data?

**Story:** The chain stores HASHES (fingerprints) — not the actual content. The content goes into a separate evidence store, linked by hash. The chain proves what happened. The evidence proves what the content was.

**Analogy:** Bank statement (chain) vs. actual receipts (evidence). The statement lists transactions. The receipts have the details.

**Key term introduced:** evidence store (no tooltip needed — explained inline)

**Animation:**
- Split layout:
  - Left column: "CHAIN" header, 3 stacked record blocks with green hash text on each
  - Right column: "EVIDENCE STORE" header, 3 file-shaped blocks with hash name + content preview
- Dashed lines connecting each chain record to its evidence file (matching by hash)
- Blocks appear with staggered timing (chain first, then evidence, then connections)
- Bottom text: "Linked by hash: re-hash the file, compare to chain"
- Camera: Straight on, wide enough to see both columns
- Feeling: Two-layer clarity, "that makes sense"

---

## Step 6: PII Filtering — Sensitive Data Never Enters the Record

**Title:** PII Filtering: Sensitive data never enters the record

**Story:** What if input contains a credit card number? PII filters run BEFORE hashing. The credit card number never touches the chain.

**Analogy:** (Not needed — the pipeline diagram IS the explanation)

**Key term introduced:** PII filters (hover tooltip: "pattern matching that finds and replaces sensitive data like credit card numbers, SSNs, or API keys with placeholders like [REDACTED:CC]")

**Animation:**
- Left-to-right pipeline of 4 stages:
  1. Red box: "Raw Input" — '"Charge 4111-2222-3333-4444"'
  2. Amber box: "PII Filter" — "credit card pattern matched"
  3. Green box: "Redacted" — '"Charge [REDACTED:CC]"'
  4. Blue box: "Hash + Store" — "SHA-256 → chain"
- Arrows between stages appearing one by one
- Each stage appears with a slight delay after the previous
- Bottom text: "Credit card number NEVER enters the chain"
- Camera: Straight on, eye level
- Feeling: Pipeline clarity, relief ("my data is safe")

---

## Step 7: The Trust Problem

**Title:** But wait — who's watching the watcher?

**Story:** The hash chain is created by the operator. If they cheat, they could forge the whole thing. A diary you wrote yourself proves nothing to a skeptic. This is why AHP has three trust levels.

**Analogy:** Writing your own diary vs. having a notary witness it.

**Animation:**
- Three growing horizontal bars, stacked vertically:
  - Blue bar (shortest): "Level 1: Hash Chain" — "Proves records weren't changed after writing"
  - Purple bar (medium): "Level 2: + Signatures" — "Proves WHO wrote the records"
  - Green bar (longest): "Level 3: + Witnesses" — "Proves to OUTSIDERS what happened"
- Each bar grows from left with a smooth animation, appearing one after another
- Bottom text: "Each level ADDS to the previous one" / "More trust = harder to cheat"
- Camera: Straight on
- Feeling: Progressive, building confidence

---

## Step 8: Witnesses — A Notary for Your AI Agent

**Title:** Level 3: A notary for your AI agent

**Story:** The agent sends periodic checkpoints to an independent witness service. The witness signs a receipt. Now the agent can't rewrite history before the checkpoint.

**Analogy:** Notary public — you bring a document, notary stamps it with their seal and date.

**Key term introduced:** checkpoint (hover tooltip: "a package containing the chain hash, sequence number, timestamp, and agent's digital signature, sent to an independent witness")

**Animation:**
- Left: Blue "Agent" box with a mini chain inside (3 small blocks)
- Right: Green "Witness" box labeled "(independent)"
- After delay:
  - Top arrow path: green sphere travels from agent to witness
  - Label: "checkpoint: My chain has 500 records, hash = a7f3..."
  - Sphere changes to gold on return trip (receipt)
  - Bottom arrow path: gold sphere travels back
  - Label: "receipt: Confirmed at 3:42pm — here's my signature"
- Sphere loops continuously (checkpoint → receipt → checkpoint...)
- Bottom text: "Agent can't rewrite history before record #500"
- Camera: Straight on, both sides visible
- Feeling: Back-and-forth trust establishment, "that's clever"

---

## Step 9: Configuration

**Title:** Not every agent needs the same recording

**Story:** Different agents have different policies. A customer support bot needs full recording. A code assistant needs minimal logging. One config file controls everything.

**Animation:**
- Center: Amber "ahp.yaml" box, gently pulsing
- Four corners: Agent boxes with different colors:
  - Green: "customer-support" (Level 3, full recording)
  - Blue: "code-assistant" (Level 1, no reasoning)
  - Green: "financial-tx" (Level 3, full + 2 witnesses)
  - Blue: "data-pipeline" (Level 1, hashes only)
- Lines radiating from center config to each agent
- Each agent box shows its level and recording mode
- Bottom text: "Different agents, different policies"
- Camera: Overhead-ish angle
- Feeling: Organized, practical

---

## Step 10: The Big Picture

**Title:** What AHP makes possible

**Story:** When every agent records its actions in one standard format: debugging, compliance, incident response, accountability. AHP is open protocol, Apache 2.0, anyone can implement it.

**Animation:**
- Center: Large pulsing blue sphere labeled "AHP"
- Five smaller spheres orbiting at distance, each representing a concept:
  - Blue: Hash Chain
  - Purple: Reasoning
  - Green: Evidence
  - Emerald: Witnesses
  - Amber: Privacy
- Lines connecting each to center
- Each sphere gently floating
- Bottom text: "Open protocol. Apache 2.0. Anyone can implement it."
- Camera: Slightly above, looking at the constellation
- Feeling: Complete, unified, aspirational

---

## Visual Design System

**Color palette:**
| Element | Color | Hex |
|---------|-------|-----|
| Background | Near black | #0b0d14 |
| Primary (action, links) | Soft blue | #7aa2f7 |
| Inference/reasoning | Purple | #bb9af7 |
| Hashes/evidence | Green | #9ece6a |
| Warnings/filters | Amber | #e0af68 |
| Errors/breaks | Red | #e05050 |
| Witness/trust | Emerald | #68ddb5 |
| Secondary text | Gray-blue | #6a7090 |

**Typography:**
- Titles: 26px, bold, white
- Body: 15px, regular, gray-blue (#9aa0b8)
- Code/hashes: Monospace, 13px, light blue (#c0c8e0)
- Labels in 3D: Sans-serif, 10-22px depending on importance

**Interaction:**
- Arrow keys / spacebar to navigate
- Click progress dots to jump
- Hover on purple terms to see definition tooltips
- Orbit/zoom the 3D scene with mouse (subtle, not primary)

**Card design:**
- Bottom-left panel with glass morphism (frosted glass effect)
- Max width 680px
- Subtitle (uppercase, blue, small) → Title (large, white) → Body (readable) → Nav buttons
- Smooth fade transition between steps

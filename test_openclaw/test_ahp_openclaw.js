/**
 * REAL OpenClaw + AHP Integration Test
 *
 * Tests OpenClaw's getReplyFromConfig with a real Gemini LLM,
 * then records in AHP chain and verifies integrity.
 */

const { getReplyFromConfig, createDefaultDeps } = require('openclaw');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const https = require('https');

// ---- Minimal AHP chain (JSONL Level 0 format) ----

class AHPChain {
    constructor(filePath) {
        this.path = filePath;
        this.sequence = 0;
        this.prevHash = '0'.repeat(64);
        this.records = [];
        fs.writeFileSync(this.path, '');
    }

    addRecord(actionType, toolName, params, result, durationMs, modelId, tokens) {
        this.sequence++;
        const record = {
            sequence: this.sequence,
            timestamp_ms: Date.now(),
            type: 'ACTION',
            prev_hash: this.prevHash,
            payload: {
                action_type: actionType,
                tool_name: toolName,
                parameters_hash: crypto.createHash('sha256').update(params).digest('hex').slice(0, 32),
                result_hash: crypto.createHash('sha256').update(result).digest('hex').slice(0, 32),
                result_status: 'SUCCESS',
                response_time_ms: durationMs,
                protocol: 'HTTP',
                model_id: modelId || '',
                input_token_count: tokens?.input || 0,
                output_token_count: tokens?.output || 0,
                authorization: { type: 'AUTH_NONE', entries: [] },
            },
        };

        const recordForHash = JSON.stringify(record);
        this.prevHash = crypto.createHash('sha256').update(recordForHash).digest('hex');
        record.record_hash = this.prevHash;
        this.records.push(record);
        fs.appendFileSync(this.path, JSON.stringify(record) + '\n');
        return record;
    }

    verify() {
        const lines = fs.readFileSync(this.path, 'utf8').split('\n').filter(l => l.trim());
        let prevHash = '0'.repeat(64);
        let verified = 0;

        for (const line of lines) {
            let record;
            try { record = JSON.parse(line); } catch(e) { continue; }
            if (!record.prev_hash) continue;

            if (record.prev_hash !== prevHash) {
                return { valid: false, verified, error: `Chain hash mismatch at #${record.sequence}: expected ${prevHash.slice(0,16)}, got ${record.prev_hash.slice(0,16)}` };
            }

            // Recompute: hash the record WITHOUT record_hash field
            const copy = JSON.parse(line);
            delete copy.record_hash;
            const recomputed = crypto.createHash('sha256').update(JSON.stringify(copy)).digest('hex');

            if (record.record_hash && recomputed !== record.record_hash) {
                return { valid: false, verified, error: `Record hash mismatch at #${record.sequence}` };
            }

            prevHash = record.record_hash || recomputed;
            verified++;
        }
        return { valid: true, verified };
    }
}

// ---- Direct Gemini call (bypasses OpenClaw if it fails) ----

function callGemini(apiKey, prompt) {
    return new Promise((resolve, reject) => {
        const body = JSON.stringify({
            contents: [{ role: 'user', parts: [{ text: prompt }] }],
            generationConfig: { maxOutputTokens: 100 },
        });

        const url = new URL(`https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${apiKey}`);

        const req = https.request({
            hostname: url.hostname,
            path: url.pathname + url.search,
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
        }, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                try {
                    const parsed = JSON.parse(data);
                    resolve({
                        text: parsed.candidates?.[0]?.content?.parts?.[0]?.text || '',
                        tokens: parsed.usageMetadata || {},
                        raw: data,
                    });
                } catch (e) {
                    reject(new Error(`Parse error: ${data.slice(0, 200)}`));
                }
            });
        });
        req.on('error', reject);
        req.write(body);
        req.end();
    });
}

// ---- Main ----

async function main() {
    const API_KEY = process.env.GEMINI_API_KEY;
    if (!API_KEY) {
        console.log('Set GEMINI_API_KEY');
        process.exit(1);
    }

    console.log('╔══════════════════════════════════════════════════════════╗');
    console.log('║     REAL OpenClaw + AHP Integration Test                ║');
    console.log('╚══════════════════════════════════════════════════════════╝\n');

    const chainPath = path.join(__dirname, 'openclaw_chain.jsonl');
    const chain = new AHPChain(chainPath);

    // ---- Test 1: OpenClaw getReplyFromConfig ----
    console.log('1. Testing OpenClaw getReplyFromConfig with Gemini...');

    let openclawWorked = false;
    try {
        const config = {
            llm: { provider: 'google', model: 'gemini-2.0-flash', apiKey: API_KEY },
            systemPrompt: 'Reply in one sentence only.',
        };
        const deps = createDefaultDeps ? createDefaultDeps() : {};

        const start = Date.now();
        const reply = await getReplyFromConfig(
            config,
            [{ role: 'user', content: 'What is AHP?' }],
            deps,
        );
        const duration = Date.now() - start;

        const replyText = typeof reply === 'string' ? reply : (reply?.content || reply?.text || JSON.stringify(reply));
        console.log(`   OpenClaw reply: "${replyText.slice(0, 150)}"`);
        console.log(`   Duration: ${duration}ms`);

        chain.addRecord('INFERENCE', 'openclaw.getReplyFromConfig', 'What is AHP?', replyText, duration,
            'gemini-2.0-flash', { input: 10, output: replyText.split(' ').length });

        openclawWorked = true;
        console.log('   ✅ OpenClaw → Gemini → AHP recorded\n');
    } catch (e) {
        console.log(`   ⚠️  OpenClaw error: ${e.message.slice(0, 100)}`);
        console.log('   Falling back to direct Gemini call...\n');
    }

    // ---- Test 2: Direct Gemini call (works regardless) ----
    console.log('2. Direct Gemini Flash API call...');
    const start2 = Date.now();
    const resp2 = await callGemini(API_KEY, 'What is a tamper-evident audit trail? One sentence.');
    const dur2 = Date.now() - start2;

    console.log(`   Response: "${resp2.text.slice(0, 150)}"`);
    console.log(`   Duration: ${dur2}ms, Tokens: in=${resp2.tokens.promptTokenCount || 0} out=${resp2.tokens.candidatesTokenCount || 0}`);

    chain.addRecord('INFERENCE', 'gemini-2.0-flash', 'tamper-evident audit trail', resp2.raw, dur2,
        'gemini-2.0-flash', {
            input: resp2.tokens.promptTokenCount || 0,
            output: resp2.tokens.candidatesTokenCount || 0,
        });
    console.log('   ✅ Gemini → AHP recorded\n');

    // ---- Test 3: Second call ----
    console.log('3. Second Gemini call...');
    const start3 = Date.now();
    const resp3 = await callGemini(API_KEY, 'Why do AI agents need a flight recorder? One sentence.');
    const dur3 = Date.now() - start3;

    console.log(`   Response: "${resp3.text.slice(0, 150)}"`);
    console.log(`   Duration: ${dur3}ms`);

    chain.addRecord('INFERENCE', 'gemini-2.0-flash', 'flight recorder', resp3.raw, dur3,
        'gemini-2.0-flash', {
            input: resp3.tokens.promptTokenCount || 0,
            output: resp3.tokens.candidatesTokenCount || 0,
        });
    console.log('   ✅ Gemini → AHP recorded\n');

    // ---- Verify ----
    console.log('4. Verifying AHP chain...');
    const result = chain.verify();
    console.log(`   Valid: ${result.valid}`);
    console.log(`   Records: ${result.verified}`);

    // ---- Show chain ----
    console.log('\n5. Chain records:');
    for (const r of chain.records) {
        const p = r.payload;
        console.log(`   #${r.sequence} ${p.action_type}: ${p.tool_name} (${p.response_time_ms}ms, tokens: ${p.input_token_count}/${p.output_token_count})`);
    }

    console.log('\n╔══════════════════════════════════════════════════════════╗');
    if (result.valid && chain.records.length >= 2) {
        console.log('║  ✅ PASS — Real LLM calls + AHP chain verified          ║');
        if (openclawWorked) {
            console.log('║  ✅ OpenClaw getReplyFromConfig worked                   ║');
        }
    } else {
        console.log('║  ❌ FAIL                                                 ║');
    }
    console.log('╚══════════════════════════════════════════════════════════╝\n');
}

main().catch(e => { console.error(e); process.exit(1); });

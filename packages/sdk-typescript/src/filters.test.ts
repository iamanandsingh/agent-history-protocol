/**
 * Tests for Filter / FilterPipeline — regex matching, scope, hashing, presets.
 */

import { strict as assert } from "assert";
import { test, describe } from "node:test";

import { Filter, FilterPipeline, PRESETS } from "./filters";

describe("Filter.apply", () => {
  test("replaces single match and reports didMatch", () => {
    const f = new Filter("digits", "\\d+", "[N]");
    const [out, matched] = f.apply("order 12345 done");
    assert.equal(out, "order [N] done");
    assert.equal(matched, true);
  });

  test("returns input unchanged when no match", () => {
    const f = new Filter("digits", "\\d+", "[N]");
    const [out, matched] = f.apply("no numbers here");
    assert.equal(out, "no numbers here");
    assert.equal(matched, false);
  });

  test("global flag replaces all occurrences", () => {
    const f = new Filter("vowel", "[aeiou]", "*");
    const [out] = f.apply("hello world");
    assert.equal(out, "h*ll* w*rld");
  });

  test("apply is repeatable (lastIndex reset)", () => {
    const f = new Filter("digits", "\\d+", "[N]");
    const [a] = f.apply("a1 b2");
    const [b] = f.apply("a1 b2");
    assert.equal(a, b);
  });
});

describe("FilterPipeline scope", () => {
  test("filter scoped to 'parameters' applies in parameters scope", () => {
    const pipe = new FilterPipeline([
      new Filter("d", "\\d+", "[N]", ["parameters"]),
    ]);
    const [out, redacted] = pipe.apply(
      new TextEncoder().encode("id=42"),
      "parameters",
    );
    assert.equal(new TextDecoder().decode(out), "id=[N]");
    assert.equal(redacted, true);
  });

  test("filter scoped to 'parameters' does NOT apply in results scope", () => {
    const pipe = new FilterPipeline([
      new Filter("d", "\\d+", "[N]", ["parameters"]),
    ]);
    const [out, redacted] = pipe.apply(
      new TextEncoder().encode("id=42"),
      "results",
    );
    assert.equal(new TextDecoder().decode(out), "id=42");
    assert.equal(redacted, false);
  });

  test("filter with scope 'all' applies in any scope", () => {
    const pipe = new FilterPipeline([
      new Filter("d", "\\d+", "[N]", ["all"]),
    ]);
    const [, ra] = pipe.apply(new TextEncoder().encode("x=1"), "parameters");
    const [, rb] = pipe.apply(new TextEncoder().encode("x=1"), "results");
    assert.equal(ra, true);
    assert.equal(rb, true);
  });
});

describe("FilterPipeline edge cases", () => {
  test("payload over MAX_FILTER_SIZE is passed through unchanged", () => {
    const pipe = new FilterPipeline([new Filter("d", "\\d+", "[N]")]);
    const big = new Uint8Array(FilterPipeline.MAX_FILTER_SIZE + 1);
    big[0] = 0x31; // '1'
    const [out, redacted] = pipe.apply(big, "parameters");
    assert.equal(out.length, big.length);
    assert.equal(redacted, false);
  });

  test("non-utf8 binary payload is passed through unchanged", () => {
    const pipe = new FilterPipeline([new Filter("d", "\\d+", "[N]")]);
    const bin = new Uint8Array([0xff, 0xfe, 0xfd, 0xfc]);
    const [out, redacted] = pipe.apply(bin, "parameters");
    assert.deepEqual(Array.from(out), Array.from(bin));
    assert.equal(redacted, false);
  });
});

describe("FilterPipeline.hashPayload", () => {
  test("returns 16-byte hash and filtered bytes", () => {
    const pipe = new FilterPipeline([new Filter("d", "\\d+", "[N]")]);
    const [hash, filtered, redacted] = pipe.hashPayload(
      new TextEncoder().encode("v=42"),
      "parameters",
    );
    assert.equal(hash.length, 16);
    assert.equal(new TextDecoder().decode(filtered), "v=[N]");
    assert.equal(redacted, true);
  });
});

describe("FilterPipeline.configHash", () => {
  test("empty pipeline hashes to 32 zero bytes", () => {
    const pipe = new FilterPipeline();
    const h = pipe.configHash();
    assert.equal(h.length, 32);
    assert.ok(h.every((b) => b === 0));
  });

  test("non-empty pipeline produces stable non-zero hash", () => {
    const pipeA = new FilterPipeline([new Filter("d", "\\d+", "[N]")]);
    const pipeB = new FilterPipeline([new Filter("d", "\\d+", "[N]")]);
    assert.deepEqual(Array.from(pipeA.configHash()), Array.from(pipeB.configHash()));
    assert.ok(pipeA.configHash().some((b) => b !== 0));
  });
});

describe("PRESETS", () => {
  test("pci preset redacts a credit card number", () => {
    const pipe = new FilterPipeline(null, ["pci"]);
    const [out] = pipe.apply(
      new TextEncoder().encode("card 4111-1111-1111-1111 ok"),
      "parameters",
    );
    assert.match(new TextDecoder().decode(out), /\[REDACTED:CC\]/);
  });

  test("pii-us preset redacts an SSN", () => {
    const pipe = new FilterPipeline(null, ["pii-us"]);
    const [out] = pipe.apply(
      new TextEncoder().encode("SSN 123-45-6789"),
      "parameters",
    );
    assert.match(new TextDecoder().decode(out), /\[REDACTED:SSN\]/);
  });

  test("credentials preset redacts a Bearer token in any scope", () => {
    const pipe = new FilterPipeline(null, ["credentials"]);
    const [out] = pipe.apply(
      new TextEncoder().encode("Authorization: Bearer abc123XYZ=="),
      "results",
    );
    assert.match(new TextDecoder().decode(out), /Bearer \[REDACTED:TOKEN\]/);
  });

  test("PRESETS exposes the documented preset names", () => {
    for (const name of ["pci", "pii-us", "pii-eu", "credentials", "hipaa"]) {
      assert.ok(name in PRESETS, `missing preset: ${name}`);
    }
  });
});

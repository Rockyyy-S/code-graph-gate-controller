import assert from "node:assert/strict";
import test from "node:test";
import { canonicalizeJson, sha256CanonicalJson } from "../lib/canonical-json.mjs";

test("canonical JSON 复现固定向量", () => {
  assert.equal(canonicalizeJson({ b: 2, a: 1 }), '{"a":1,"b":2}');
  assert.equal(
    sha256CanonicalJson({ b: 2, a: 1 }),
    "43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777",
  );
});

test("canonical JSON 拒绝非 JSON 值和非法 Unicode", () => {
  for (const value of [{ value: undefined }, [Number.NaN], { value: 1n }, { value: "\ud800" }]) {
    assert.throws(() => canonicalizeJson(value), /JCS/u);
  }
});

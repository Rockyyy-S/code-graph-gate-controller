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

test("canonical JSON 数组拒绝访问器、隐藏字段和自定义原型且不执行 getter", () => {
  let getterCalls = 0;
  const accessor = [1];
  Object.defineProperty(accessor, "0", {
    enumerable: true,
    get() {
      getterCalls += 1;
      return 1;
    },
  });
  const symbolField = [1];
  Object.defineProperty(symbolField, Symbol("hidden"), { value: 2 });
  const hiddenElement = [1];
  Object.defineProperty(hiddenElement, "0", { enumerable: false, value: 1 });
  const customPrototype = [1];
  Object.setPrototypeOf(customPrototype, Object.create(Array.prototype));

  for (const value of [accessor, symbolField, hiddenElement, customPrototype]) {
    assert.throws(() => canonicalizeJson(value), /JCS/u);
  }
  assert.equal(getterCalls, 0);
});

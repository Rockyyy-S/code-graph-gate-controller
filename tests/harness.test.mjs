import assert from "node:assert/strict";
import test from "node:test";
import { evaluateApplicability } from "../lib/harness.mjs";

test("triggerPaths 缺失时 always applicable", () => {
  assert.equal(evaluateApplicability({ gateId: "type" }, []), "required");
});

test("受限 POSIX glob 区分 required 与 not-applicable", () => {
  const definition = { gateId: "type", triggerPaths: ["packages/**", "scripts/*.mjs"] };
  assert.equal(evaluateApplicability(definition, ["packages/contracts/src/index.ts"]), "required");
  assert.equal(evaluateApplicability(definition, ["docs/readme.md"]), "not-applicable");
});

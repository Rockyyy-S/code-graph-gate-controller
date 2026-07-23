import assert from "node:assert/strict";
import test from "node:test";
import {
  didRequiredBlockingGatesPass,
  evaluateApplicability,
} from "../lib/harness.mjs";
import { parseNameStatusZ } from "../lib/git-context.mjs";

test("triggerPaths 缺失时 always applicable", () => {
  assert.equal(evaluateApplicability({ gateId: "type" }, []), "required");
});

test("受限 POSIX glob 区分 required 与 not-applicable", () => {
  const definition = { gateId: "type", triggerPaths: ["packages/**", "scripts/*.mjs"] };
  assert.equal(evaluateApplicability(definition, ["packages/contracts/src/index.ts"]), "required");
  assert.equal(evaluateApplicability(definition, ["docs/readme.md"]), "not-applicable");
});

test("globstar 匹配零级和多级目录", () => {
  const definition = { gateId: "type", triggerPaths: ["src/**/*.ts"] };
  assert.equal(evaluateApplicability(definition, ["src/a.ts"]), "required");
  assert.equal(evaluateApplicability(definition, ["src/nested/a.ts"]), "required");
});

test("NUL name-status 对非法 UTF-8 路径 fail closed", () => {
  assert.throws(
    () => parseNameStatusZ(Buffer.from([0x41, 0x00, 0xff, 0x00])),
    /UTF-8/u,
  );
  assert.throws(
    () => parseNameStatusZ(Buffer.from("A\0file.ts", "utf8")),
    /NUL|截断/u,
  );
});

test("non-blocking gate 失败不改变 required blocking 结论", () => {
  const evidence = [
    { gateId: "required", status: "pass" },
    { gateId: "advisory", status: "fail" },
  ];

  assert.equal(
    didRequiredBlockingGatesPass(evidence, new Set(["required"])),
    true,
  );
  assert.equal(
    didRequiredBlockingGatesPass(evidence, new Set(["required", "advisory"])),
    false,
  );
});

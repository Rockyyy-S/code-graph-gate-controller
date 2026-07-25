import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";
import {
  GATE_HARNESS_ARGUMENT_NAMES_V2,
  parseArguments,
} from "../bin/produce-gate-evidence.mjs";

/** 构造 GateHarness V2 的完整参数向量。 */
function createArguments(overrides = {}) {
  const values = {
    "--artifact-directory": path.resolve("artifacts"),
    "--base-oid": "a".repeat(40),
    "--candidate-root": path.resolve("candidate"),
    "--controller-repository": "Rockyyy-S/code-graph-gate-controller",
    "--gate-gid": "20001",
    "--gate-home": path.resolve("gate-home"),
    "--gate-temp-directory": path.resolve("gate-tmp"),
    "--gate-uid": "20001",
    "--head-oid": "b".repeat(40),
    "--object-format": "sha1",
    "--provider-repository-id": "1303415307",
    "--proposed-record-directory": path.resolve("trusted/proposed"),
    "--pull-number": "0",
    "--trusted-record": path.resolve("trusted/registry.json"),
    "--workflow-file": "produce-gate-evidence.yml",
    "--workflow-sha": "c".repeat(40),
    ...overrides,
  };
  return GATE_HARNESS_ARGUMENT_NAMES_V2.flatMap((name) => [name, values[name]]);
}

test("GateHarness V2 参数集合封闭且支持 push/PR 安全整数边界", () => {
  assert.equal(GATE_HARNESS_ARGUMENT_NAMES_V2.length, 16);
  assert.equal(parseArguments(createArguments()).pullNumber, 0);
  assert.equal(
    parseArguments(createArguments({ "--pull-number": "42" })).pullNumber,
    42,
  );
  assert.equal(
    parseArguments(
      createArguments({ "--pull-number": String(Number.MAX_SAFE_INTEGER) }),
    ).pullNumber,
    Number.MAX_SAFE_INTEGER,
  );
  assert.throws(
    () => parseArguments(createArguments({ "--pull-number": "-1" })),
    /非负整数/u,
  );
  assert.throws(
    () =>
      parseArguments(
        createArguments({ "--pull-number": String(Number.MAX_SAFE_INTEGER + 1) }),
      ),
    /安全整数/u,
  );
});

test("GateHarness V2 拒绝缺失、未知和相对 proposed 目录", () => {
  assert.throws(() => parseArguments(createArguments().slice(0, -2)), /缺失/u);
  assert.throws(
    () => parseArguments([...createArguments(), "--unknown", "value"]),
    /未知字段/u,
  );
  assert.throws(
    () =>
      parseArguments(
        createArguments({ "--proposed-record-directory": "trusted/proposed" }),
      ),
    /绝对路径/u,
  );
});

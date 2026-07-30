import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";
import {
  GATE_HARNESS_PORTABLE_ARGUMENT_NAMES_V3,
  GATE_HARNESS_PORTABLE_ARGUMENT_NAMES_V4,
  GATE_HARNESS_WIN32_ARGUMENT_NAMES_V3,
  GATE_HARNESS_WIN32_ARGUMENT_NAMES_V4,
  parseArguments,
  parseArgumentsV3,
  parseMergeArguments,
} from "../bin/produce-gate-evidence.mjs";

/** 构造 GateHarness V4 的完整平台分区参数向量。 */
function createArguments(overrides = {}) {
  const values = {
    "--artifact-directory": path.resolve("artifacts"),
    "--base-oid": "a".repeat(40),
    "--candidate-root": path.resolve("candidate"),
    "--controller-repository": "Rockyyy-S/code-graph-gate-controller",
    "--execution-partition": "portable",
    "--gate-gid": "20001",
    "--gate-home": path.resolve("gate-home"),
    "--gate-temp-directory": path.resolve("gate-tmp"),
    "--gate-uid": "20001",
    "--harness-contract-version": "4",
    "--head-oid": "b".repeat(40),
    "--object-format": "sha1",
    "--provider-repository-id": "1303415307",
    "--proposed-record-directory": path.resolve("trusted/proposed"),
    "--pull-number": "0",
    "--trusted-record": path.resolve("trusted/registry.json"),
    "--trusted-pnpm-executable": path.resolve("trusted/pnpm.exe"),
    "--workflow-file": "produce-gate-evidence.yml",
    "--workflow-sha": "c".repeat(40),
    ...overrides,
  };
  const argumentNames = values["--execution-partition"] === "win32"
    ? GATE_HARNESS_WIN32_ARGUMENT_NAMES_V4
    : GATE_HARNESS_PORTABLE_ARGUMENT_NAMES_V4;
  return argumentNames.flatMap((name) => [name, values[name]]);
}

/** 构造不可变 GateHarness V3 的历史参数向量。 */
function createArgumentsV3(overrides = {}) {
  const values = {
    "--artifact-directory": path.resolve("artifacts"),
    "--base-oid": "a".repeat(40),
    "--candidate-root": path.resolve("candidate"),
    "--controller-repository": "Rockyyy-S/code-graph-gate-controller",
    "--execution-partition": "portable",
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
  const argumentNames = values["--execution-partition"] === "win32"
    ? GATE_HARNESS_WIN32_ARGUMENT_NAMES_V3
    : GATE_HARNESS_PORTABLE_ARGUMENT_NAMES_V3;
  return argumentNames.flatMap((name) => [name, values[name]]);
}

test("GateHarness V4 参数集合封闭且支持 push/PR 安全整数边界", () => {
  assert.equal(GATE_HARNESS_PORTABLE_ARGUMENT_NAMES_V3.length, 17);
  assert.equal(GATE_HARNESS_WIN32_ARGUMENT_NAMES_V3.length, 15);
  assert.equal(GATE_HARNESS_PORTABLE_ARGUMENT_NAMES_V4.length, 18);
  assert.equal(GATE_HARNESS_WIN32_ARGUMENT_NAMES_V4.length, 17);
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

test("GateHarness V4 拒绝缺失、未知、错误分区和相对专用路径", () => {
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
  assert.throws(
    () => parseArguments(createArguments({ "--execution-partition": "linux" })),
    /缺失|未知/u,
  );
  assert.throws(
    () =>
      parseArguments(
        createArguments({
          "--execution-partition": "win32",
          "--trusted-pnpm-executable": "pnpm.exe",
        }),
      ),
    /绝对路径/u,
  );
  assert.throws(
    () => parseArguments(createArguments({ "--harness-contract-version": "3" })),
    /缺失|未知/u,
  );
});

test("V3 解析边界保持不变且 V4 不静默接受历史参数", () => {
  assert.equal(parseArgumentsV3(createArgumentsV3()).executionPartition, "portable");
  assert.equal(
    parseArgumentsV3(createArgumentsV3({ "--execution-partition": "win32" }))
      .trustedPnpmExecutable,
    undefined,
  );
  assert.throws(() => parseArguments(createArgumentsV3()), /缺失|未知/u);
});

test("Win32 V4 强制专用 launcher、拒绝 Unix UID/GID 且合并输入必须是绝对路径数组", () => {
  const win32 = parseArguments(createArguments({ "--execution-partition": "win32" }));
  assert.equal(win32.executionPartition, "win32");
  assert.equal(win32.gateUid, undefined);
  assert.equal(win32.gateGid, undefined);
  assert.equal(win32.trustedPnpmExecutable, path.resolve("trusted/pnpm.exe"));

  const artifactPaths = [path.resolve("portable.json"), path.resolve("win32.json")];
  assert.deepEqual(
    parseMergeArguments([
      "--artifact-directory",
      path.resolve("merged"),
      "--input-artifacts-json",
      JSON.stringify(artifactPaths),
    ]),
    {
      artifactDirectory: path.resolve("merged"),
      artifactPaths,
    },
  );
  assert.throws(
    () => parseMergeArguments([
      "--artifact-directory",
      path.resolve("merged"),
      "--input-artifacts-json",
      JSON.stringify(["relative.json", path.resolve("win32.json")]),
    ]),
    /绝对路径/u,
  );
});

import assert from "node:assert/strict";
import test from "node:test";
import {
  createGateEnvironment,
  createTrustedGateArguments,
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

test("pnpm gate 禁止执行未绑定的 pre/post lifecycle", () => {
  assert.deepEqual(createTrustedGateArguments("pnpm", ["unit"]), [
    "--config.enable-pre-post-scripts=false",
    "--config.ignore-pnpmfile=true",
    "unit",
  ]);
  assert.deepEqual(createTrustedGateArguments("node", ["scripts/check.mjs"]), [
    "scripts/check.mjs",
  ]);
});

test("嵌套 pnpm 继承 hooks 禁用环境", () => {
  const environment = createGateEnvironment({
    gateHome: "/tmp/gate-home",
    gateTempDirectory: "/tmp/gate-tmp",
  });

  assert.equal(environment.npm_config_enable_pre_post_scripts, "false");
  assert.equal(environment.npm_config_ignore_pnpmfile, "true");
  assert.equal(environment.PNPM_CONFIG_ENABLE_PRE_POST_SCRIPTS, "false");
  assert.equal(environment.PNPM_CONFIG_IGNORE_PNPMFILE, "true");
});

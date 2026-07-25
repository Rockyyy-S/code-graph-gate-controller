import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";
import {
  createGateEnvironment,
  createGateRuntimePaths,
  createTrustedGateArguments,
  didRequiredBlockingGatesPass,
  evaluateApplicability,
  runIdentityProcessTool,
} from "../lib/harness.mjs";
import {
  createTrustedGitArguments,
  parseNameStatusZ,
} from "../lib/git-context.mjs";

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

test("pnpm gate 禁止执行未绑定 lifecycle 与只读阶段二次安装", () => {
  assert.deepEqual(createTrustedGateArguments("pnpm", ["unit"]), [
    "--config.enable-pre-post-scripts=false",
    "--config.ignore-pnpmfile=true",
    "--config.verify-deps-before-run=false",
    "unit",
  ]);
  assert.deepEqual(createTrustedGateArguments("node", ["scripts/check.mjs"]), [
    "scripts/check.mjs",
  ]);
});

test("嵌套 pnpm 继承 hooks 与依赖二次安装禁用环境", () => {
  const environment = createGateEnvironment({
    baseOid: "a".repeat(40),
    gateHome: "/tmp/gate-home",
    gateTempDirectory: "/tmp/gate-tmp",
    headOid: "b".repeat(40),
  });

  assert.equal(environment.CODEGRAPH_BASE_OID, "a".repeat(40));
  assert.equal(environment.CODEGRAPH_HEAD_OID, "b".repeat(40));
  assert.equal(environment.npm_config_enable_pre_post_scripts, "false");
  assert.equal(environment.npm_config_ignore_pnpmfile, "true");
  assert.equal(environment.npm_config_verify_deps_before_run, "false");
  assert.equal(environment.PNPM_CONFIG_ENABLE_PRE_POST_SCRIPTS, "false");
  assert.equal(environment.PNPM_CONFIG_IGNORE_PNPMFILE, "true");
  assert.equal(environment.PNPM_CONFIG_VERIFY_DEPS_BEFORE_RUN, "false");
});

test("每个 gate 使用短且独立的 HOME 与 TMP 槽位", () => {
  assert.deepEqual(
    createGateRuntimePaths(
      {
        gateHome: "/tmp/gate-home",
        gateTempDirectory: "/tmp/gate-tmp",
      },
      35,
    ),
    {
      gateHome: path.join("/tmp/gate-home", "z"),
      gateTempDirectory: path.join("/tmp/gate-tmp", "z"),
    },
  );
  assert.notDeepEqual(
    createGateRuntimePaths(
      {
        gateHome: "/tmp/gate-home",
        gateTempDirectory: "/tmp/gate-tmp",
      },
      36,
    ),
    createGateRuntimePaths(
      {
        gateHome: "/tmp/gate-home",
        gateTempDirectory: "/tmp/gate-tmp",
      },
      35,
    ),
  );
  assert.throws(
    () =>
      createGateRuntimePaths(
        {
          gateHome: "/tmp/gate-home",
          gateTempDirectory: "/tmp/gate-tmp",
        },
        -1,
      ),
    /非负安全整数/u,
  );
});

test("短 TMP 槽位为 Hosted Unix socket fixture 保留 100-byte 路径预算", () => {
  const { gateTempDirectory } = createGateRuntimePaths(
    {
      gateHome: "/tmp/gatecandidate-home",
      gateTempDirectory: "/g",
    },
    36,
  );
  const fixtureCacheRoot = path.posix.join(
    gateTempDirectory,
    "codegraph-shutdown-timeout-XXXXXX",
  );
  const endpoint = path.posix.join(
    fixtureCacheRoot,
    "codegraph",
    "w",
    "a".repeat(24),
    `s-${"b".repeat(16)}.sock`,
  );

  assert.ok(Buffer.byteLength(endpoint, "utf8") <= 100);
});

test("root Harness 只信任当前候选 Git 路径", () => {
  assert.deepEqual(createTrustedGitArguments("/workspace/candidate", ["status"]), [
    "-c",
    "safe.directory=/workspace/candidate",
    "-C",
    "/workspace/candidate",
    "status",
  ]);
});

test("UID 清理工具的每次 pkill/pgrep 都受 Harness 剩余绝对预算约束", async () => {
  let receivedOptions;
  const noMatch = await runIdentityProcessTool("pgrep", ["-u", "1001"], {
    deadlineAt: 150,
    exec: async (_executable, _args, options) => {
      receivedOptions = options;
      const error = new Error("no match");
      error.code = 1;
      throw error;
    },
    now: () => 100,
  });

  assert.equal(noMatch, false);
  assert.equal(receivedOptions.timeout, 50);
  assert.equal(receivedOptions.killSignal, "SIGKILL");
  await assert.rejects(
    runIdentityProcessTool("pkill", ["-KILL", "-u", "1001"], {
      deadlineAt: 100,
      exec: async () => {
        throw new Error("不应执行");
      },
      now: () => 100,
    }),
    /deadline|预算/u,
  );
});

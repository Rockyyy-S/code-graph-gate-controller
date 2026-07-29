import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { sha256CanonicalJson } from "../lib/canonical-json.mjs";
import {
  createGateEnvironment,
  createGateRuntimePaths,
  createTrustedGateArguments,
  didRequiredBlockingGatesPass,
  evaluateApplicability,
  mergeGateEvidenceArtifacts,
  runIdentityProcessTool,
  selectGateEntriesForPartition,
  WIN32_HOST_IDENTITY_GATE_ID,
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

test("portable 与 Win32 分区互斥且 Win32 gate 必须保持 blocking", () => {
  const registry = {
    gates: [
      { gateDefinition: { blocking: true, gateId: "type" } },
      {
        gateDefinition: {
          blocking: true,
          gateId: WIN32_HOST_IDENTITY_GATE_ID,
        },
      },
    ],
  };
  assert.deepEqual(
    selectGateEntriesForPartition(registry, "portable", "linux")
      .map(([, entry]) => entry.gateDefinition.gateId),
    ["type"],
  );
  assert.deepEqual(
    selectGateEntriesForPartition(registry, "win32", "win32")
      .map(([, entry]) => entry.gateDefinition.gateId),
    [WIN32_HOST_IDENTITY_GATE_ID],
  );
  assert.throws(
    () => selectGateEntriesForPartition(registry, "win32", "linux"),
    /真实 runner 平台/u,
  );
  registry.gates[1].gateDefinition.blocking = false;
  assert.throws(
    () => selectGateEntriesForPartition(registry, "win32", "win32"),
    /缺失|降级/u,
  );
});

test("分区 artifact 只在绑定一致且 gate 不重复时合并", async (context) => {
  const root = await mkdtemp(path.join(tmpdir(), "gate-evidence-merge-"));
  context.after(() => rm(root, { force: true, recursive: true }));
  const shared = {
    affectedPaths: ["apps/graph-service/src/host-path-identity.ts"],
    evaluationContext: {
      baseOid: "a".repeat(40),
      comparisonBaseOid: "a".repeat(40),
      evaluationContextDigest: "b".repeat(64),
      gateRegistryDigest: "c".repeat(64),
      headOid: "d".repeat(40),
      objectFormat: "sha1",
      providerRepositoryId: "1303415307",
      schemaVersion: 1,
    },
    gateImplementationDigest: "e".repeat(64),
    gateRegistryDigest: "c".repeat(64),
    schemaVersion: 1,
  };
  const createEvidence = (gateId) => {
    const evidence = {
      evaluationContextDigest: "b".repeat(64),
      evidenceProducerId:
        `gha-oidc://1303415307/Rockyyy-S/code-graph-gate-controller/.github/workflows/produce-gate-evidence.yml@${"f".repeat(40)}#${gateId}`,
      gateDefinitionDigest: "1".repeat(64),
      gateId,
      headOid: "d".repeat(40),
      outputDigest: "2".repeat(64),
      schemaVersion: 1,
      status: "pass",
    };
    return { ...evidence, gateEvidenceDigest: sha256CanonicalJson(evidence) };
  };
  const portablePath = path.join(root, "portable.json");
  const win32Path = path.join(root, "win32.json");
  await Promise.all([
    writeFile(portablePath, JSON.stringify({
      ...shared,
      evidence: [createEvidence("type")],
    })),
    writeFile(win32Path, JSON.stringify({
      ...shared,
      evidence: [createEvidence(WIN32_HOST_IDENTITY_GATE_ID)],
    })),
  ]);

  const outputRoot = path.join(root, "merged");
  const result = await mergeGateEvidenceArtifacts({
    artifactDirectory: outputRoot,
    artifactPaths: [portablePath, win32Path],
  });
  assert.deepEqual(
    result.artifact.evidence.map(({ gateId }) => gateId),
    [WIN32_HOST_IDENTITY_GATE_ID, "type"],
  );
  assert.deepEqual(
    JSON.parse(await readFile(path.join(outputRoot, "gate-evidence.json"), "utf8")),
    result.artifact,
  );

  await writeFile(win32Path, JSON.stringify({
    ...shared,
    evidence: [createEvidence("type")],
  }));
  await assert.rejects(
    mergeGateEvidenceArtifacts({
      artifactDirectory: outputRoot,
      artifactPaths: [portablePath, win32Path],
    }),
    /重复生成/u,
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

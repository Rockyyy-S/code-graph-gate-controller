import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  access,
  chmod,
  copyFile,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { sha256CanonicalJson, sha256Hex } from "../lib/canonical-json.mjs";
import {
  createGateEnvironment,
  createGateRuntimePaths,
  createTrustedGateArguments,
  didRequiredBlockingGatesPass,
  evaluateApplicability,
  mergeGateEvidenceArtifacts,
  runIdentityProcessTool,
  selectGateEntriesForPartition,
  validateWin32PreflightArtifact,
  validateTrustedPnpmExecutable,
  WIN32_HOST_IDENTITY_GATE_ID,
} from "../lib/harness.mjs";
import {
  createTrustedGitArguments,
  parseNameStatusZ,
} from "../lib/git-context.mjs";

/** 构造 Harness 可接受的最小 Win32 NTFS preflight artifact。 */
function createWin32Preflight(overrides = {}) {
  const selectedRoot = path.resolve("win32-preflight-root");
  return {
    candidateRoot: path.resolve("candidate"),
    drive: "C",
    driveType: "Fixed",
    fileSystem: "NTFS",
    getVolume: { status: 0, stderr: "", stdout: "[]", timeout: false },
    probeDurationMs: 12,
    probeStartedAt: "2026-07-30T00:00:00.000Z",
    processPlatform: "win32",
    root: { ordinary: true, reparse: false },
    runnerTemp: path.resolve("runner-temp"),
    schemaVersion: 1,
    selectedRoot,
    ...overrides,
  };
}

test("Win32 preflight 区分非 NTFS、查询错误、超时与非 Win32 并保留实际值", () => {
  const selectedRoot = path.resolve("win32-preflight-root");
  const context = { gateTempDirectory: selectedRoot, platform: "win32" };
  assert.equal(validateWin32PreflightArtifact(createWin32Preflight(), context).fileSystem, "NTFS");
  const cases = [
    {
      code: "WIN32_PREFLIGHT_NON_NTFS",
      context,
      expected: "ReFS",
      preflight: createWin32Preflight({ fileSystem: "ReFS" }),
    },
    {
      code: "WIN32_PREFLIGHT_QUERY_ERROR",
      context,
      expected: "Access denied",
      preflight: createWin32Preflight({
        getVolume: { status: 5, stderr: "Access denied", stdout: "", timeout: false },
      }),
    },
    {
      code: "WIN32_PREFLIGHT_QUERY_TIMEOUT",
      context,
      expected: "timed out",
      preflight: createWin32Preflight({
        getVolume: { status: null, stderr: "timed out", stdout: "", timeout: true },
      }),
    },
    {
      code: "WIN32_PREFLIGHT_NON_WIN32",
      context: { ...context, platform: "linux" },
      expected: "linux",
      preflight: createWin32Preflight(),
    },
    {
      code: "WIN32_PREFLIGHT_DEADLINE_DRIFT",
      context,
      expected: "10001",
      preflight: createWin32Preflight({ probeDurationMs: 10_001 }),
    },
  ];
  for (const item of cases) {
    assert.throws(
      () => validateWin32PreflightArtifact(item.preflight, item.context),
      (error) => {
        assert.equal(error.code, item.code);
        assert.equal(error.preflight, item.preflight);
        assert.match(error.message, new RegExp(item.expected, "u"));
        return true;
      },
    );
  }
});

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
  assert.equal(environment.CODEGRAPH_TRUSTED_WIN32_PREFLIGHT_V1, undefined);
});

test("Win32 Harness 只向候选传递已验证 preflight，portable 分区不暴露", () => {
  const selectedRoot = path.resolve("win32-preflight-root");
  const validatedWin32Preflight = validateWin32PreflightArtifact(
    createWin32Preflight({ selectedRoot }),
    { gateTempDirectory: selectedRoot, platform: "win32" },
  );
  const shared = {
    baseOid: "a".repeat(40),
    gateHome: selectedRoot,
    gateTempDirectory: selectedRoot,
    headOid: "b".repeat(40),
    validatedWin32Preflight,
  };
  const win32Environment = createGateEnvironment({
    ...shared,
    executionPartition: "win32",
    hostPathInvocationAttestationPath: path.join(selectedRoot, "invocation.json"),
    trustedPnpmExecutable: path.join(selectedRoot, "pnpm.exe"),
  });
  const portableEnvironment = createGateEnvironment({
    ...shared,
    executionPartition: "portable",
  });

  assert.deepEqual(
    JSON.parse(win32Environment.CODEGRAPH_TRUSTED_WIN32_PREFLIGHT_V1),
    validatedWin32Preflight,
  );
  assert.equal(portableEnvironment.CODEGRAPH_TRUSTED_WIN32_PREFLIGHT_V1, undefined);
});

test("显式可信 launcher 在无 npm_execpath 且恶意 PATH 存在时仍以绝对路径执行", async (context) => {
  const root = await mkdtemp(path.join(tmpdir(), "trusted-pnpm-harness-"));
  context.after(() => rm(root, { force: true, recursive: true }));
  const trustedDirectory = path.join(root, "trusted");
  const maliciousDirectory = path.join(root, "malicious");
  await Promise.all([
    mkdir(trustedDirectory),
    mkdir(maliciousDirectory),
  ]);
  const trustedPnpm = path.join(trustedDirectory, "pnpm.exe");
  await copyFile(process.execPath, trustedPnpm);
  await chmod(trustedPnpm, 0o755);
  const trustedBytes = await readFile(trustedPnpm);
  const validated = await validateTrustedPnpmExecutable(trustedPnpm, {
    expectedSha256: sha256Hex(trustedBytes),
    expectedSize: trustedBytes.length,
    execFileImpl: async (executable, args, options) => {
      assert.equal(executable, trustedPnpm);
      assert.deepEqual(args, ["--version"]);
      assert.equal(options.shell, false);
      return { stderr: "", stdout: "11.12.0\n" };
    },
  });
  const marker = path.join(root, "malicious.marker");
  const maliciousPnpm = process.platform === "win32"
    ? path.join(maliciousDirectory, "pnpm.cmd")
    : path.join(maliciousDirectory, "pnpm");
  await writeFile(
    maliciousPnpm,
    process.platform === "win32"
      ? `@echo off\r\necho malicious>"${marker}"\r\nexit /b 99\r\n`
      : `#!/bin/sh\nprintf malicious > '${marker}'\nexit 99\n`,
    "utf8",
  );
  await chmod(maliciousPnpm, 0o755);
  const environment = createGateEnvironment({
    baseOid: "a".repeat(40),
    executionPartition: "win32",
    gateHome: root,
    gateTempDirectory: root,
    headOid: "b".repeat(40),
    hostPathInvocationAttestationPath: path.join(root, "invocation.json"),
    trustedPnpmExecutable: validated,
    GITHUB_TOKEN: "不得泄漏",
  });
  const result = spawnSync(
    process.execPath,
    [
      "--input-type=module",
      "--eval",
      "import { spawnSync } from 'node:child_process'; const child = spawnSync(process.env.CODEGRAPH_TRUSTED_PNPM_EXE, ['--eval', \"process.stdout.write('trusted')\"], { encoding: 'utf8', shell: false }); process.stdout.write(child.stdout); process.exit(child.status ?? 1);",
    ],
    {
      encoding: "utf8",
      env: {
        ...environment,
        PATH: `${maliciousDirectory}${path.delimiter}${process.env.PATH ?? ""}`,
      },
      shell: false,
    },
  );
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, "trusted");
  await assert.rejects(access(marker), /ENOENT/u);
  assert.equal(environment.CODEGRAPH_TRUSTED_PNPM_EXE, trustedPnpm);
  assert.equal(
    environment.CODEGRAPH_HOST_PATH_IDENTITY_ATTESTATION_PATH,
    path.join(root, "invocation.json"),
  );
  assert.equal(environment.npm_execpath, undefined);
  assert.equal(environment.GITHUB_TOKEN, undefined);
  assert.equal(environment.ACTIONS_ID_TOKEN_REQUEST_TOKEN, undefined);
  assert.equal(environment.PATH.includes(trustedDirectory), false);
});

test("可信 launcher 对路径、类型、reparse、大小、摘要与版本漂移全部 fail closed", async (context) => {
  const root = await mkdtemp(path.join(tmpdir(), "trusted-pnpm-negative-"));
  context.after(() => rm(root, { force: true, recursive: true }));
  const trustedPnpm = path.join(root, "pnpm.exe");
  await writeFile(trustedPnpm, "trusted-bytes", "utf8");
  const expectedSha256 = sha256Hex(Buffer.from("trusted-bytes"));
  const validDependencies = {
    expectedSha256,
    expectedSize: Buffer.byteLength("trusted-bytes"),
    execFileImpl: async () => ({ stderr: "", stdout: "11.12.0\n" }),
  };
  await assert.rejects(
    validateTrustedPnpmExecutable("pnpm.exe", validDependencies),
    /参数无效/u,
  );
  await assert.rejects(
    validateTrustedPnpmExecutable(path.join(root, "trusted.exe"), validDependencies),
    /参数无效/u,
  );
  await assert.rejects(
    validateTrustedPnpmExecutable(path.join(root, "missing", "pnpm.exe"), validDependencies),
    /ENOENT/u,
  );
  const directoryLauncher = path.join(root, "directory", "pnpm.exe");
  await mkdir(directoryLauncher, { recursive: true });
  await assert.rejects(
    validateTrustedPnpmExecutable(directoryLauncher, validDependencies),
    /普通非 reparse/u,
  );
  await assert.rejects(
    validateTrustedPnpmExecutable(trustedPnpm, {
      ...validDependencies,
      lstatImpl: async () => ({
        isFile: () => true,
        isSymbolicLink: () => true,
        size: Buffer.byteLength("trusted-bytes"),
      }),
    }),
    /普通非 reparse/u,
  );
  await assert.rejects(
    validateTrustedPnpmExecutable(trustedPnpm, {
      ...validDependencies,
      expectedSize: Buffer.byteLength("trusted-bytes") + 1,
    }),
    /普通非 reparse/u,
  );
  await assert.rejects(
    validateTrustedPnpmExecutable(trustedPnpm, {
      ...validDependencies,
      expectedSha256: "0".repeat(64),
    }),
    /SHA-256 漂移/u,
  );
  await assert.rejects(
    validateTrustedPnpmExecutable(trustedPnpm, {
      ...validDependencies,
      execFileImpl: async () => ({ stderr: "", stdout: "11.12.1\n" }),
    }),
    /版本漂移/u,
  );
  await assert.rejects(
    validateTrustedPnpmExecutable(trustedPnpm, {
      ...validDependencies,
      realpathImpl: async () => path.join(root, "redirected", "pnpm.exe"),
    }),
    /重定向/u,
  );
});

test("portable 分区不注入 Win32 launcher 且保持现有环境行为", () => {
  const environment = createGateEnvironment({
    baseOid: "a".repeat(40),
    executionPartition: "portable",
    gateHome: "/tmp/gate-home",
    gateTempDirectory: "/tmp/gate-tmp",
    headOid: "b".repeat(40),
    trustedPnpmExecutable: "/tmp/pnpm.exe",
  });
  assert.equal(environment.CODEGRAPH_TRUSTED_PNPM_EXE, undefined);
  assert.equal(environment.PATH, process.env.PATH);
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

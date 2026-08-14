import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";
import {
  GATE_HARNESS_PORTABLE_ARGUMENT_NAMES_V3,
  GATE_HARNESS_PORTABLE_ARGUMENT_NAMES_V4,
  GATE_HARNESS_WIN32_ARGUMENT_NAMES_V3,
  GATE_HARNESS_WIN32_ARGUMENT_NAMES_V4,
} from "../bin/produce-gate-evidence.mjs";
import { GATE_HARNESS_CONTRACT_VERSION } from "../lib/harness.mjs";

const workflowPath = new URL("../.github/workflows/produce-gate-evidence.yml", import.meta.url);
const harnessPath = new URL("../lib/harness.mjs", import.meta.url);
const controllerWorkflowPath = new URL("../.github/workflows/controller.yml", import.meta.url);
const monitorWorkflowPath = new URL("../.github/workflows/drift-monitor.yml", import.meta.url);
const trustedHarnessSha = "f03e200280d8da8bdd474abe01b9ef2e90f3a631";
const pnpmArchiveSha256 = "dd19bfd8bcd33a3b38dcce335e8d233194c0a61ffe1f5bcf5047f60f6d4978b8";
const pnpmWin32ArchiveSha256 =
  "7ac25ba81b8a9f213a307ae89198ba7e636e6c74fa0d775d554ba46e0187358b";
const pnpmWin32EntrySha256 =
  "0a8b6b9d6f391bb83e868a3f951eec74fb8f745c176fce523a9359f40b20fb7b";
const pnpmWin32EntrySize = 98099528;
const betterSqliteIntegrity =
  "sha512-dq9AtApgg5PGFtBzPFSBl3HZQjHok5gaQCM6zh2Yk0aSmDCs1CbnVI8/HgASQkNKsWFpseIO9beg5xxpYhbIfA==";
/** 从 Win32 host identity gate 的真实 imports 反向闭合的最小有序构建集合。 */
const win32OrderedBuildClosure = Object.freeze([
  "@codegraph/domain",
  "@codegraph/contracts",
  "@codegraph/application",
  "@codegraph/service-client",
  "@codegraph/adapter-analyzer-typescript",
  "@codegraph/adapter-git-local",
  "@codegraph/adapter-host-path-posix-native",
  "@codegraph/adapter-store-sqlite",
  "@codegraph/graph-service",
]);

/**
 * 提取 Portable helper provisioning 的阻断步骤，避免断言误命中 Win32 或清理逻辑。
 *
 * @param {string} workflow 完整 workflow 文本。
 * @returns {string} Portable helper provisioning 步骤文本。
 */
function extractPortableHelperProvisionStep(workflow) {
  const portableJob = /\n  gate-execution:\s*[\s\S]*?(?=\n  gate-execution-win32:)/u.exec(workflow)?.[0];
  const provisionStep = /- name: Provision signed Linux host-path helper runtime[\s\S]*?(?=\n\s+- name:)/u.exec(portableJob)?.[0];

  assert.equal(typeof provisionStep, "string");
  return provisionStep;
}

/**
 * 提取 Portable trusted tool 的纯策略函数，使正负 fixture 执行生产 workflow 的同一组谓词。
 *
 * @param {string} provisionStep Portable helper provisioning 步骤文本。
 * @returns {string} 可独立执行的 Bash 函数定义。
 */
function extractTrustedToolPolicyFunction(provisionStep) {
  const policyFunction = /validate_trusted_system_tool_policy\(\) \{[\s\S]*?\n          \}/u.exec(
    provisionStep,
  )?.[0];

  assert.equal(typeof policyFunction, "string");
  return policyFunction;
}

/**
 * 将 fixture 字段编码为 Bash 单引号参数，避免诊断值改变命令结构。
 *
 * @param {unknown} value fixture 字段值。
 * @returns {string} Bash 安全字面量。
 */
function quoteBash(value) {
  return `'${String(value).replaceAll("'", `'"'"'`)}'`;
}

/**
 * 在本机 Git Bash 或 POSIX Bash 中执行 workflow 的纯策略函数。
 *
 * @param {string} policyFunction workflow 中提取的函数定义。
 * @param {readonly string[]} fixture 按生产函数参数顺序排列的拓扑证据。
 * @returns {{status: number | null, stdout: string, stderr: string}} 执行结果。
 */
function runTrustedToolPolicyFixture(policyFunction, fixture) {
  const bashExecutable =
    process.platform === "win32"
      ? join(process.env.ProgramFiles ?? "C:\\Program Files", "Git", "bin", "bash.exe")
      : "bash";
  const invocation = `validate_trusted_system_tool_policy ${fixture.map(quoteBash).join(" ")}`;
  const result = spawnSync(bashExecutable, ["-c", `${policyFunction}\n${invocation}\n`], {
    encoding: "utf8",
  });

  assert.equal(result.error, undefined);
  return {
    status: result.status,
    stdout: result.stdout,
    stderr: result.stderr,
  };
}

test("reusable producer 显式接收并绑定外部 workflow commit SHA", async () => {
  const workflow = await readFile(workflowPath, "utf8");

  assert.match(workflow, /producer_workflow_sha:\s*\n\s+required: true\s*\n\s+type: string/u);
  assert.match(workflow, /PRODUCER_WORKFLOW_SHA: \$\{\{ inputs\.producer_workflow_sha \}\}/u);
  assert.match(workflow, /--workflow-sha "\$PRODUCER_WORKFLOW_SHA"/u);
  assert.doesNotMatch(workflow, /github\.workflow_sha/u);
});

test("Win32 外层固定 deadline preflight 由 Harness 验证后传递给候选", async () => {
  const [workflow, harness] = await Promise.all([
    readFile(workflowPath, "utf8"),
    readFile(harnessPath, "utf8"),
  ]);
  const win32Job = /\n  gate-execution-win32:\s*[\s\S]*?(?=\n  gate-evidence:)/u.exec(workflow)?.[0];

  assert.equal(typeof win32Job, "string");
  assert.match(win32Job, /Get-Volume -ErrorAction Stop/u);
  assert.match(win32Job, /Wait-Job -Job \$job -Timeout 30/u);
  assert.match(win32Job, /--win32-preflight-artifact', \$env:WIN32_PREFLIGHT_ARTIFACT/u);
  assert.match(harness, /validatedWin32Preflight = validateWin32PreflightArtifact/u);
  assert.match(harness, /CODEGRAPH_TRUSTED_WIN32_PREFLIGHT_V1/u);
  assert.match(harness, /JSON\.stringify\(options\.validatedWin32Preflight\)/u);
});

test("Controller terminal failure 通过 Checks PATCH 原位终结 pending", async () => {
  const controller = await readFile(
    new URL("../bin/run-controller.mjs", import.meta.url),
    "utf8",
  );

  assert.match(controller, /createTerminalFailureCheckRecord/u);
  assert.match(controller, /check-runs\/\$\{checkId\}/u);
  assert.match(controller, /method: "PATCH"/u);
});

test("Controller check lifecycle 独立于 result CAS，并按 ID readback 验证", async () => {
  const [controller, publisher] = await Promise.all([
    readFile(new URL("../bin/run-controller.mjs", import.meta.url), "utf8"),
    readFile(new URL("../lib/controller-check-publisher.mjs", import.meta.url), "utf8"),
  ]);

  assert.match(controller, /check-lifecycle-v1/u);
  assert.match(controller, /checkLifecycleKey: createCheckLifecycleKey/u);
  assert.match(controller, /assertFreshDriftMonitorReadOnly/u);
  assert.match(publisher, /GET-readback-verify/u);
  assert.match(publisher, /completed_at/u);
  assert.match(publisher, /supersededByCheckId/u);
  assert.match(publisher, /supersededByLifecycleKey/u);
});

test("reusable producer 固定检出已批准的不可变 GateHarness", async () => {
  const workflow = await readFile(workflowPath, "utf8");
  const checkoutBlock = /- name: Checkout immutable GateHarness[\s\S]*?(?=\n\s+- name:)/u.exec(workflow)?.[0];
  const immutablePins = workflow.match(new RegExp(`ref: ${trustedHarnessSha}`, "gu")) ?? [];

  assert.equal(typeof checkoutBlock, "string");
  assert.match(checkoutBlock, /path: trusted-harness/u);
  assert.match(checkoutBlock, new RegExp(`ref: ${trustedHarnessSha}`, "u"));
  assert.equal(immutablePins.length, 3, "Portable、Win32、merge 必须固定到同一已验证 Harness merge SHA。");
  assert.doesNotMatch(workflow, /97048ec0c2f6a38716bf3c0b38ac8c6bf31c709f/u);
  assert.doesNotMatch(checkoutBlock, /ref:\s+(?:main|master|HEAD)\b/u);
});

test("候选执行 job 不持有 OIDC/attestation 权限，签名在干净 runner 完成", async () => {
  const workflow = await readFile(workflowPath, "utf8");
  const portableJob = /\n  gate-execution:\s*[\s\S]*?(?=\n  gate-execution-win32:)/u.exec(workflow)?.[0];
  const win32Job = /\n  gate-execution-win32:\s*[\s\S]*?(?=\n  gate-evidence:)/u.exec(workflow)?.[0];
  const attestationJob = /\n  gate-evidence:\s*[\s\S]*$/u.exec(workflow)?.[0];
  const elevatedPermissionPattern = new RegExp(
    ["id-token", "attestations"].map((name) => `${name}:\\s*write`).join("|"),
    "u",
  );

  assert.equal(typeof portableJob, "string");
  assert.equal(typeof win32Job, "string");
  assert.equal(typeof attestationJob, "string");
  assert.doesNotMatch(portableJob, elevatedPermissionPattern);
  assert.doesNotMatch(win32Job, elevatedPermissionPattern);
  assert.match(
    attestationJob,
    /needs:\s*\n\s+- gate-execution\s*\n\s+- gate-execution-win32/u,
  );
  assert.doesNotMatch(attestationJob, /if:\s*\$\{\{\s*always\(\)/u);
  assert.match(attestationJob, /id-token:\s*write/u);
  assert.match(attestationJob, /attestations:\s*write/u);
  assert.match(attestationJob, /actions\/download-artifact@[0-9a-f]{40}/u);
  assert.match(attestationJob, /actions\/attest-build-provenance@[0-9a-f]{40}/u);
});

test("候选 lifecycle、环境、工作树与 artifact 权限均被隔离", async () => {
  const workflow = await readFile(workflowPath, "utf8");
  const pnpmInstallOffset = workflow.indexOf("- name: Install checksum-pinned pnpm release");
  const firstCheckoutOffset = workflow.indexOf("- name: Checkout immutable GateHarness");
  const evidenceStep = /- name: Produce child gate evidence[\s\S]*?(?=\n\s+- name:)/u.exec(workflow)?.[0];
  const evidenceRun = evidenceStep?.split("run: |", 2)[1];

  assert.ok(pnpmInstallOffset >= 0 && pnpmInstallOffset < firstCheckoutOffset);
  assert.equal(typeof evidenceStep, "string");
  assert.equal(typeof evidenceRun, "string");
  assert.doesNotMatch(evidenceRun, /\$\{\{ inputs\./u);
  assert.doesNotMatch(workflow, /pnpm\/action-setup@|standalone: true/u);
  assert.match(workflow, /pnpm\/pnpm\/releases\/download\/v11\.12\.0\/pnpm-linux-x64\.tar\.gz/u);
  assert.match(workflow, new RegExp(`PNPM_ARCHIVE_SHA256: ${pnpmArchiveSha256}`, "u"));
  assert.match(workflow, /--proto '=https' --proto-redir '=https' --tlsv1\.2/u);
  assert.match(workflow, /sha256sum --check --strict/u);
  assert.match(workflow, /mktemp -d "\$RUNNER_TEMP\/pnpm-11\.12\.0\.XXXXXX"/u);
  assert.match(workflow, /tar --extract --gzip --file "\$archive"[\s\S]*-- pnpm dist/u);
  assert.match(workflow, /source_pnpm="\$\(realpath -- "\$staging\/pnpm"\)"/u);
  assert.match(workflow, /source_dist="\$\(realpath -- "\$staging\/dist"\)"/u);
  assert.match(workflow, /find "\$staging_root" -type l -print0/u);
  assert.match(workflow, /cp -a -- "\$source_dist" \/opt\/trusted-pnpm\/bin\/dist/u);
  assert.match(workflow, /install -o 0 -g 0 -m 0755 "\$source_pnpm" \/opt\/trusted-pnpm\/bin\/pnpm/u);
  assert.match(workflow, /chown -R 0:0 \/opt\/trusted-pnpm/u);
  assert.match(workflow, /chmod -R u\+rwX,go\+rX,go-w \/opt\/trusted-pnpm/u);
  assert.match(workflow, /stat -c '%U:%G %a' \/opt\/trusted-pnpm\/bin\/pnpm/u);
  assert.match(workflow, /find \/opt\/trusted-pnpm -perm \/022 -print -quit/u);
  assert.match(
    workflow,
    /sudo -u gatecandidate env -i --chdir=\/tmp\/gatecandidate-install-home/u,
  );
  assert.match(workflow, /\[\[ "\$pnpm_version" == "11\.12\.0" \]\]/u);
  assert.match(workflow, /TRUSTED_PNPM_BIN: \/opt\/trusted-pnpm\/bin/u);
  assert.match(workflow, /PATH="\$TRUSTED_PNPM_BIN:\$PATH"/u);
  assert.match(
    workflow,
    /sudo -u gatecandidate env -i --chdir="\$candidate_root"[\s\S]*pnpm install --frozen-lockfile --ignore-pnpmfile --ignore-scripts/u,
  );
  assert.match(workflow, /grep -Ec '\^  better-sqlite3@12\\\.11\\\.1:\$'/u);
  assert.match(workflow, new RegExp(betterSqliteIntegrity.replaceAll("+", "\\+"), "u"));
  assert.match(
    workflow,
    /value\?\.dependencies\?\.\["better-sqlite3"\] !== "12\.11\.1"/u,
  );
  assert.match(
    workflow,
    /pnpm --filter @codegraph\/adapter-store-sqlite --fail-if-no-match rebuild better-sqlite3/u,
  );
  assert.match(
    workflow,
    /import Database from "better-sqlite3"; const database = new Database\(":memory:"\)/u,
  );
  assert.doesNotMatch(workflow, /pnpm install[^\n]*--ignore-scripts=false/u);
  assert.match(workflow, /workspace_root="\$\(realpath -- "\$GITHUB_WORKSPACE"\)"/u);
  assert.match(workflow, /source_candidate="\$\(realpath -- candidate\)"/u);
  assert.match(workflow, /candidate_parent=\/tmp\/gatecandidate-root/u);
  assert.match(workflow, /candidate_root="\$candidate_parent\/worktree"/u);
  assert.match(workflow, /install -d -o 0 -g 0 -m 0711 "\$candidate_parent"/u);
  assert.match(workflow, /git -C "\$source_candidate" rev-parse HEAD/u);
  assert.match(workflow, /sudo cp -a -- "\$source_candidate\/\." "\$candidate_root\/"/u);
  assert.match(workflow, /sudo git -c safe\.directory="\$candidate_root" -C "\$candidate_root" rev-parse HEAD/u);
  assert.match(workflow, /sudo pkill -KILL -u 20001 \|\| true/u);
  assert.match(workflow, /gatecandidate-install-home/u);
  assert.match(workflow, /install -d -o 0 -g 0 -m 0711 \/tmp\/gatecandidate-home/u);
  assert.match(workflow, /\[\[ ! -e \/g \]\]/u);
  assert.match(workflow, /--gate-temp-directory \/g/u);
  assert.match(workflow, /if mountpoint --quiet \/g; then\s+sudo \/usr\/bin\/umount -- \/g/u);
  assert.match(workflow, /resolved_output="\$\(realpath -m -- "\$output_path"\)"/u);
  assert.match(workflow, /\[\[ "\$resolved_output" != "\$output_path" \]\]/u);
  assert.doesNotMatch(workflow, /sudo -u gatecandidate --chdir=|sudo -D\b/u);
  assert.doesNotMatch(workflow, /setfacl|chmod[^\n]*GITHUB_WORKSPACE/u);
  assert.match(workflow, /sudo env -i HOME=/u);
  assert.match(workflow, /sudo chown -R "\$\(id -u\):20001" "\$candidate_root"/u);
  assert.match(workflow, /sudo chmod -R u\+rwX,g\+rX,o-rwx "\$candidate_root"/u);
  assert.match(workflow, /sudo rm -rf -- "\$candidate_root\/\.git"/u);
  assert.match(workflow, /sudo cp -a -- "\$source_candidate\/\.git" "\$candidate_root\/\.git"/u);
  assert.match(
    workflow,
    /git -c safe\.directory="\$candidate_root" -C "\$candidate_root" diff --quiet --no-ext-diff HEAD --/u,
  );
  assert.match(workflow, /--candidate-root \/tmp\/gatecandidate-root\/worktree/u);
  assert.match(workflow, /--execution-partition portable/u);
  assert.match(workflow, /--harness-contract-version 4/u);
  assert.match(workflow, /sudo rm -rf -- \/tmp\/gatecandidate-root/u);
  assert.match(workflow, /install -d -m 0700 artifacts/u);
  assert.match(workflow, /--gate-uid 20001/u);
  assert.match(workflow, /--gate-gid 20001/u);
  assert.match(workflow, /env -i HOME=/u);
});

test("portable producer 只开放显式输出并提供隔离的 Rust 1.88 离线执行面", async () => {
  const workflow = await readFile(workflowPath, "utf8");
  const rustBootstrap = /- name: Bootstrap fixed Rust toolchain and locked dependency cache[\s\S]*?(?=\n\s+- name:)/u.exec(workflow)?.[0];
  const outputGrant = /- name: Grant candidate writes only to generated output directories[\s\S]*?(?=\n\s+- name:)/u.exec(workflow)?.[0];
  const portableEvidence = /- name: Produce child gate evidence[\s\S]*?(?=\n\s+- name:)/u.exec(workflow)?.[0];

  assert.equal(typeof rustBootstrap, "string");
  assert.equal(typeof outputGrant, "string");
  assert.equal(typeof portableEvidence, "string");
  assert.match(rustBootstrap, /set -euo pipefail/u);
  assert.match(rustBootstrap, /RUST_TOOLCHAIN: 1\.88\.0/u);
  assert.match(
    rustBootstrap,
    /rustup_source="\$\(realpath -- "\$\(command -v rustup\)"\)"/u,
  );
  assert.match(rustBootstrap, /HOME="\$bootstrap_home"/u);
  assert.match(rustBootstrap, /CARGO_HOME="\$bootstrap_cargo_home"/u);
  assert.match(rustBootstrap, /RUSTUP_HOME="\$bootstrap_rustup_home"/u);
  assert.match(
    rustBootstrap,
    /toolchain install "\$RUST_TOOLCHAIN" --profile minimal --no-self-update/u,
  );
  assert.match(
    rustBootstrap,
    /cargo" fetch --locked --manifest-path "\$candidate_root\/Cargo\.toml"/u,
  );
  assert.match(rustBootstrap, /cargo" metadata --locked --offline --format-version 1/u);
  assert.match(rustBootstrap, /export CARGO_HOME="\\\$cargo_home"/u);
  assert.match(rustBootstrap, /export CARGO_TARGET_DIR="\\\$HOME\/\.cargo-target"/u);
  assert.match(
    rustBootstrap,
    /ln -s \/opt\/trusted-rust\/cargo-cache\/registry "\\\$cargo_home\/registry"/u,
  );
  assert.match(rustBootstrap, /chown -R 0:0 \/opt\/trusted-rust/u);
  assert.match(rustBootstrap, /find \/opt\/trusted-rust -perm \/022 -print -quit/u);
  assert.doesNotMatch(rustBootstrap, /sh\.rustup\.rs|curl[^\n]*rustup|wget[^\n]*rustup/u);

  assert.match(outputGrant, /packages\/adapters\/host-path-posix-native\/dist/u);
  assert.match(outputGrant, /sudo -u gatecandidate test -w "\$output_path"/u);
  assert.match(outputGrant, /readonly_paths=\(/u);
  assert.match(outputGrant, /packages\/adapters\/host-path-posix-native\/src\/index\.ts/u);
  assert.match(outputGrant, /if sudo -u gatecandidate test -w "\$readonly_path"/u);
  assert.doesNotMatch(outputGrant, /chown -R 20001:20001 "\$candidate_root"/u);

  assert.match(portableEvidence, /TRUSTED_RUST_BIN: \/opt\/trusted-rust\/bin/u);
  assert.match(
    portableEvidence,
    /PATH="\$TRUSTED_RUST_BIN:\$TRUSTED_PNPM_BIN:\$PATH"/u,
  );
});

test("portable producer 在 Harness 前建立真实签名 helper 与受支持 snapshot 运行面", async () => {
  const workflow = await readFile(workflowPath, "utf8");
  const portableJob = /\n  gate-execution:\s*[\s\S]*?(?=\n  gate-execution-win32:)/u.exec(workflow)?.[0];
  const filesystemStep = /- name: Create supported btrfs snapshot filesystem[\s\S]*?(?=\n\s+- name:)/u.exec(portableJob)?.[0];
  const provisionStep = /- name: Provision signed Linux host-path helper runtime[\s\S]*?(?=\n\s+- name:)/u.exec(portableJob)?.[0];
  const preflightStep = /- name: Verify real Linux host-path helper preflight[\s\S]*?(?=\n\s+- name:)/u.exec(portableJob)?.[0];
  const cleanupStep = /- name: Tear down portable helper and snapshot runtime[\s\S]*?(?=\n\s+- name:|$)/u.exec(portableJob)?.[0];

  assert.equal(typeof portableJob, "string");
  assert.equal(typeof filesystemStep, "string");
  assert.equal(typeof provisionStep, "string");
  assert.equal(typeof preflightStep, "string");
  assert.equal(typeof cleanupStep, "string");
  assert.match(portableJob, /runs-on:\s*ubuntu-24\.04/u);
  assert.ok(
    portableJob.indexOf("Create supported btrfs snapshot filesystem") <
      portableJob.indexOf("Provision signed Linux host-path helper runtime") &&
      portableJob.indexOf("Provision signed Linux host-path helper runtime") <
        portableJob.indexOf("Verify real Linux host-path helper preflight") &&
      portableJob.indexOf("Verify real Linux host-path helper preflight") <
        portableJob.indexOf("Produce child gate evidence"),
  );

  assert.match(filesystemStep, /command -v \/usr\/sbin\/mkfs\.btrfs/u);
  assert.match(filesystemStep, /--find --show "\$gate_image"/u);
  assert.match(filesystemStep, /mount -t btrfs/u);
  assert.match(filesystemStep, /findmnt --noheadings --output FSTYPE --target \/g/u);
  assert.match(filesystemStep, /\[\[ "\$gate_filesystem" == "btrfs" \]\]/u);
  assert.doesNotMatch(portableJob, /(?:apt-get|apt |dnf |yum |apk )/u);

  assert.match(provisionStep, /cargo build --locked --offline --release/u);
  assert.match(provisionStep, /--bin codegraph-host-path-bridge/u);
  assert.match(provisionStep, /--bin codegraph-host-path-daemon/u);
  assert.match(provisionStep, /\/usr\/libexec\/codegraph-host-path-bridge/u);
  assert.match(provisionStep, /\/usr\/libexec\/codegraph-host-path-daemon/u);
  assert.match(provisionStep, /\/etc\/codegraph-host-path\/client\.key/u);
  assert.match(provisionStep, /\/usr\/share\/codegraph-host-path\/provenance\.json/u);
  assert.match(provisionStep, /\/usr\/share\/codegraph-host-path\/release\.pub/u);
  assert.match(provisionStep, /\/run\/codegraph-host-path\/helper\.sock/u);
  assert.match(provisionStep, /randomBytes\(32\)/u);
  assert.match(provisionStep, /generateKeyPairSync\("ed25519"\)/u);
  assert.match(provisionStep, /bridgeBinarySha256/u);
  assert.match(provisionStep, /daemonBinarySha256/u);
  assert.match(provisionStep, /manifestSha256/u);
  assert.match(provisionStep, /signatureKeyId: `ci-job-scoped-/u);
  assert.match(provisionStep, /signerId: `ci-job-scoped-/u);
  assert.match(provisionStep, /sudo stat -c '%U:%G %a' \/etc\/codegraph-host-path\)" == "root:gatecandidate 750"/u);
  assert.match(provisionStep, /sudo stat -c '%U:%G %a' \/etc\/codegraph-host-path\/client\.key/u);
  assert.match(provisionStep, /sudo test -S \/run\/codegraph-host-path\/helper\.sock/u);
  assert.match(provisionStep, /sudo stat -c '%U:%G %a' \/run\/codegraph-host-path\/helper\.sock/u);
  assert.match(provisionStep, /\/run\/codegraph-host-path\/daemon\.pid/u);
  assert.match(provisionStep, /serve-v1/u);
  assert.doesNotMatch(provisionStep, /(?:release-root|release-signer|dummy|weak-provider)/iu);

  assert.match(preflightStep, /createInstalledLinuxSnapshotHelperBindingV1/u);
  assert.match(preflightStep, /captureHostPathPosixNativeV1/u);
  assert.match(preflightStep, /node_tool="\$\(realpath -- "\$\(command -v node\)"\)"/u);
  assert.match(preflightStep, /node_bin_dir="\$\(dirname -- "\$node_tool"\)"/u);
  assert.match(preflightStep, /\[\[ -f "\$node_tool" && ! -L "\$node_tool" && -x "\$node_tool" \]\]/u);
  assert.match(
    preflightStep,
    /PATH="\$node_bin_dir:\/opt\/trusted-pnpm\/bin:\/usr\/bin:\/bin"/u,
  );
  assert.equal(
    preflightStep.match(/PATH="\$node_bin_dir:\/usr\/bin:\/bin"/gu)?.length,
    2,
  );
  assert.match(preflightStep, /outcome\.status !== "complete"/u);
  assert.match(preflightStep, /outcome\.reason === "PROVIDER_ERROR"/u);
  assert.match(preflightStep, /binding\.provider\.capture/u);
  assert.match(preflightStep, /Linux helper bridge 失败：\(\[A-Z0-9_\]\{1,128\}\)\\s\*\$/u);
  assert.match(preflightStep, /stableMessageCodes/u);
  assert.match(preflightStep, /BRIDGE_RESPONSE_INVALID/u);
  assert.match(preflightStep, /RESPONSE_\(\?:SHAPE_INVALID\|BINDING_MISMATCH\)/u);
  assert.match(preflightStep, /\[codegraph-linux-helper\] bridge:/u);
  assert.doesNotMatch(preflightStep, /process\.stderr\.write\(`\$\{error/u);
  assert.match(preflightStep, /LINUX_HELPER_INITIALIZATION_FAILED/u);
  assert.match(preflightStep, /fail-closed preflight/u);
  assert.match(preflightStep, /release\.pub\.preflight-backup/u);
  assert.match(preflightStep, /invalid_public_key/u);
  assert.match(preflightStep, /sudo mv -- "\$release_backup" \/usr\/share\/codegraph-host-path\/release\.pub/u);
  assert.match(preflightStep, /sudo stat -c '%U:%G %a' \/etc\/codegraph-host-path\/client\.key/u);
  assert.match(preflightStep, /sudo stat -c '%U:%G %a' \/run\/codegraph-host-path\/helper\.sock/u);
  assert.doesNotMatch(
    portableJob,
    /CODEGRAPH_[A-Z0-9_]*(?:OVERRIDE|TEST_PROVIDER)|createTest[A-Za-z0-9]*Provider|dummy socket/iu,
  );

  const terminateOffset = cleanupStep.indexOf("HOST_PATH_DAEMON_PID");
  const bridgeOffset = cleanupStep.indexOf("codegraph-host-path-bridge");
  const unmountOffset = cleanupStep.indexOf("umount -- /g");
  const loopOffset = cleanupStep.indexOf('--detach "$GATE_BTRFS_LOOP"');
  const materialOffset = cleanupStep.indexOf("/etc/codegraph-host-path");
  assert.ok(
    terminateOffset >= 0 &&
      bridgeOffset > terminateOffset &&
      unmountOffset > bridgeOffset &&
      loopOffset > unmountOffset &&
      materialOffset > loopOffset,
  );
  assert.match(cleanupStep, /if mountpoint --quiet \/g/u);
  assert.match(cleanupStep, /if mountpoint --quiet \/g; then[\s\S]*umount -- \/g/u);
  assert.match(cleanupStep, /umount -- \/g \|\| cleanup_status=1/u);
  assert.match(cleanupStep, /sudo test -f \/run\/codegraph-host-path\/daemon\.pid/u);
  assert.match(cleanupStep, /sudo tr -d '\[:space:\]' \/run\/codegraph-host-path\/daemon\.pid/u);
  assert.doesNotMatch(cleanupStep, /<\/run\/codegraph-host-path\/daemon\.pid/u);
  assert.match(cleanupStep, /exit "\$cleanup_status"/u);
  assert.doesNotMatch(cleanupStep, /rm -rf -- \/g[\s\S]*umount -- \/g/u);
});

test("Portable helper 私有 build home 由正确身份逐项证明，拒绝 runner 跨 UID 盲断言", async () => {
  const workflow = await readFile(workflowPath, "utf8");
  const provisionStep = extractPortableHelperProvisionStep(workflow);

  assert.match(
    provisionStep,
    /install -d -o 20001 -g 20001 -m 0700 "\$helper_build_home"/u,
  );
  assert.doesNotMatch(provisionStep, /chmod[^\n]*helper_build_home/u);
  assert.doesNotMatch(
    provisionStep,
    /\[\[ -f "\$(?:bridge|daemon)_source" && ! -L "\$(?:bridge|daemon)_source"/u,
  );
  assert.match(provisionStep, /helper-proof\[\$label\] parent-traversal/u);
  assert.match(provisionStep, /sudo -u gatecandidate test -x "\$source_parent"/u);
  assert.match(provisionStep, /sudo test -f "\$source"/u);
  assert.match(provisionStep, /if sudo test -L "\$source"/u);
});

test("Portable helper 在目标用户 Cargo 进程内固定安全 umask", async () => {
  const workflow = await readFile(workflowPath, "utf8");
  const provisionStep = extractPortableHelperProvisionStep(workflow);
  const sudoOffset = provisionStep.indexOf(
    'sudo -u gatecandidate env -i --chdir="$candidate_root"',
  );
  const candidateShellOffset = provisionStep.indexOf(
    "/bin/bash --noprofile --norc -c '",
    sudoOffset,
  );
  const umaskOffset = provisionStep.indexOf("umask 0022", candidateShellOffset);
  const cargoOffset = provisionStep.indexOf(
    "exec /opt/trusted-rust/bin/cargo build",
    umaskOffset,
  );
  const candidateShellEnd = provisionStep.indexOf(
    `' bash "$helper_manifest"`,
    cargoOffset,
  );

  assert.ok(sudoOffset >= 0, "helper 构建必须以 gatecandidate 身份启动。");
  assert.ok(candidateShellOffset > sudoOffset, "umask 必须由目标用户的实际子进程设置。");
  assert.ok(umaskOffset > candidateShellOffset, "目标用户子进程必须显式固定 restrictive umask。");
  assert.ok(cargoOffset > umaskOffset, "restrictive umask 必须先于 Cargo 创建 executable 生效。");
  assert.ok(candidateShellEnd > cargoOffset, "Cargo 必须保持在目标用户的受控子进程内。");
  // 外层 umask 无法约束 sudo 为目标身份建立的新进程，合同只接受子进程内策略。
  assert.doesNotMatch(
    provisionStep.slice(0, candidateShellOffset),
    /^\s*umask\s+0022\s*$/mu,
    "不得用 sudo 外层 umask 冒充目标用户进程的创建权限策略。",
  );
  assert.match(
    provisionStep.slice(candidateShellOffset, candidateShellEnd),
    /--manifest-path "\$1"/u,
  );
  assert.doesNotMatch(
    provisionStep,
    /chmod[^\n]*(?:bridge_source|daemon_source|\.cargo-target\/release)/u,
    "候选产物不得在证明前通过 chmod 事后修补。",
  );
});

test("Portable helper 从 Cargo JSON 唯一归因两个 executable 并保留 Cargo exit code", async () => {
  const workflow = await readFile(workflowPath, "utf8");
  const provisionStep = extractPortableHelperProvisionStep(workflow);

  assert.match(provisionStep, /--message-format=json-render-diagnostics/u);
  assert.match(provisionStep, /cargo_status=\$\?/u);
  assert.match(provisionStep, /exit "\$cargo_status"/u);
  assert.match(provisionStep, /message\.reason !== "compiler-artifact"/u);
  assert.match(provisionStep, /executablePaths\.size !== 1/u);
  assert.match(provisionStep, /expected_bridge_source="\$helper_build_home\/\.cargo-target\/release\/codegraph-host-path-bridge"/u);
  assert.match(provisionStep, /expected_daemon_source="\$helper_build_home\/\.cargo-target\/release\/codegraph-host-path-daemon"/u);
  assert.match(provisionStep, /cargo-topology\[bridge\]: resolved=%s expected=%s/u);
  assert.match(provisionStep, /cargo-topology\[daemon\]: resolved=%s expected=%s/u);
  assert.match(provisionStep, /if \[\[ "\$bridge_source" != "\$expected_bridge_source" \]\]; then/u);
  assert.match(provisionStep, /if \[\[ "\$daemon_source" != "\$expected_daemon_source" \]\]; then/u);
  assert.doesNotMatch(provisionStep, /^\s*\[\[ "\$(?:bridge|daemon)_source" ==/mu);
});

test("Portable trusted distro symlink alias 解析到可信 regular executable target", async () => {
  const workflow = await readFile(workflowPath, "utf8");
  const provisionStep = extractPortableHelperProvisionStep(workflow);

  assert.doesNotMatch(
    provisionStep,
    /\[\[ -f "\$readelf_tool" && ! -L "\$readelf_tool" && -x "\$readelf_tool" \]\]/u,
    "首个失败谓词：! -L /usr/bin/readelf 错误拒绝可信 distro symlink alias。",
  );
  const policyFunction = extractTrustedToolPolicyFunction(provisionStep);
  const result = runTrustedToolPolicyFixture(policyFunction, [
    "readelf",
    "/usr/bin/readelf",
    "symbolic link",
    "0",
    "0",
    "777",
    "/usr/bin/x86_64-linux-gnu-readelf",
    "regular file",
    "0",
    "0",
    "755",
    "yes",
    "yes",
    "yes",
  ]);

  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /trusted-tool\[readelf\] proof:/u);
  assert.match(result.stdout, /alias=\/usr\/bin\/readelf/u);
  assert.match(result.stdout, /resolved=\/usr\/bin\/x86_64-linux-gnu-readelf/u);
});

test("Portable trusted tool 策略对危险 target 与身份漂移全部 fail-closed", async () => {
  const workflow = await readFile(workflowPath, "utf8");
  const provisionStep = extractPortableHelperProvisionStep(workflow);
  const policyFunction = extractTrustedToolPolicyFunction(provisionStep);
  const trustedFixture = [
    "readelf",
    "/usr/bin/readelf",
    "symbolic link",
    "0",
    "0",
    "777",
    "/usr/bin/x86_64-linux-gnu-readelf",
    "regular file",
    "0",
    "0",
    "755",
    "yes",
    "yes",
    "yes",
  ];
  const cases = [
    ["dangling symlink", 6, "", /resolved-target: fail/u],
    ["non-root target", 8, "1000", /target-owner: fail/u],
    ["group-writable target", 10, "775", /target-mode: fail/u],
    ["world-writable target", 10, "757", /target-mode: fail/u],
    ["non-regular target", 7, "directory", /target-regular: fail/u],
    ["non-executable target", 11, "no", /target-executable: fail/u],
    ["escaped target", 6, "/tmp/readelf", /resolved-policy: fail/u],
    ["alias identity drift", 12, "no", /alias-stable: fail/u],
    ["target identity drift", 13, "no", /target-stable: fail/u],
  ];

  for (const [name, index, value, expectedFailure] of cases) {
    const fixture = [...trustedFixture];
    fixture[index] = value;
    const result = runTrustedToolPolicyFixture(policyFunction, fixture);

    assert.notEqual(result.status, 0, `${name} 必须被拒绝。`);
    assert.match(result.stderr, expectedFailure, `${name} 未命中预期首个拒绝谓词。`);
  }
});

test("Portable helper 对两个 binary 输出可归因的文件、ELF 与候选身份诊断", async () => {
  const workflow = await readFile(workflowPath, "utf8");
  const provisionStep = extractPortableHelperProvisionStep(workflow);
  const requiredDiagnostics = [
    "lstat",
    "regular",
    "non-symlink",
    "owner-group",
    "numeric-mode",
    "size",
    "sha256",
    "file",
    "elf-class",
    "elf-machine",
    "elf-type",
    "gatecandidate-x-ok",
  ];

  for (const diagnostic of requiredDiagnostics) {
    assert.match(
      provisionStep,
      new RegExp(`helper-proof\\[(?:\\$label|%s)\\] ${diagnostic}`, "u"),
      `缺少 ${diagnostic} 可归因诊断。`,
    );
  }
  assert.match(provisionStep, /"\$file_tool" --brief -- "\$source"/u);
  assert.match(provisionStep, /"\$readelf_tool" -h -- "\$source"/u);
  assert.match(provisionStep, /prove_private_binary bridge "\$bridge_source"/u);
  assert.match(provisionStep, /prove_private_binary daemon "\$daemon_source"/u);
});

test("Portable helper 以 gatecandidate 真实执行零参数 probe 并精确拒绝异常输出", async () => {
  const workflow = await readFile(workflowPath, "utf8");
  const provisionStep = extractPortableHelperProvisionStep(workflow);

  assert.match(provisionStep, /run_zero_argument_probe bridge "\$bridge_source" BRIDGE_ARGV/u);
  assert.match(provisionStep, /run_zero_argument_probe daemon "\$daemon_source" DAEMON_ARGV/u);
  assert.match(
    provisionStep,
    /sudo -u gatecandidate env -i[\s\S]*?"\$source" > "\$probe_stdout" 2> "\$probe_stderr"/u,
  );
  assert.match(provisionStep, /case "\$probe_status" in\s+126\|127\)/u);
  assert.match(provisionStep, /permission denied\|exec format/u);
  assert.match(provisionStep, /\[\[ ! -s "\$probe_stdout" \]\]/u);
  assert.match(
    provisionStep,
    /cmp --silent -- "\$probe_stderr" <\(printf '%s\\n' "\$expected_stderr"\)/u,
  );
});

test("Portable helper 冻结 candidate 私有输出后只签名并安装 runner-owned staged bytes", async () => {
  const workflow = await readFile(workflowPath, "utf8");
  const provisionStep = extractPortableHelperProvisionStep(workflow);
  const killOffset = provisionStep.indexOf("sudo pkill -KILL -u 20001");
  const freezeOffset = provisionStep.indexOf("freeze_private_binary bridge");
  const signOffset = provisionStep.indexOf('node --input-type=module <<\'NODE\'');

  assert.ok(killOffset >= 0 && freezeOffset > killOffset && signOffset > freezeOffset);
  assert.match(provisionStep, /if sudo pgrep -u 20001/u);
  assert.match(
    provisionStep,
    /sudo install -o "\$runner_uid" -g "\$runner_gid" -m 0700 "\$source" "\$staged"/u,
  );
  assert.match(provisionStep, /\[\[ "\$source_sha" == "\$staged_sha" \]\]/u);
  assert.match(provisionStep, /BRIDGE_SOURCE="\$bridge_staged"/u);
  assert.match(provisionStep, /DAEMON_SOURCE="\$daemon_staged"/u);
  assert.match(
    provisionStep,
    /install -o 0 -g 0 -m 0755 "\$bridge_staged" \/usr\/libexec\/codegraph-host-path-bridge/u,
  );
  assert.match(
    provisionStep,
    /install -o 0 -g 0 -m 0755 "\$daemon_staged" \/usr\/libexec\/codegraph-host-path-daemon/u,
  );
  assert.match(provisionStep, /\[\[ "\$bridge_sha" == "\$bridge_staged_sha" \]\]/u);
  assert.match(provisionStep, /\[\[ "\$daemon_sha" == "\$daemon_staged_sha" \]\]/u);
});

test("Win32 blocking gate 只在 windows-latest/NTFS runner 执行并由干净 job 合并", async () => {
  const workflow = await readFile(workflowPath, "utf8");
  const portableJob = /\n  gate-execution:\s*[\s\S]*?(?=\n  gate-execution-win32:)/u.exec(workflow)?.[0];
  const win32Job = /\n  gate-execution-win32:\s*[\s\S]*?(?=\n  gate-evidence:)/u.exec(workflow)?.[0];
  const attestationJob = /\n  gate-evidence:\s*[\s\S]*$/u.exec(workflow)?.[0];

  assert.equal(typeof portableJob, "string");
  assert.equal(typeof win32Job, "string");
  assert.equal(typeof attestationJob, "string");
  assert.match(portableJob, /runs-on:\s*ubuntu-24\.04/u);
  assert.match(portableJob, /--execution-partition portable/u);
  assert.doesNotMatch(portableJob, /--execution-partition win32/u);
  assert.match(win32Job, /runs-on:\s*windows-latest/u);
  assert.match(win32Job, /shell:\s*pwsh/u);
  assert.ok(
    win32Job.indexOf("Enforce byte-exact LF checkout") <
      win32Job.indexOf("Checkout immutable GateHarness"),
  );
  assert.match(win32Job, /git config --global core\.autocrlf false/u);
  assert.match(win32Job, /git config --global core\.eol lf/u);
  assert.match(win32Job, /--execution-partition', 'win32'/u);
  assert.match(win32Job, /--harness-contract-version', '4'/u);
  assert.match(
    win32Job,
    /--host-path-invocation-attestation', \$env:HOST_PATH_INVOCATION_ATTESTATION/u,
  );
  assert.match(win32Job, /--path-sentinel-marker', \$env:PATH_SENTINEL_MARKER/u);
  assert.match(win32Job, /--trusted-pnpm-executable', \$env:TRUSTED_PNPM_EXE/u);
  assert.match(win32Job, /--win32-preflight-artifact', \$env:WIN32_PREFLIGHT_ARTIFACT/u);
  assert.doesNotMatch(win32Job, /--gate-(?:uid|gid)/u);
  assert.match(win32Job, /pnpm-win32-x64\.zip/u);
  assert.match(win32Job, new RegExp(`PNPM_ARCHIVE_SHA256: ${pnpmWin32ArchiveSha256}`, "u"));
  assert.match(win32Job, new RegExp(`PNPM_ENTRY_SHA256: ${pnpmWin32EntrySha256}`, "u"));
  assert.match(win32Job, new RegExp(`PNPM_ENTRY_SIZE: '${pnpmWin32EntrySize}'`, "u"));
  assert.match(win32Job, /Get-FileHash -Algorithm SHA256/u);
  assert.match(win32Job, /Get-Volume -ErrorAction Stop/u);
  assert.match(win32Job, /Wait-Job -Job \$job -Timeout 30/u);
  assert.match(win32Job, /fileSystem = \$null/u);
  assert.match(win32Job, /DriveType -ne 'Fixed'/u);
  assert.match(win32Job, /FileSystem -ne 'NTFS'/u);
  assert.match(win32Job, /WIN32_PREFLIGHT_ARTIFACT=\$artifactPath/u);
  assert.match(win32Job, /GATE_TEMP=\$\(\$report\.selectedRoot\)/u);
  assert.match(win32Job, /TEMP=\$\(\$report\.selectedRoot\)/u);
  assert.match(win32Job, /TMPDIR=\$\(\$report\.selectedRoot\)/u);
  assert.match(
    win32Job,
    /node trusted-harness\/bin\/install-trusted-pnpm-win32\.mjs --archive \$archive --trusted-root \$trustedRoot/u,
  );
  assert.match(win32Job, /TRUSTED_PNPM_EXE=\$trustedPnpm/u);
  assert.match(win32Job, /\$trustedItem\.Length -ne \[int64\]\$env:PNPM_ENTRY_SIZE/u);
  assert.match(win32Job, /\$actualEntrySha -ne \$env:PNPM_ENTRY_SHA256/u);
  assert.match(win32Job, /\$trustedPnpm = \$env:TRUSTED_PNPM_EXE/u);
  assert.match(win32Job, /\[IO\.Path\]::IsPathFullyQualified\(\$trustedPnpm\)/u);
  assert.match(win32Job, /\[IO\.Path\]::GetFileName\(\$trustedPnpm\) -ine 'pnpm\.exe'/u);
  assert.match(win32Job, /\$trustedItem\.PSIsContainer/u);
  assert.match(win32Job, /\[IO\.FileAttributes\]::ReparsePoint/u);
  assert.match(win32Job, /可信 pnpm launcher SHA-256 漂移/u);
  assert.match(win32Job, /\$pnpmVersion\.Trim\(\) -ne '11\.12\.0'/u);
  assert.match(win32Job, /Get-Command pnpm -All/u);
  assert.match(win32Job, /Remove-Item Env:npm_execpath/u);
  assert.match(win32Job, /PATH_SENTINEL_MARKER=\$sentinelMarker/u);
  assert.match(win32Job, /PATH=\$sentinelRoot;\$env:PATH/u);
  assert.match(win32Job, /恶意 PATH pnpm sentinel 被调用/u);
  assert.ok(
    win32Job.indexOf("Install frozen dependencies without candidate lifecycle") <
      win32Job.indexOf("Build exact ordered workspace closure for Win32 gate"),
  );
  assert.ok(
    win32Job.indexOf("Build exact ordered workspace closure for Win32 gate") <
      win32Job.indexOf("Produce Win32 host identity evidence"),
  );
  const buildClosure = /- name: Build exact ordered workspace closure for Win32 gate[\s\S]*?(?=\n\s+- name:)/u.exec(win32Job)?.[0];
  assert.equal(typeof buildClosure, "string");
  let previousBuildOffset = -1;
  for (const packageName of win32OrderedBuildClosure) {
    const packageOffset = buildClosure.indexOf(`Name = '${packageName}'`);
    assert.ok(packageOffset > previousBuildOffset, `${packageName} 必须按依赖顺序构建。`);
    previousBuildOffset = packageOffset;
  }
  assert.match(buildClosure, /ProcessStartInfo/u);
  assert.match(buildClosure, /UseShellExecute = \$false/u);
  assert.match(buildClosure, /FileName = \$trustedPnpm/u);
  assert.match(buildClosure, /ArgumentList\.Add/u);
  assert.match(buildClosure, /npm_config_enable_pre_post_scripts'\] = 'false'/u);
  assert.match(buildClosure, /npm_config_ignore_pnpmfile'\] = 'true'/u);
  assert.match(buildClosure, /npm_config_verify_deps_before_run'\] = 'false'/u);
  assert.match(buildClosure, /PNPM_CONFIG_IGNORE_PNPMFILE'\] = 'true'/u);
  assert.match(buildClosure, /foreach \(\$relativeOutput in \$build\.Outputs\)/u);
  assert.match(buildClosure, /\$item\.PSIsContainer/u);
  assert.match(buildClosure, /\[IO\.FileAttributes\]::ReparsePoint/u);
  assert.match(buildClosure, /构建输出不是普通非 reparse 文件/u);
  assert.match(buildClosure, /构建造成 tracked 漂移/u);
  assert.doesNotMatch(win32Job, /--filter @codegraph\/adapter-host-path-posix-native[^\n]*run build/u);
  assert.ok(
    win32Job.indexOf("Revalidate trusted pnpm launcher for evidence") <
      win32Job.indexOf("Produce Win32 host identity evidence"),
  );
  assert.doesNotMatch(win32Job, /Expand-Archive|GITHUB_PATH|TRUSTED_PNPM_BIN/u);
  assert.doesNotMatch(win32Job, /PATH=.*TRUSTED_PNPM/u);
  assert.doesNotMatch(win32Job, /^\s*(?:&\s*)?pnpm(?:\.exe)?\s/mu);
  assert.match(
    win32Job,
    /install --frozen-lockfile --ignore-pnpmfile --ignore-scripts/u,
  );
  assert.match(win32Job, /Win32 host identity blocking gate 失败/u);
  assert.match(win32Job, /Reject empty Win32 host identity test collection/u);
  assert.match(win32Job, /if: \$\{\{ always\(\) \}\}/u);
  assert.match(win32Job, /\(\\s\*0 tests\?\\s\*\\\)|\\bno tests\\b/u);
  assert.match(win32Job, /\\bTests\\s\+\[1-9\]\[0-9\]\*\\s\+passed\\b/u);
  assert.match(win32Job, /gate-evidence-win32-raw-/u);
  assert.doesNotMatch(workflow, /continue-on-error:\s*true/u);

  assert.match(attestationJob, /Checkout immutable GateHarness for clean merge/u);
  assert.match(attestationJob, new RegExp(`ref: ${trustedHarnessSha}`, "u"));
  assert.match(attestationJob, /gate-evidence-portable-raw-/u);
  assert.match(attestationJob, /gate-evidence-win32-raw-/u);
  assert.match(attestationJob, /produce-gate-evidence\.mjs merge/u);
  assert.match(attestationJob, /--input-artifacts-json/u);
  assert.ok(
    attestationJob.indexOf("produce-gate-evidence.mjs merge") <
      attestationJob.indexOf("Attest exact evidence artifact"),
  );
});

test("Controller canonical producer 只来自已验证 approval", async () => {
  const approval = JSON.parse(
    await readFile(new URL("../trusted/registry-approval.json", import.meta.url), "utf8"),
  );
  const controller = await readFile(
    new URL("../bin/run-controller.mjs", import.meta.url),
    "utf8",
  );

  assert.doesNotMatch(controller, /const producerWorkflowSha = "[a-f0-9]{40}";/u);
  assert.doesNotMatch(controller, new RegExp(approval.producerWorkflowSha, "u"));
  assert.match(
    controller,
    /expectedProducerWorkflowSha: trustedApproval\.producerWorkflowSha/u,
  );
  assert.match(
    controller,
    /canonicalProducerWorkflowSha: trustedApproval\.producerWorkflowSha/u,
  );
  assert.equal(approval.producerWorkflowSha, "b5bb1069f93fb92640d23df2b803401d4537f59d");
  assert.match(controller, /"--signer-workflow"/u);
  assert.match(controller, /"--signer-digest"/u);
  assert.doesNotMatch(controller, /"--signer-repo"/u);
  assert.match(
    controller,
    /trustedState = await loadState\(\);[\s\S]*?await assertFresh\(\);[\s\S]*?pulls = await listPulls\(\);[\s\S]*?catch \(error\)[\s\S]*?await revokePulls/u,
  );
  assert.match(
    controller,
    /for \(let attempt = 0; attempt < 5; attempt \+= 1\)[\s\S]*?listOpenPullsBestEffort\(\)[\s\S]*?publishDriftFailureForOpenPulls[\s\S]*?sameCurrentPullSnapshot/u,
  );
  assert.match(controller, /assertUniqueOpenPullHeads\(pulls\)/u);
  assert.match(controller, /selectLatestWorkflowRun\(runs, headOid, pull\.number\)/u);
  assert.match(controller, /assertTrustedCandidateSelectionCurrent/u);
  assert.match(controller, /closePublishedSuccess/u);
  assert.match(controller, /publishCheckForStablePull/u);
  assert.match(controller, /check-runs\?filter=all/u);
  assert.match(controller, /allowFailureOnHistoryError/u);
  assert.match(
    controller,
    /"drift-monitor-invalid"[\s\S]*?"controller-invalid"[\s\S]*?trustedSequence/u,
  );
});

test("Controller 从 candidate authorization 选择 producer 并贯穿 attestation", async () => {
  const [controller, harness, proposedApproval] = await Promise.all([
    readFile(new URL("../bin/run-controller.mjs", import.meta.url), "utf8"),
    readFile(harnessPath, "utf8"),
    readFile(
      new URL(
        "../trusted/proposed/833c11094b9189f2aaefbe85bbc811c504dda0e1.approval.json",
        import.meta.url,
      ),
      "utf8",
    ).then(JSON.parse),
  ]);

  assert.doesNotMatch(
    controller,
    /const producerWorkflowSha = "[a-f0-9]{40}";/u,
  );
  assert.doesNotMatch(controller, new RegExp(proposedApproval.producerWorkflowSha, "u"));
  assert.match(controller, /canonicalProducerWorkflowSha: trustedApproval\.producerWorkflowSha/u);
  assert.match(controller, /selectCandidateAuthorization/u);
  assert.match(controller, /candidateAuthorization\.producerWorkflowSha/u);
  assert.match(
    controller,
    /"--signer-digest",\s*candidateAuthorization\.producerWorkflowSha/u,
  );
  assert.match(
    controller,
    /producerWorkflowSha: candidateAuthorization\.producerWorkflowSha/u,
  );
  assert.match(controller, /trustedRecord: candidateAuthorization\.record/u);
  assert.match(
    controller,
    /assertTrustedCandidateSelectionCurrent\(\s*candidateAuthorization/u,
  );
  assert.match(harness, /producer\.workflowSha !== options\.workflowSha/u);
});

test("monitor 完成事件直接触发 Controller，可信 lease guardian 持续撤销过期 success", async () => {
  const controllerWorkflow = await readFile(controllerWorkflowPath, "utf8");
  const monitorWorkflow = await readFile(monitorWorkflowPath, "utf8");
  const controller = await readFile(
    new URL("../bin/run-controller.mjs", import.meta.url),
    "utf8",
  );
  const guardian = await readFile(
    new URL("../bin/run-controller-lease-guardian.mjs", import.meta.url),
    "utf8",
  );
  const policy = await readFile(
    new URL("../lib/controller-policy.mjs", import.meta.url),
    "utf8",
  );

  assert.match(monitorWorkflow, /push:\s*\n\s+branches: \[main\]/u);
  assert.match(monitorWorkflow, /workflow_dispatch:\s*\n\s*schedule:/u);
  assert.match(controllerWorkflow, /workflow_dispatch:\s*\n\s*schedule:/u);
  assert.match(monitorWorkflow, /cron: "2-59\/5 \* \* \* \*"/u);
  assert.match(controllerWorkflow, /cron: "4-59\/5 \* \* \* \*"/u);
  assert.match(
    controllerWorkflow,
    /workflow_run:\s*\n\s+workflows: \["architecture-drift-monitor"\]\s*\n\s+types: \[completed\]\s*\n\s+branches: \[main\]/u,
  );
  assert.match(
    controllerWorkflow,
    /concurrency:\s*\n\s+group: architecture-gate-controller\s*\n\s+cancel-in-progress: false/u,
  );
  assert.match(controllerWorkflow, /CONTROLLER_TRUSTED_SHA: \$\{\{ github\.sha \}\}/u);
  assert.match(controllerWorkflow, /node bin\/run-controller-lease-guardian\.mjs/u);
  assert.match(controllerWorkflow, /timeout-minutes: 55/u);
  assert.match(controllerWorkflow, /ref: \$\{\{ github\.sha \}\}/u);
  assert.match(monitorWorkflow, /ref: \$\{\{ github\.sha \}\}/u);
  assert.match(controllerWorkflow, /permissions:\s*\n\s+actions: write\s*\n\s+contents: read/u);
  assert.match(
    controller,
    /actions\/workflows\/drift-monitor\.yml\/runs["`] \+\s*\n\s*`\?branch=\$\{encodeURIComponent\(controllerDefaultBranch\)\}&per_page=100`/u,
  );
  assert.match(controller, /actions\/workflows\/drift-monitor\.yml\/dispatches/u);
  assert.match(controller, /body: \{ ref: controllerDefaultBranch \}/u);
  assert.match(controller, /method: "POST"/u);
  assert.match(controller, /token: controllerRepositoryToken/u);
  assert.match(controller, /timeoutMs: 5_000/u);
  assert.match(controller, /monitorRefreshState: controllerMonitorRefreshState/u);
  assert.match(
    guardian,
    /actions\/workflows\/\$\{controllerWorkflowPath\}\/dispatches/u,
  );
  assert.match(guardian, /body: \{ ref: controllerDefaultBranch \}/u);
  assert.match(guardian, /process\.env\.CONTROLLER_REPOSITORY_TOKEN/u);
  assert.match(guardian, /timeoutMs: 5_000,\s*\n\s+token,/u);
  assert.match(guardian, /timeoutMs: 5_000/u);
  assert.match(guardian, /requiredCycleReservationMs/u);
  assert.match(guardian, /ControllerCycleDeadlineError/u);
  assert.match(policy, /6 \* 60 \* 1000/u);
  assert.match(policy, /15 \* 60 \* 1000/u);
  assert.doesNotMatch(controllerWorkflow, /workflow_dispatch:\s*\n\s+inputs:/u);
  assert.doesNotMatch(monitorWorkflow, /workflow_dispatch:\s*\n\s+inputs:/u);
});

test("阶段 B producer 显式升级 Harness V4 并保留 V3 参数边界", async () => {
  const workflow = await readFile(workflowPath, "utf8");

  assert.equal(GATE_HARNESS_CONTRACT_VERSION, 4);
  assert.deepEqual(GATE_HARNESS_PORTABLE_ARGUMENT_NAMES_V3, [
    "--artifact-directory",
    "--base-oid",
    "--candidate-root",
    "--controller-repository",
    "--execution-partition",
    "--gate-gid",
    "--gate-home",
    "--gate-temp-directory",
    "--gate-uid",
    "--head-oid",
    "--object-format",
    "--proposed-record-directory",
    "--provider-repository-id",
    "--pull-number",
    "--trusted-record",
    "--workflow-file",
    "--workflow-sha",
  ]);
  assert.deepEqual(
    GATE_HARNESS_WIN32_ARGUMENT_NAMES_V3,
    GATE_HARNESS_PORTABLE_ARGUMENT_NAMES_V3.filter(
      (name) => name !== "--gate-gid" && name !== "--gate-uid",
    ),
  );
  assert.deepEqual(
    GATE_HARNESS_PORTABLE_ARGUMENT_NAMES_V4,
    [...GATE_HARNESS_PORTABLE_ARGUMENT_NAMES_V3, "--harness-contract-version"].sort(),
  );
  assert.deepEqual(
    GATE_HARNESS_WIN32_ARGUMENT_NAMES_V4,
    [
      ...GATE_HARNESS_WIN32_ARGUMENT_NAMES_V3,
      "--harness-contract-version",
      "--host-path-invocation-attestation",
      "--path-sentinel-marker",
      "--trusted-pnpm-executable",
      "--win32-preflight-artifact",
    ].sort(),
  );
  assert.match(workflow, /--pull-number "\$PULL_NUMBER"/u);
  assert.match(
    workflow,
    /--proposed-record-directory "\$PWD\/trusted-state\/trusted\/proposed"/u,
  );
  assert.doesNotMatch(workflow, /阶段 A 保留 V1 pin/u);
});

test("drift monitor 完整分页读取 ruleset 列表", async () => {
  const monitor = await readFile(
    new URL("../bin/run-drift-monitor.mjs", import.meta.url),
    "utf8",
  );

  assert.match(monitor, /collectGithubPages\(\{/u);
  assert.match(monitor, /rulesets\?includes_parents=false/u);
  assert.doesNotMatch(
    monitor,
    /const summaries = await githubJson\(`repos\/\$\{targetRepository\}\/rulesets/u,
  );
});

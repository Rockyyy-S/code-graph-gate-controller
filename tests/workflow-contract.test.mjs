import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
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
const trustedHarnessSha = "97048ec0c2f6a38716bf3c0b38ac8c6bf31c709f";
const pnpmArchiveSha256 = "dd19bfd8bcd33a3b38dcce335e8d233194c0a61ffe1f5bcf5047f60f6d4978b8";
const pnpmWin32ArchiveSha256 =
  "7ac25ba81b8a9f213a307ae89198ba7e636e6c74fa0d775d554ba46e0187358b";
const pnpmWin32EntrySha256 =
  "0a8b6b9d6f391bb83e868a3f951eec74fb8f745c176fce523a9359f40b20fb7b";
const pnpmWin32EntrySize = 98099528;
const betterSqliteIntegrity =
  "sha512-dq9AtApgg5PGFtBzPFSBl3HZQjHok5gaQCM6zh2Yk0aSmDCs1CbnVI8/HgASQkNKsWFpseIO9beg5xxpYhbIfA==";

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
  assert.match(win32Job, /Wait-Job -Job \$job -Timeout 10/u);
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

  assert.equal(typeof checkoutBlock, "string");
  assert.match(checkoutBlock, /path: trusted-harness/u);
  assert.match(checkoutBlock, new RegExp(`ref: ${trustedHarnessSha}`, "u"));
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
  assert.match(workflow, /echo "GATE_TEMP_ROOT_CREATED=true" >> "\$GITHUB_ENV"/u);
  assert.match(workflow, /--gate-temp-directory \/g/u);
  assert.match(
    workflow,
    /if \[\[ "\$\{GATE_TEMP_ROOT_CREATED:-\}" == "true" \]\]; then\s+sudo rm -rf -- \/g\s+fi/u,
  );
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

test("Win32 blocking gate 只在 windows-latest/NTFS runner 执行并由干净 job 合并", async () => {
  const workflow = await readFile(workflowPath, "utf8");
  const portableJob = /\n  gate-execution:\s*[\s\S]*?(?=\n  gate-execution-win32:)/u.exec(workflow)?.[0];
  const win32Job = /\n  gate-execution-win32:\s*[\s\S]*?(?=\n  gate-evidence:)/u.exec(workflow)?.[0];
  const attestationJob = /\n  gate-evidence:\s*[\s\S]*$/u.exec(workflow)?.[0];

  assert.equal(typeof portableJob, "string");
  assert.equal(typeof win32Job, "string");
  assert.equal(typeof attestationJob, "string");
  assert.match(portableJob, /runs-on:\s*ubuntu-latest/u);
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
  assert.match(win32Job, /Wait-Job -Job \$job -Timeout 10/u);
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
      win32Job.indexOf("Build trusted POSIX adapter output for Win32 gate"),
  );
  assert.ok(
    win32Job.indexOf("Build trusted POSIX adapter output for Win32 gate") <
      win32Job.indexOf("Produce Win32 host identity evidence"),
  );
  assert.match(
    win32Job,
    /& \$trustedPnpm --dir \$candidateRoot exec tsc[\s\S]*packages\/adapters\/host-path-posix-native\/tsconfig\.build\.json/u,
  );
  assert.match(win32Job, /foreach \(\$lifecycle in @\('preinstall', 'install', 'postinstall'\)\)/u);
  assert.match(win32Job, /npm_config_enable_pre_post_scripts = 'false'/u);
  assert.match(win32Job, /npm_config_ignore_pnpmfile = 'true'/u);
  assert.match(win32Job, /'index\.js', 'index\.d\.ts', 'linux-helper\.js', 'linux-helper\.d\.ts'/u);
  assert.match(win32Job, /可信 POSIX adapter 构建造成 tracked 漂移/u);
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

test("Controller attestation policy 与已提升可信根 producer SHA 保持一致", async () => {
  const approval = JSON.parse(
    await readFile(new URL("../trusted/registry-approval.json", import.meta.url), "utf8"),
  );
  const controller = await readFile(
    new URL("../bin/run-controller.mjs", import.meta.url),
    "utf8",
  );

  assert.match(
    controller,
    new RegExp(`const producerWorkflowSha = "${approval.producerWorkflowSha}";`, "u"),
  );
  assert.match(
    controller,
    /expectedProducerWorkflowSha: trustedApproval\.producerWorkflowSha/u,
  );
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

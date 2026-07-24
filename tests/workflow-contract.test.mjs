import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const workflowPath = new URL("../.github/workflows/produce-gate-evidence.yml", import.meta.url);
const controllerWorkflowPath = new URL("../.github/workflows/controller.yml", import.meta.url);
const monitorWorkflowPath = new URL("../.github/workflows/drift-monitor.yml", import.meta.url);
const trustedHarnessSha = "9b76436d1e7cbb7e81b348f503f481fb00c06933";
const pnpmArchiveSha256 = "dd19bfd8bcd33a3b38dcce335e8d233194c0a61ffe1f5bcf5047f60f6d4978b8";

test("reusable producer 显式接收并绑定外部 workflow commit SHA", async () => {
  const workflow = await readFile(workflowPath, "utf8");

  assert.match(workflow, /producer_workflow_sha:\s*\n\s+required: true\s*\n\s+type: string/u);
  assert.match(workflow, /PRODUCER_WORKFLOW_SHA: \$\{\{ inputs\.producer_workflow_sha \}\}/u);
  assert.match(workflow, /--workflow-sha "\$PRODUCER_WORKFLOW_SHA"/u);
  assert.doesNotMatch(workflow, /github\.workflow_sha/u);
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
  const executionJob = /gate-execution:\s*[\s\S]*?(?=\n  gate-evidence:)/u.exec(workflow)?.[0];
  const attestationJob = /\n  gate-evidence:\s*[\s\S]*$/u.exec(workflow)?.[0];

  assert.equal(typeof executionJob, "string");
  assert.equal(typeof attestationJob, "string");
  assert.doesNotMatch(executionJob, /id-token:\s*write|attestations:\s*write/u);
  assert.match(attestationJob, /needs:\s*gate-execution/u);
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
  assert.match(workflow, /sudo rm -rf -- \/tmp\/gatecandidate-root/u);
  assert.match(workflow, /install -d -m 0700 artifacts/u);
  assert.match(workflow, /--gate-uid 20001/u);
  assert.match(workflow, /--gate-gid 20001/u);
  assert.match(workflow, /env -i HOME=/u);
});

test("Controller attestation policy 与已批准 producer SHA 保持一致", async () => {
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
  assert.match(controller, /"--signer-workflow"/u);
  assert.match(controller, /"--signer-digest"/u);
  assert.doesNotMatch(controller, /"--signer-repo"/u);
});

test("monitor 完成事件直接触发 Controller，定时兜底按顺序错开", async () => {
  const controllerWorkflow = await readFile(controllerWorkflowPath, "utf8");
  const monitorWorkflow = await readFile(monitorWorkflowPath, "utf8");

  assert.match(monitorWorkflow, /cron: "2-59\/5 \* \* \* \*"/u);
  assert.match(controllerWorkflow, /cron: "4-59\/5 \* \* \* \*"/u);
  assert.match(
    controllerWorkflow,
    /workflow_run:\s*\n\s+workflows: \["architecture-drift-monitor"\]\s*\n\s+types: \[completed\]/u,
  );
});

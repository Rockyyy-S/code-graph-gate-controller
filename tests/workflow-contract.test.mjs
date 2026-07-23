import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const workflowPath = new URL("../.github/workflows/produce-gate-evidence.yml", import.meta.url);
const trustedHarnessSha = "c5ea72c3e40607f59c01574d044e1c123ffeffec";

test("reusable producer 显式接收并绑定外部 workflow commit SHA", async () => {
  const workflow = await readFile(workflowPath, "utf8");

  assert.match(workflow, /producer_workflow_sha:\s*\n\s+required: true\s*\n\s+type: string/u);
  assert.match(workflow, /--workflow-sha "\$\{\{ inputs\.producer_workflow_sha \}\}"/u);
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

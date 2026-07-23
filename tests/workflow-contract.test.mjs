import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const workflowPath = new URL("../.github/workflows/produce-gate-evidence.yml", import.meta.url);

test("reusable producer 显式接收并绑定外部 workflow commit SHA", async () => {
  const workflow = await readFile(workflowPath, "utf8");

  assert.match(workflow, /producer_workflow_sha:\s*\n\s+required: true\s*\n\s+type: string/u);
  assert.match(workflow, /--workflow-sha "\$\{\{ inputs\.producer_workflow_sha \}\}"/u);
  assert.doesNotMatch(workflow, /github\.workflow_sha/u);
});

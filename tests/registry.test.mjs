import assert from "node:assert/strict";
import test from "node:test";
import { sha256CanonicalJson } from "../lib/canonical-json.mjs";
import { parseEvidenceProducerId, validateRegistry } from "../lib/registry.mjs";

const workflowSha = "1".repeat(40);

/** 创建摘要闭合的最小 registry。 */
function createRegistry(overrides = {}) {
  const gateDefinition = {
    blocking: true,
    capabilityOwner: "dev-enablement",
    checkId: "type",
    command: ["pnpm", "type"],
    evidenceProducerId: `gha-oidc://1303415307/Rockyyy-S/code-graph-gate-controller/.github/workflows/produce-gate-evidence.yml@${workflowSha}#type`,
    gateId: "type",
    ...overrides,
  };
  return {
    gates: [
      {
        gateDefinition,
        gateDefinitionDigest: sha256CanonicalJson(gateDefinition),
      },
    ],
    schemaVersion: 1,
  };
}

test("registry 验证 definition digest 与 producer identity", () => {
  const registry = createRegistry();
  assert.doesNotThrow(() => validateRegistry(registry));
  assert.deepEqual(parseEvidenceProducerId(registry.gates[0].gateDefinition.evidenceProducerId, "type"), {
    candidateRepositoryId: "1303415307",
    owner: "Rockyyy-S",
    repository: "code-graph-gate-controller",
    workflowFile: "produce-gate-evidence.yml",
    workflowSha,
  });
});

test("registry 对摘要漂移、未知字段和非法 trigger fail closed", () => {
  const drifted = createRegistry();
  drifted.gates[0].gateDefinitionDigest = "0".repeat(64);
  assert.throws(() => validateRegistry(drifted), /digest 漂移/u);

  const unknown = createRegistry();
  unknown.unknown = true;
  assert.throws(() => validateRegistry(unknown), /缺失或未知字段/u);

  const invalidTrigger = createRegistry({ triggerPaths: [] });
  assert.throws(() => validateRegistry(invalidTrigger), /triggerPaths/u);
});

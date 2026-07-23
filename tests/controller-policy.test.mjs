import assert from "node:assert/strict";
import test from "node:test";
import { sha256CanonicalJson } from "../lib/canonical-json.mjs";
import { evaluateControllerCandidate } from "../lib/controller-policy.mjs";

const workflowSha = "1".repeat(40);

/** 创建 registry/context/evidence 摘要闭合的 Controller 测试 fixture。 */
function createFixture() {
  const gateDefinition = {
    blocking: true,
    capabilityOwner: "qa",
    checkId: "unit",
    command: ["pnpm", "unit"],
    evidenceProducerId: `gha-oidc://1303415307/Rockyyy-S/code-graph-gate-controller/.github/workflows/produce-gate-evidence.yml@${workflowSha}#unit`,
    gateId: "unit",
  };
  const registry = {
    gates: [
      {
        gateDefinition,
        gateDefinitionDigest: sha256CanonicalJson(gateDefinition),
      },
    ],
    schemaVersion: 1,
  };
  const gateRegistryDigest = sha256CanonicalJson(registry);
  const contextInput = {
    baseOid: "a".repeat(40),
    comparisonBaseOid: "a".repeat(40),
    gateRegistryDigest,
    headOid: "b".repeat(40),
    objectFormat: "sha1",
    providerRepositoryId: "1303415307",
    schemaVersion: 1,
  };
  const evaluationContext = {
    ...contextInput,
    evaluationContextDigest: sha256CanonicalJson(contextInput),
  };
  const evidenceInput = {
    evaluationContextDigest: evaluationContext.evaluationContextDigest,
    evidenceProducerId: gateDefinition.evidenceProducerId,
    gateDefinitionDigest: registry.gates[0].gateDefinitionDigest,
    gateId: "unit",
    headOid: evaluationContext.headOid,
    outputDigest: "c".repeat(64),
    schemaVersion: 1,
    status: "pass",
  };
  const evidence = {
    ...evidenceInput,
    gateEvidenceDigest: sha256CanonicalJson(evidenceInput),
  };
  return {
    artifact: {
      affectedPaths: ["src/index.ts"],
      evaluationContext,
      evidence: [evidence],
      gateRegistryDigest,
      schemaVersion: 1,
    },
    currentProviderContext: {
      baseOid: evaluationContext.baseOid,
      headOid: evaluationContext.headOid,
      providerRepositoryId: evaluationContext.providerRepositoryId,
    },
    registry,
    trustedRecord: {
      approvalEvidenceDigest: "d".repeat(64),
      effectiveAt: "2026-07-23T00:00:00Z",
      gateRegistryDigest,
      providerRepositoryId: "1303415307",
      schemaVersion: 1,
      sequence: 1,
      sourceCommit: "e".repeat(40),
    },
  };
}

test("Controller 接受完整绑定的 pass evidence", () => {
  const fixture = createFixture();
  const result = evaluateControllerCandidate(fixture);
  assert.equal(result.status, "accepted");
  assert.equal(result.conclusion, "success");
  assert.match(result.casKey, /^1303415307:b{40}:/);
});

test("相同 digest 重放幂等，冲突 digest invalid", () => {
  const idempotent = createFixture();
  idempotent.artifact.evidence.push(structuredClone(idempotent.artifact.evidence[0]));
  assert.equal(evaluateControllerCandidate(idempotent).status, "accepted");

  const conflict = createFixture();
  conflict.artifact.evidence.push({
    ...structuredClone(conflict.artifact.evidence[0]),
    gateEvidenceDigest: "f".repeat(64),
  });
  assert.equal(evaluateControllerCandidate(conflict).status, "invalid");
});

test("拒绝旧 head、旧 registry、错误 producer 和缺失 required evidence", () => {
  const staleHead = createFixture();
  staleHead.currentProviderContext.headOid = "9".repeat(40);
  assert.equal(evaluateControllerCandidate(staleHead).status, "invalid");

  const oldRegistry = createFixture();
  oldRegistry.trustedRecord.gateRegistryDigest = "8".repeat(64);
  assert.equal(evaluateControllerCandidate(oldRegistry).status, "invalid");

  const producerMismatch = createFixture();
  producerMismatch.artifact.evidence[0].evidenceProducerId = producerMismatch.artifact.evidence[0].evidenceProducerId.replace(
    "Rockyyy-S",
    "attacker",
  );
  assert.deepEqual(evaluateControllerCandidate(producerMismatch).invalidGateIds, ["unit"]);

  const missing = createFixture();
  missing.artifact.evidence = [];
  assert.deepEqual(evaluateControllerCandidate(missing).missingEvidenceGateIds, ["unit"]);
});

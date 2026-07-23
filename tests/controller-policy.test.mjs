import assert from "node:assert/strict";
import test from "node:test";
import { sha256CanonicalJson } from "../lib/canonical-json.mjs";
import {
  evaluateControllerCandidate,
  selectFreshDriftMonitorRun,
} from "../lib/controller-policy.mjs";

const workflowSha = "1".repeat(40);
const gateImplementationDigest = "f".repeat(64);

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
      gateImplementationDigest,
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
      gateImplementationDigest,
      gateRegistryDigest,
      providerRepositoryId: "1303415307",
      schemaVersion: 1,
      sequence: 3,
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

test("Controller 不要求当前路径不适用的 blocking gate 证据", () => {
  const fixture = createFixture();
  fixture.registry.gates[0].gateDefinition.triggerPaths = ["docs/**"];
  fixture.registry.gates[0].gateDefinitionDigest = sha256CanonicalJson(
    fixture.registry.gates[0].gateDefinition,
  );
  fixture.trustedRecord.gateRegistryDigest = sha256CanonicalJson(fixture.registry);
  fixture.artifact.gateRegistryDigest = fixture.trustedRecord.gateRegistryDigest;
  fixture.artifact.evaluationContext.gateRegistryDigest = fixture.trustedRecord.gateRegistryDigest;
  const { evaluationContextDigest: _oldDigest, ...contextInput } =
    fixture.artifact.evaluationContext;
  fixture.artifact.evaluationContext.evaluationContextDigest =
    sha256CanonicalJson(contextInput);
  fixture.artifact.evidence = [];

  const result = evaluateControllerCandidate(fixture);
  assert.equal(result.status, "accepted");
  assert.deepEqual(result.missingEvidenceGateIds, []);
});

test("Controller 拒绝 artifact 未知字段和未批准实现摘要", () => {
  const unknownField = createFixture();
  unknownField.artifact.untrusted = true;
  assert.equal(evaluateControllerCandidate(unknownField).status, "invalid");

  const implementationDrift = createFixture();
  implementationDrift.artifact.gateImplementationDigest = "0".repeat(64);
  assert.equal(evaluateControllerCandidate(implementationDrift).status, "invalid");
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

test("Controller 接受最近成功的 schedule 或 workflow_dispatch monitor run", () => {
  const now = Date.parse("2026-07-23T07:00:00Z");
  const runs = [
    {
      conclusion: "success",
      event: "schedule",
      status: "completed",
      updated_at: "2026-07-23T06:40:00Z",
    },
    {
      conclusion: "success",
      event: "workflow_dispatch",
      status: "completed",
      updated_at: "2026-07-23T06:56:00Z",
    },
  ];
  assert.equal(selectFreshDriftMonitorRun(runs, now), runs[1]);
});

test("Controller 拒绝失败、过期或非可信事件的 monitor run", () => {
  const now = Date.parse("2026-07-23T07:00:00Z");
  for (const run of [
    {
      conclusion: "failure",
      event: "schedule",
      status: "completed",
      updated_at: "2026-07-23T06:59:00Z",
    },
    {
      conclusion: "success",
      event: "workflow_dispatch",
      status: "completed",
      updated_at: "2026-07-23T06:40:00Z",
    },
    {
      conclusion: "success",
      event: "push",
      status: "completed",
      updated_at: "2026-07-23T06:59:00Z",
    },
  ]) {
    assert.throws(() => selectFreshDriftMonitorRun([run], now), /drift monitor/u);
  }
});

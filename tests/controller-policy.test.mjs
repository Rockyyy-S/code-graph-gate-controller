import assert from "node:assert/strict";
import test from "node:test";
import { sha256CanonicalJson } from "../lib/canonical-json.mjs";
import {
  evaluateControllerCandidate,
  selectFreshDriftMonitorRun,
  selectLatestWorkflowRun,
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
  assert.equal(
    result.casKey,
    `1303415307:${"b".repeat(40)}:${fixture.artifact.evaluationContext.evaluationContextDigest}`,
  );
});

test("umbrella CAS 只绑定 provider/head/evaluation context 三元组", () => {
  const first = createFixture();
  const second = createFixture();
  second.artifact.gateImplementationDigest = "0".repeat(64);
  second.trustedRecord.gateImplementationDigest = second.artifact.gateImplementationDigest;
  second.trustedRecord.sequence += 1;

  assert.equal(
    evaluateControllerCandidate(first).casKey,
    evaluateControllerCandidate(second).casKey,
  );
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

test("Controller 拒绝未知、not-applicable 或格式错误的额外 evidence", () => {
  const unknown = createFixture();
  unknown.artifact.evidence.push({
    gateEvidenceDigest: "not-a-digest",
    gateId: "unknown",
  });
  assert.equal(evaluateControllerCandidate(unknown).status, "invalid");

  const malformed = createFixture();
  malformed.artifact.evidence[0].gateEvidenceDigest = "not-a-digest";
  assert.equal(evaluateControllerCandidate(malformed).status, "invalid");

  const notApplicable = createFixture();
  notApplicable.registry.gates[0].gateDefinition.triggerPaths = ["docs/**"];
  notApplicable.registry.gates[0].gateDefinitionDigest = sha256CanonicalJson(
    notApplicable.registry.gates[0].gateDefinition,
  );
  notApplicable.trustedRecord.gateRegistryDigest = sha256CanonicalJson(
    notApplicable.registry,
  );
  notApplicable.artifact.gateRegistryDigest = notApplicable.trustedRecord.gateRegistryDigest;
  notApplicable.artifact.evaluationContext.gateRegistryDigest =
    notApplicable.trustedRecord.gateRegistryDigest;
  const { evaluationContextDigest: _oldDigest, ...contextInput } =
    notApplicable.artifact.evaluationContext;
  notApplicable.artifact.evaluationContext.evaluationContextDigest =
    sha256CanonicalJson(contextInput);
  assert.equal(evaluateControllerCandidate(notApplicable).status, "invalid");
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
  assert.equal(evaluateControllerCandidate(producerMismatch).status, "invalid");

  const missing = createFixture();
  missing.artifact.evidence = [];
  assert.deepEqual(evaluateControllerCandidate(missing).missingEvidenceGateIds, ["unit"]);
});

const monitorSelection = {
  defaultBranch: "main",
  now: Date.parse("2026-07-23T07:00:00Z"),
  repository: "Rockyyy-S/code-graph-gate-controller",
  trustedHeadSha: "f".repeat(40),
  workflowPath: ".github/workflows/drift-monitor.yml",
};

function monitorRun(overrides = {}) {
  return {
    conclusion: "success",
    event: "schedule",
    head_branch: "main",
    head_sha: "f".repeat(40),
    path: ".github/workflows/drift-monitor.yml",
    repository: { full_name: "Rockyyy-S/code-graph-gate-controller" },
    status: "completed",
    updated_at: "2026-07-23T06:56:00Z",
    ...overrides,
  };
}

test("Controller 接受默认分支可信提交上的最近成功 monitor run", () => {
  const now = Date.parse("2026-07-23T07:00:00Z");
  const runs = [
    monitorRun({ updated_at: "2026-07-23T06:40:00Z" }),
    monitorRun(),
  ];
  assert.equal(selectFreshDriftMonitorRun(runs, { ...monitorSelection, now }), runs[1]);
  assert.equal(
    selectFreshDriftMonitorRun([monitorRun({ event: "push" })], {
      ...monitorSelection,
      now,
    }).event,
    "push",
  );
});

test("Controller 拒绝明显来自未来的 monitor 完成时间", () => {
  assert.throws(
    () =>
      selectFreshDriftMonitorRun(
        [monitorRun({ updated_at: "2026-07-24T07:00:00Z" })],
        monitorSelection,
      ),
    /未来|过期|fail closed/u,
  );
});

test("Controller 拒绝失败、过期、错误 ref/path/head 或手动 monitor run", () => {
  for (const run of [
    monitorRun({ conclusion: "failure" }),
    monitorRun({ updated_at: "2026-07-23T06:40:00Z" }),
    monitorRun({ event: "workflow_dispatch" }),
    monitorRun({ head_branch: "review-branch" }),
    monitorRun({ head_sha: "0".repeat(40) }),
    monitorRun({ path: ".github/workflows/untrusted.yml" }),
  ]) {
    assert.throws(
      () => selectFreshDriftMonitorRun([run], monitorSelection),
      /drift monitor/u,
    );
  }
});

test("workflow run 先按新 run ID、再按同 run attempt 选择", () => {
  const headOid = "b".repeat(40);
  const newerRun = {
    head_sha: headOid,
    id: 20,
    pull_requests: [{ number: 5 }],
    run_attempt: 1,
  };
  const oldRerun = {
    head_sha: headOid,
    id: 10,
    pull_requests: [{ number: 5 }],
    run_attempt: 9,
  };

  assert.equal(selectLatestWorkflowRun([oldRerun, newerRun], headOid, 5), newerRun);
});

test("workflow run 必须绑定当前 PR number，不能复用相同 head 的另一 PR run", () => {
  const headOid = "b".repeat(40);
  const wrongPull = {
    head_sha: headOid,
    id: 30,
    pull_requests: [{ number: 6 }],
    run_attempt: 1,
  };
  const expectedPull = {
    head_sha: headOid,
    id: 20,
    pull_requests: [{ number: 5 }],
    run_attempt: 1,
  };

  assert.equal(selectLatestWorkflowRun([wrongPull, expectedPull], headOid, 5), expectedPull);
});

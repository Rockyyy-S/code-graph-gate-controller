import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { sha256CanonicalJson } from "../lib/canonical-json.mjs";
import {
  parseEvidenceProducerId,
  UNBOUND_GATE_IMPLEMENTATION_DIGEST_V1,
  validateRegistry,
  validateTrustedRegistryApproval,
  validateTrustedRegistryRecord,
} from "../lib/registry.mjs";

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

  const unsupportedTrigger = createRegistry({ triggerPaths: ["src/[ab].ts"] });
  assert.throws(() => validateRegistry(unsupportedTrigger), /triggerPaths/u);

  const duplicateCheckId = createRegistry();
  const secondDefinition = {
    ...duplicateCheckId.gates[0].gateDefinition,
    evidenceProducerId: duplicateCheckId.gates[0].gateDefinition.evidenceProducerId.replace(
      /#type$/u,
      "#unit",
    ),
    gateId: "unit",
  };
  duplicateCheckId.gates.push({
    gateDefinition: secondDefinition,
    gateDefinitionDigest: sha256CanonicalJson(secondDefinition),
  });
  assert.throws(() => validateRegistry(duplicateCheckId), /checkId/u);
});

test("sequence=3 可信记录绑定 gate 实现摘要", () => {
  assert.doesNotThrow(() =>
    validateTrustedRegistryRecord({
      approvalEvidenceDigest: "a".repeat(64),
      effectiveAt: "2026-07-23T00:00:00Z",
      gateImplementationDigest: "b".repeat(64),
      gateRegistryDigest: "c".repeat(64),
      providerRepositoryId: "1303415307",
      schemaVersion: 1,
      sequence: 3,
      sourceCommit: "d".repeat(40),
    }),
  );
  assert.throws(
    () =>
      validateTrustedRegistryRecord({
        approvalEvidenceDigest: "a".repeat(64),
        effectiveAt: "2026-07-23T00:00:00Z",
        gateRegistryDigest: "c".repeat(64),
        providerRepositoryId: "1303415307",
        schemaVersion: 1,
        sequence: 3,
        sourceCommit: "d".repeat(40),
      }),
    /TrustedGateRegistryRecordV1/u,
  );
});

test("可信 registry sequence=12 绑定批准证据、候选提交、实现摘要和新 producer", async () => {
  const approval = JSON.parse(
    await readFile(new URL("../trusted/registry-approval.json", import.meta.url), "utf8"),
  );
  const record = JSON.parse(
    await readFile(new URL("../trusted/registry.json", import.meta.url), "utf8"),
  );
  const previousApproval = JSON.parse(
    await readFile(
      new URL("../trusted/previous-registry-approval.json", import.meta.url),
      "utf8",
    ),
  );
  const previousRecord = JSON.parse(
    await readFile(new URL("../trusted/previous-registry.json", import.meta.url), "utf8"),
  );

  validateTrustedRegistryRecord(record);
  assert.equal(record.sequence, 12);
  assert.equal(record.sourceCommit, "c07840f3f343e79a4c8ae82d2662dcda341fd88f");
  assert.equal(
    record.gateImplementationDigest,
    "3411b9c742fea63cc11211d10cef615b97c570936b8f886e923ddf34849e8fed",
  );
  assert.equal(
    record.gateRegistryDigest,
    "2034633e962fc22f7d7174cb63a6babb15a9c87d8eac7db23352def56fd3e2f0",
  );
  assert.equal(record.approvalEvidenceDigest, sha256CanonicalJson(approval));
  assert.equal(approval.sequence, record.sequence);
  assert.equal(approval.producerWorkflowSha, "3be138e4808de92410d2235d772ce7d423ff143d");
  assert.doesNotThrow(() =>
    validateTrustedRegistryApproval({
      approval,
      expectedProducerWorkflowSha: approval.producerWorkflowSha,
      previousApproval,
      previousRecord,
      record,
    }),
  );
});

test("可信批准拒绝 digest、sequence、source commit 或 producer 漂移", async () => {
  const approval = JSON.parse(
    await readFile(new URL("../trusted/registry-approval.json", import.meta.url), "utf8"),
  );
  const record = JSON.parse(
    await readFile(new URL("../trusted/registry.json", import.meta.url), "utf8"),
  );
  const previousApproval = JSON.parse(
    await readFile(
      new URL("../trusted/previous-registry-approval.json", import.meta.url),
      "utf8",
    ),
  );
  const previousRecord = JSON.parse(
    await readFile(new URL("../trusted/previous-registry.json", import.meta.url), "utf8"),
  );
  const mutations = [
    (value) => (value.sequence = 1),
    (value) => (value.sourceCommit = "f".repeat(40)),
    (value) => (value.gateRegistryDigest = "f".repeat(64)),
    (value) => (value.previousGateRegistryDigest = "f".repeat(64)),
    (value) => (value.previousProducerWorkflowSha = "f".repeat(40)),
    (value) => (value.producerWorkflowSha = "f".repeat(40)),
  ];
  for (const mutate of mutations) {
    const drifted = structuredClone(approval);
    mutate(drifted);
    assert.throws(
      () =>
        validateTrustedRegistryApproval({
          approval: drifted,
          expectedProducerWorkflowSha: approval.producerWorkflowSha,
          previousApproval,
          previousRecord,
          record,
        }),
      /TrustedGateRegistryApprovalV1/u,
    );
  }

  assert.throws(
    () =>
      validateTrustedRegistryApproval({
        approval,
        expectedProducerWorkflowSha: approval.producerWorkflowSha,
        previousApproval,
        previousRecord: { ...previousRecord, sequence: previousRecord.sequence + 2 },
        record,
      }),
    /TrustedGateRegistry/u,
  );
});

test("sequence=3 迁移把未绑定实现状态固定为唯一 sentinel", () => {
  const previousApproval = {
    approvalKind: "gate-registry-producer-migration",
    approvedAt: "2026-07-23T01:00:00Z",
    approvedBy: "owner",
    gateRegistryDigest: "a".repeat(64),
    previousGateRegistryDigest: "9".repeat(64),
    previousProducerWorkflowSha: "1".repeat(40),
    producerWorkflowSha: "2".repeat(40),
    providerRepositoryId: "1303415307",
    schemaVersion: 1,
    sequence: 2,
    sourceCommit: "3".repeat(40),
  };
  const previousRecord = {
    approvalEvidenceDigest: sha256CanonicalJson(previousApproval),
    effectiveAt: "2026-07-23T01:00:00Z",
    gateRegistryDigest: previousApproval.gateRegistryDigest,
    providerRepositoryId: "1303415307",
    schemaVersion: 1,
    sequence: 2,
    sourceCommit: previousApproval.sourceCommit,
  };
  const approval = {
    approvalKind: "gate-trust-root-migration",
    approvedAt: "2026-07-23T02:00:00Z",
    approvedBy: "owner",
    gateImplementationDigest: "b".repeat(64),
    gateRegistryDigest: "c".repeat(64),
    previousGateImplementationDigest: UNBOUND_GATE_IMPLEMENTATION_DIGEST_V1,
    previousGateRegistryDigest: previousRecord.gateRegistryDigest,
    previousProducerWorkflowSha: previousApproval.producerWorkflowSha,
    producerWorkflowSha: "4".repeat(40),
    providerRepositoryId: "1303415307",
    schemaVersion: 1,
    sequence: 3,
    sourceCommit: "5".repeat(40),
  };
  const record = {
    approvalEvidenceDigest: sha256CanonicalJson(approval),
    effectiveAt: "2026-07-23T02:00:00Z",
    gateImplementationDigest: approval.gateImplementationDigest,
    gateRegistryDigest: approval.gateRegistryDigest,
    providerRepositoryId: approval.providerRepositoryId,
    schemaVersion: 1,
    sequence: 3,
    sourceCommit: approval.sourceCommit,
  };

  assert.doesNotThrow(() =>
    validateTrustedRegistryApproval({
      approval,
      expectedProducerWorkflowSha: approval.producerWorkflowSha,
      previousApproval,
      previousRecord,
      record,
    }),
  );

  assert.throws(
    () =>
      validateTrustedRegistryApproval({
        approval: {
          ...approval,
          previousGateImplementationDigest: "0".repeat(64),
        },
        expectedProducerWorkflowSha: approval.producerWorkflowSha,
        previousApproval,
        previousRecord,
        record,
      }),
    /TrustedGateRegistryApprovalV1/u,
  );
});

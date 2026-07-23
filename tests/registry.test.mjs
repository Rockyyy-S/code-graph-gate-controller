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

test("可信 registry sequence=4 绑定批准证据、候选提交、实现摘要和新 producer", async () => {
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
  assert.equal(record.sequence, 4);
  assert.equal(record.sourceCommit, "ffafe93655bb3f3edcd6927c4cedfc41a77edf44");
  assert.equal(
    record.gateImplementationDigest,
    "3294b01cbe2d0190bc94b275f8bcb4ba3c3bb69ec26e3143131d00c4625ec4b2",
  );
  assert.equal(
    record.gateRegistryDigest,
    "5ace12ca56260706bfbc6efa1b575553a3606ca0229ff4d94cd41ae2094cf5ee",
  );
  assert.equal(record.approvalEvidenceDigest, sha256CanonicalJson(approval));
  assert.equal(approval.sequence, record.sequence);
  assert.equal(approval.producerWorkflowSha, "cf72d883c82c1042bdce3cdbcfb95251cc6257bd");
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
        previousRecord: { ...previousRecord, sequence: 9 },
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

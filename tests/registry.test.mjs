import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { sha256CanonicalJson } from "../lib/canonical-json.mjs";
import {
  loadApprovedProposals,
  parseEvidenceProducerId,
  selectTrustedRecordForCandidate,
  UNBOUND_GATE_IMPLEMENTATION_DIGEST_V1,
  validateProposedRegistryApproval,
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

/** 创建与当前可信根闭合的 proposed record/approval 测试对。 */
function createProposedPair({
  currentRecord,
  effectiveAt,
  expiresAt,
  headOid,
  pullNumber,
}) {
  const approval = {
    approvalKind: "proposed-gate-registry",
    approvedAt: effectiveAt,
    approvedBy: "owner",
    baseGateRegistryDigest: currentRecord.gateRegistryDigest,
    effectiveAt,
    expiresAt,
    gateImplementationDigest: "e".repeat(64),
    gateRegistryDigest: "f".repeat(64),
    headOid,
    producerWorkflowSha: workflowSha,
    providerRepositoryId: currentRecord.providerRepositoryId,
    pullNumber,
    schemaVersion: 1,
    sequence: currentRecord.sequence + 1,
    sourceCommit: headOid,
  };
  return {
    approval,
    record: {
      approvalEvidenceDigest: sha256CanonicalJson(approval),
      baseGateRegistryDigest: approval.baseGateRegistryDigest,
      effectiveAt,
      expiresAt,
      gateImplementationDigest: approval.gateImplementationDigest,
      gateRegistryDigest: approval.gateRegistryDigest,
      headOid,
      providerRepositoryId: approval.providerRepositoryId,
      pullNumber,
      schemaVersion: 1,
      sequence: approval.sequence,
      sourceCommit: headOid,
    },
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

test("registry 独立拒绝 no-op executable 与 Node 内联命令", () => {
  for (const command of [
    ["true"],
    ["/bin/echo", "ok"],
    ["node", "--eval=process.exit(0)"],
    ["node", "-eprocess.exit(0)"],
  ]) {
    assert.throws(() => validateRegistry(createRegistry({ command })), /no-op|恒成功/u);
  }
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

test("可信 registry sequence=17 正式提升最终 Story 1.3 根", async () => {
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
  assert.equal(record.sequence, 17);
  assert.equal(record.sourceCommit, "4e01c64e827ba5d650a2a7345d10d72b7611aa77");
  assert.equal(
    record.gateImplementationDigest,
    "3c32ce2afc5f32bebcb4ca4e44799dbc644c4c8e08934ef8b4cf204c70758ef2",
  );
  assert.equal(
    record.gateRegistryDigest,
    "9a4cb4adcce9c1767ce156cb0b5dc464eae2ca9cbca124caa5b7d0e770a74bd0",
  );
  assert.equal(record.approvalEvidenceDigest, sha256CanonicalJson(approval));
  assert.equal(approval.sequence, record.sequence);
  assert.equal(approval.producerWorkflowSha, "c01e7c0550b9d9150df26c20cebb10aaefdf648d");
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

test("Story 1.4 proposal 与 sequence 17、PR #8 精确 head 和固定 producer 闭合", async () => {
  const currentRecord = JSON.parse(
    await readFile(new URL("../trusted/registry.json", import.meta.url), "utf8"),
  );
  const proposals = await loadApprovedProposals(
    fileURLToPath(new URL("../trusted/proposed", import.meta.url)),
    {
      currentRecord,
      expectedProducerWorkflowSha: "0981130a71a3960aa374a82829d42aa9d9f15012",
      now: Date.parse("2026-07-25T19:51:27+08:00"),
    },
  );

  assert.equal(proposals.length, 1);
  assert.equal(proposals[0].record.sequence, 18);
  assert.equal(proposals[0].record.pullNumber, 8);
  assert.equal(
    proposals[0].record.headOid,
    "2515a0a68178051fe87cf305851fa386cad0db77",
  );
  assert.equal(
    proposals[0].record.gateRegistryDigest,
    "b91f8793a5edb4a1f8428c2aca88ba6ecd7b89e23a4a5af1ab72217979903a4f",
  );
  assert.equal(
    proposals[0].record.gateImplementationDigest,
    "7c1c1440f5ca63c32656870b70ab75a20a8f4d606890fe428eaaae1a8ed64fee",
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

test("proposed registry 只对批准的精确 PR head 和当前可信根生效", () => {
  const currentRecord = {
    approvalEvidenceDigest: "a".repeat(64),
    effectiveAt: "2026-07-23T00:00:00Z",
    gateImplementationDigest: "b".repeat(64),
    gateRegistryDigest: "c".repeat(64),
    providerRepositoryId: "1303415307",
    schemaVersion: 1,
    sequence: 16,
    sourceCommit: "d".repeat(40),
  };
  const approval = {
    approvalKind: "proposed-gate-registry",
    approvedAt: "2026-07-24T00:00:00Z",
    approvedBy: "owner",
    baseGateRegistryDigest: currentRecord.gateRegistryDigest,
    effectiveAt: "2026-07-24T00:00:00Z",
    expiresAt: "2026-07-25T00:00:00Z",
    gateImplementationDigest: "e".repeat(64),
    gateRegistryDigest: "f".repeat(64),
    headOid: "1".repeat(40),
    producerWorkflowSha: workflowSha,
    providerRepositoryId: currentRecord.providerRepositoryId,
    pullNumber: 5,
    schemaVersion: 1,
    sequence: 17,
    sourceCommit: "1".repeat(40),
  };
  const record = {
    approvalEvidenceDigest: sha256CanonicalJson(approval),
    baseGateRegistryDigest: approval.baseGateRegistryDigest,
    effectiveAt: approval.approvedAt,
    expiresAt: approval.expiresAt,
    gateImplementationDigest: approval.gateImplementationDigest,
    gateRegistryDigest: approval.gateRegistryDigest,
    headOid: approval.headOid,
    providerRepositoryId: approval.providerRepositoryId,
    pullNumber: approval.pullNumber,
    schemaVersion: 1,
    sequence: approval.sequence,
    sourceCommit: approval.sourceCommit,
  };

  assert.doesNotThrow(() =>
    validateProposedRegistryApproval({
      approval,
      currentRecord,
      expectedProducerWorkflowSha: workflowSha,
      now: Date.parse("2026-07-24T12:00:00Z"),
      record,
    }),
  );
  assert.equal(
    selectTrustedRecordForCandidate({
      currentRecord,
      headOid: record.headOid,
      now: Date.parse("2026-07-24T12:00:00Z"),
      proposals: [{ approval, record }],
      providerRepositoryId: record.providerRepositoryId,
      pullNumber: record.pullNumber,
      registryDigest: record.gateRegistryDigest,
      workflowSha,
    }).sourceCommit,
    record.headOid,
  );
  assert.throws(
    () =>
      selectTrustedRecordForCandidate({
        currentRecord,
        headOid: "2".repeat(40),
        now: Date.parse("2026-07-24T12:00:00Z"),
        proposals: [{ approval, record }],
        providerRepositoryId: record.providerRepositoryId,
        pullNumber: record.pullNumber,
        registryDigest: record.gateRegistryDigest,
        workflowSha,
      }),
    /未获批准|head/u,
  );

  const futureApproval = {
    ...approval,
    approvedAt: "2026-07-24T00:00:00Z",
    effectiveAt: "2026-07-24T13:00:00Z",
  };
  const futureRecord = {
    ...record,
    approvalEvidenceDigest: "0".repeat(64),
    effectiveAt: "2026-07-24T13:00:00Z",
  };
  futureRecord.approvalEvidenceDigest = sha256CanonicalJson(futureApproval);
  assert.throws(
    () =>
      validateProposedRegistryApproval({
        approval: futureApproval,
        currentRecord,
        expectedProducerWorkflowSha: workflowSha,
        now: Date.parse("2026-07-24T12:00:00Z"),
        record: futureRecord,
      }),
    /ProposedGateRegistryApprovalV1/u,
  );

  assert.throws(
    () =>
      selectTrustedRecordForCandidate({
        currentRecord,
        headOid: record.headOid,
        now: Date.parse("2026-07-25T00:00:01Z"),
        proposals: [{ approval, record }],
        providerRepositoryId: record.providerRepositoryId,
        pullNumber: record.pullNumber,
        registryDigest: record.gateRegistryDigest,
        workflowSha,
      }),
    /ProposedGateRegistryApprovalV1/u,
  );
});

test("相同 registry digest 的精确 proposal 可批准新的 gate implementation", () => {
  const currentRecord = {
    approvalEvidenceDigest: "a".repeat(64),
    effectiveAt: "2026-07-23T00:00:00Z",
    gateImplementationDigest: "b".repeat(64),
    gateRegistryDigest: "c".repeat(64),
    providerRepositoryId: "1303415307",
    schemaVersion: 1,
    sequence: 16,
    sourceCommit: "d".repeat(40),
  };
  const approval = {
    approvalKind: "proposed-gate-registry",
    approvedAt: "2026-07-24T00:00:00Z",
    approvedBy: "owner",
    baseGateRegistryDigest: currentRecord.gateRegistryDigest,
    effectiveAt: "2026-07-24T00:00:00Z",
    expiresAt: "2026-07-25T00:00:00Z",
    gateImplementationDigest: "e".repeat(64),
    gateRegistryDigest: currentRecord.gateRegistryDigest,
    headOid: "1".repeat(40),
    producerWorkflowSha: workflowSha,
    providerRepositoryId: currentRecord.providerRepositoryId,
    pullNumber: 5,
    schemaVersion: 1,
    sequence: 17,
    sourceCommit: "1".repeat(40),
  };
  const record = {
    approvalEvidenceDigest: sha256CanonicalJson(approval),
    baseGateRegistryDigest: approval.baseGateRegistryDigest,
    effectiveAt: approval.effectiveAt,
    expiresAt: approval.expiresAt,
    gateImplementationDigest: approval.gateImplementationDigest,
    gateRegistryDigest: approval.gateRegistryDigest,
    headOid: approval.headOid,
    providerRepositoryId: approval.providerRepositoryId,
    pullNumber: approval.pullNumber,
    schemaVersion: 1,
    sequence: approval.sequence,
    sourceCommit: approval.sourceCommit,
  };

  const selected = selectTrustedRecordForCandidate({
    currentRecord,
    headOid: record.headOid,
    now: Date.parse("2026-07-24T12:00:00Z"),
    proposals: [{ approval, record }],
    providerRepositoryId: record.providerRepositoryId,
    pullNumber: record.pullNumber,
    registryDigest: record.gateRegistryDigest,
    workflowSha,
  });

  assert.equal(selected.gateImplementationDigest, approval.gateImplementationDigest);
  assert.equal(selected.sequence, 17);
});

test("proposal loader 校验全部记录完整性但仅返回当前有效时间窗", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "controller-proposals-"));
  const currentRecord = {
    approvalEvidenceDigest: "a".repeat(64),
    effectiveAt: "2026-07-23T00:00:00Z",
    gateImplementationDigest: "b".repeat(64),
    gateRegistryDigest: "c".repeat(64),
    providerRepositoryId: "1303415307",
    schemaVersion: 1,
    sequence: 16,
    sourceCommit: "d".repeat(40),
  };
  const fixtures = [
    ["active", createProposedPair({
      currentRecord,
      effectiveAt: "2026-07-24T00:00:00Z",
      expiresAt: "2026-07-25T00:00:00Z",
      headOid: "1".repeat(40),
      pullNumber: 1,
    })],
    ["expired", createProposedPair({
      currentRecord,
      effectiveAt: "2026-07-23T00:00:00Z",
      expiresAt: "2026-07-24T01:00:00Z",
      headOid: "2".repeat(40),
      pullNumber: 2,
    })],
    ["future", createProposedPair({
      currentRecord,
      effectiveAt: "2026-07-24T13:00:00Z",
      expiresAt: "2026-07-25T00:00:00Z",
      headOid: "3".repeat(40),
      pullNumber: 3,
    })],
  ];
  try {
    for (const [name, fixture] of fixtures) {
      await Promise.all([
        writeFile(path.join(directory, `${name}.json`), JSON.stringify(fixture.record)),
        writeFile(
          path.join(directory, `${name}.approval.json`),
          JSON.stringify(fixture.approval),
        ),
      ]);
    }

    const proposals = await loadApprovedProposals(directory, {
      currentRecord,
      expectedProducerWorkflowSha: workflowSha,
      now: Date.parse("2026-07-24T12:00:00Z"),
    });
    assert.deepEqual(proposals.map(({ record }) => record.pullNumber), [1]);

    const invalidExpired = fixtures[1][1];
    await writeFile(
      path.join(directory, "invalid-expired.json"),
      JSON.stringify({ ...invalidExpired.record, approvalEvidenceDigest: "0".repeat(64) }),
    );
    await writeFile(
      path.join(directory, "invalid-expired.approval.json"),
      JSON.stringify(invalidExpired.approval),
    );
    await assert.rejects(
      loadApprovedProposals(directory, {
        currentRecord,
        expectedProducerWorkflowSha: workflowSha,
        now: Date.parse("2026-07-24T12:00:00Z"),
      }),
      /ProposedGateRegistryApprovalV1/u,
    );
  } finally {
    await rm(directory, { force: true, recursive: true });
  }
});

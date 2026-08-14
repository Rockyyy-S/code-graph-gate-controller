import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { sha256CanonicalJson } from "../lib/canonical-json.mjs";
import { loadHarnessTrustedRecordForCandidate } from "../lib/harness.mjs";
import {
  loadApprovedProposals,
  parseEvidenceProducerId,
  selectCandidateAuthorization,
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
  approvedAt,
  currentRecord,
  effectiveAt,
  expiresAt,
  gateImplementationDigest = "e".repeat(64),
  gateRegistryDigest = "f".repeat(64),
  headOid,
  producerWorkflowSha = workflowSha,
  pullNumber,
}) {
  const approvalTime = approvedAt ?? effectiveAt;
  const approval = {
    approvalKind: "proposed-gate-registry",
    approvedAt: approvalTime,
    approvedBy: "owner",
    baseGateRegistryDigest: currentRecord.gateRegistryDigest,
    effectiveAt,
    expiresAt,
    gateImplementationDigest,
    gateRegistryDigest,
    headOid,
    producerWorkflowSha,
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

/** 把 proposed record/approval 以独立文件写入测试目录。 */
async function writeProposedPair(directory, name, pair, { includeApproval = true } = {}) {
  const writes = [
    writeFile(path.join(directory, `${name}.json`), JSON.stringify(pair.record)),
  ];
  if (includeApproval) {
    writes.push(
      writeFile(
        path.join(directory, `${name}.approval.json`),
        JSON.stringify(pair.approval),
      ),
    );
  }
  await Promise.all(writes);
}

test("candidate authorization 原子返回 canonical 或 exact proposal 的 record/producer", async () => {
  const canonicalProducerWorkflowSha = "a".repeat(40);
  const proposedProducerWorkflowSha = "b".repeat(40);
  const currentRecord = {
    approvalEvidenceDigest: "1".repeat(64),
    effectiveAt: "2026-08-09T00:00:00Z",
    gateImplementationDigest: "2".repeat(64),
    gateRegistryDigest: "3".repeat(64),
    providerRepositoryId: "1303415307",
    schemaVersion: 1,
    sequence: 24,
    sourceCommit: "4".repeat(40),
  };
  const canonical = selectCandidateAuthorization({
    canonicalProducerWorkflowSha,
    currentRecord,
    headOid: "5".repeat(40),
    proposals: [],
    providerRepositoryId: currentRecord.providerRepositoryId,
    pullNumber: 9,
    registryDigest: currentRecord.gateRegistryDigest,
  });
  assert.deepEqual(canonical, {
    producerWorkflowSha: canonicalProducerWorkflowSha,
    record: currentRecord,
  });

  const proposal = createProposedPair({
    currentRecord,
    effectiveAt: "2026-08-09T01:00:00Z",
    expiresAt: "2026-08-10T01:00:00Z",
    headOid: "6".repeat(40),
    producerWorkflowSha: proposedProducerWorkflowSha,
    pullNumber: 9,
  });
  const proposed = selectCandidateAuthorization({
    canonicalProducerWorkflowSha,
    currentRecord,
    headOid: proposal.record.headOid,
    now: Date.parse("2026-08-09T12:00:00Z"),
    proposals: [proposal],
    providerRepositoryId: currentRecord.providerRepositoryId,
    pullNumber: 9,
    registryDigest: proposal.record.gateRegistryDigest,
  });
  assert.equal(proposed.producerWorkflowSha, proposedProducerWorkflowSha);
  assert.equal(proposed.record.sourceCommit, proposal.record.headOid);
  assert.equal(proposed.record.sequence, 25);
});

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

test("可信 registry sequence=24 消费精确 bec9ed7 proposal 并绑定新 producer 根", async () => {
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
  assert.equal(record.sequence, 24);
  assert.equal(record.sourceCommit, "bec9ed7c7184845e1f760730f826785f6646fa18");
  assert.equal(
    record.gateImplementationDigest,
    "95ab1080a12dcc8965abe3c6b1b9ff672ab979f1e069c3df471041d43f609427",
  );
  assert.equal(
    record.gateRegistryDigest,
    "f84f6fd96280eddd7c6b9689c975b5fd19a82260b77206c318b63bb2815e9831",
  );
  assert.equal(record.approvalEvidenceDigest, sha256CanonicalJson(approval));
  assert.equal(approval.sequence, record.sequence);
  assert.equal(previousRecord.sequence, 23);
  assert.equal(previousRecord.approvalEvidenceDigest, sha256CanonicalJson(previousApproval));
  assert.equal(previousApproval.producerWorkflowSha, "67b35a8c1516759c680c5835c1956cdd623f7476");
  assert.equal(approval.previousProducerWorkflowSha, previousApproval.producerWorkflowSha);
  assert.equal(approval.producerWorkflowSha, "b5bb1069f93fb92640d23df2b803401d4537f59d");
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

test("sequence 24 信任根按 exact head 加载历史与当前 sequence 25 proposal", async () => {
  const currentRecord = JSON.parse(
    await readFile(new URL("../trusted/registry.json", import.meta.url), "utf8"),
  );
  const canonicalProducerWorkflowSha = "b5bb1069f93fb92640d23df2b803401d4537f59d";
  const now = Date.parse("2026-08-14T12:14:00+08:00");
  const proposals = await loadApprovedProposals(
    fileURLToPath(new URL("../trusted/proposed", import.meta.url)),
    {
      currentRecord,
      now,
    },
  );

  assert.equal(currentRecord.sequence, 24);
  assert.equal(proposals.length, 8);
  const proposalsByHead = new Map(
    proposals.map((proposal) => [proposal.record.headOid, proposal]),
  );
  const oldHead = "833c11094b9189f2aaefbe85bbc811c504dda0e1";
  const newHead = "9b0210f572bd63c6614d13d60b6b28a1bb4aa246";
  const currentHead = "2a11fcd1cce2a8d9ec41483b43077d55d24f3474";
  const pr10Head = "06866f67dd7e4ac4bd91edc27e176811282f7f18";
  const repinnedPr10Head = "cfe7758aad4dca03ebe31739d8cc906331356827";
  const protectedProofPr10Head = "6f8d2286c9c2f13a3506bd4f4e74436153a13345";
  const nodePathPr10Head = "5b04f2963e6527bcd9deb9a54135e6d962aa0d5c";
  const helperLifecyclePr10Head = "34300ed1bdd90676bc3fc2760820c6c544255fd6";
  const oldProposal = proposalsByHead.get(oldHead);
  const newProposal = proposalsByHead.get(newHead);
  const currentProposal = proposalsByHead.get(currentHead);
  const pr10Proposal = proposalsByHead.get(pr10Head);
  const repinnedPr10Proposal = proposalsByHead.get(repinnedPr10Head);
  const protectedProofPr10Proposal = proposalsByHead.get(protectedProofPr10Head);
  const nodePathPr10Proposal = proposalsByHead.get(nodePathPr10Head);
  const helperLifecyclePr10Proposal = proposalsByHead.get(helperLifecyclePr10Head);
  assert.ok(oldProposal);
  assert.ok(newProposal);
  assert.ok(currentProposal);
  assert.ok(pr10Proposal);
  assert.ok(repinnedPr10Proposal);
  assert.ok(protectedProofPr10Proposal);
  assert.ok(nodePathPr10Proposal);
  assert.ok(helperLifecyclePr10Proposal);
  assert.deepEqual(oldProposal.record, {
    approvalEvidenceDigest: "7c695e1e86306963fa30e022e61953e5fb746e210d47faf3ab0445704848fd08",
    baseGateRegistryDigest: currentRecord.gateRegistryDigest,
    effectiveAt: "2026-08-09T12:10:33+08:00",
    expiresAt: "2026-08-16T12:10:33+08:00",
    gateImplementationDigest: "8737436b9b8c9e1e917d04f6bfe41c4a6a186e82533ad9e918b48b88ade6f6bc",
    gateRegistryDigest: "5318861ba63c2e6f83e998ca1a3ff827d800ab512a3af44f7e38443b9a32eb5c",
    headOid: "833c11094b9189f2aaefbe85bbc811c504dda0e1",
    providerRepositoryId: "1303415307",
    pullNumber: 9,
    schemaVersion: 1,
    sequence: 25,
    sourceCommit: oldHead,
  });
  assert.equal(
    oldProposal.record.approvalEvidenceDigest,
    sha256CanonicalJson(oldProposal.approval),
  );
  assert.equal(oldProposal.approval.approvedBy, "Rockyyy-S");
  assert.equal(
    oldProposal.approval.producerWorkflowSha,
    "23b8fc5bc221b99d78640ab55a711ae3d42054f4",
  );
  assert.deepEqual(newProposal.record, {
    approvalEvidenceDigest: "a1cd122d54183d5f55c00b8f58dd006f22b89493b0bba13e050240c61b786531",
    baseGateRegistryDigest: currentRecord.gateRegistryDigest,
    effectiveAt: "2026-08-09T15:54:54+08:00",
    expiresAt: "2026-08-16T15:54:54+08:00",
    gateImplementationDigest: "8737436b9b8c9e1e917d04f6bfe41c4a6a186e82533ad9e918b48b88ade6f6bc",
    gateRegistryDigest: "59fc03bf4b01ab0a55ef3f081805274ebd1da804370e4e7ed1fa4b4f261e8fdf",
    headOid: newHead,
    providerRepositoryId: "1303415307",
    pullNumber: 9,
    schemaVersion: 1,
    sequence: 25,
    sourceCommit: newHead,
  });
  assert.equal(
    newProposal.record.approvalEvidenceDigest,
    sha256CanonicalJson(newProposal.approval),
  );
  assert.equal(newProposal.approval.approvedBy, "Rockyyy-S");
  assert.equal(
    newProposal.approval.producerWorkflowSha,
    "d243785453f64dd0c077516ec78479b307dc361c",
  );
  assert.notEqual(
    newProposal.approval.producerWorkflowSha,
    canonicalProducerWorkflowSha,
  );

  assert.deepEqual(currentProposal.record, {
    approvalEvidenceDigest: "6c93dbd20898215cb2aa23b1040f76c94bfcb2b612eb7e0896e439b60bc39537",
    baseGateRegistryDigest: currentRecord.gateRegistryDigest,
    effectiveAt: "2026-08-10T17:06:37+08:00",
    expiresAt: "2026-08-17T17:06:37+08:00",
    gateImplementationDigest: "8737436b9b8c9e1e917d04f6bfe41c4a6a186e82533ad9e918b48b88ade6f6bc",
    gateRegistryDigest: "f0a95f6f3a88908aee584b873676291530f351b0326e4e205e09318f815feeb1",
    headOid: currentHead,
    providerRepositoryId: "1303415307",
    pullNumber: 9,
    schemaVersion: 1,
    sequence: 25,
    sourceCommit: currentHead,
  });
  assert.equal(
    currentProposal.record.approvalEvidenceDigest,
    sha256CanonicalJson(currentProposal.approval),
  );
  assert.equal(currentProposal.approval.approvedBy, "Rockyyy-S");
  assert.equal(
    currentProposal.approval.producerWorkflowSha,
    "2cc5b1206ba64c1e60702159154cf58ef903da70",
  );
  assert.notEqual(
    currentProposal.approval.producerWorkflowSha,
    canonicalProducerWorkflowSha,
  );

  assert.deepEqual(pr10Proposal.record, {
    approvalEvidenceDigest: "4892e9411e4b47007be61528141730ebc756861b7b5da4a65a189b02eade0799",
    baseGateRegistryDigest: currentRecord.gateRegistryDigest,
    effectiveAt: "2026-08-14T10:59:52+08:00",
    expiresAt: "2026-08-21T10:59:52+08:00",
    gateImplementationDigest: "59d84ab8a86b7cdc0b8261be8ce80b9c51832753ca95eb71e8255478f1d436fb",
    gateRegistryDigest: "fd655ed5937df15444743cf5a84326f8b4bef53e01bf5a4e22a95fa5877dfaca",
    headOid: pr10Head,
    providerRepositoryId: "1303415307",
    pullNumber: 10,
    schemaVersion: 1,
    sequence: 25,
    sourceCommit: pr10Head,
  });
  assert.equal(
    pr10Proposal.record.approvalEvidenceDigest,
    sha256CanonicalJson(pr10Proposal.approval),
  );
  assert.equal(pr10Proposal.approval.approvedBy, "Rockyyy-S");
  assert.equal(
    pr10Proposal.approval.producerWorkflowSha,
    "303f54e297eed25f6f35721eceb82935ccea3a0c",
  );

  assert.deepEqual(repinnedPr10Proposal.record, {
    approvalEvidenceDigest: "4b41427c3d3d77fc70f32bc776076c29ebb90328011e84722a0cc4ad3a45e329",
    baseGateRegistryDigest: currentRecord.gateRegistryDigest,
    effectiveAt: "2026-08-14T11:20:00+08:00",
    expiresAt: "2026-08-21T11:20:00+08:00",
    gateImplementationDigest: "59d84ab8a86b7cdc0b8261be8ce80b9c51832753ca95eb71e8255478f1d436fb",
    gateRegistryDigest: "28c9f7f07a5db942bf868105e77fdb1a72a04518d7969cdb68799640e727b6ef",
    headOid: repinnedPr10Head,
    providerRepositoryId: "1303415307",
    pullNumber: 10,
    schemaVersion: 1,
    sequence: 25,
    sourceCommit: repinnedPr10Head,
  });
  assert.equal(
    repinnedPr10Proposal.record.approvalEvidenceDigest,
    sha256CanonicalJson(repinnedPr10Proposal.approval),
  );
  assert.equal(repinnedPr10Proposal.approval.approvedBy, "Rockyyy-S");
  assert.equal(
    repinnedPr10Proposal.approval.producerWorkflowSha,
    "4217009b3e38a21f10780e66e9aeaa091c0d15c0",
  );

  assert.deepEqual(protectedProofPr10Proposal.record, {
    approvalEvidenceDigest: "3e1eb80e793af498ca694a0c4426f9d5a10b47c24a6af942f656a22c6c733d56",
    baseGateRegistryDigest: currentRecord.gateRegistryDigest,
    effectiveAt: "2026-08-14T11:34:00+08:00",
    expiresAt: "2026-08-21T11:34:00+08:00",
    gateImplementationDigest: "59d84ab8a86b7cdc0b8261be8ce80b9c51832753ca95eb71e8255478f1d436fb",
    gateRegistryDigest: "9a1a434f1c2e479268b9cb69e6b47af7010794daa9d5128d4b090690268a1d7c",
    headOid: protectedProofPr10Head,
    providerRepositoryId: "1303415307",
    pullNumber: 10,
    schemaVersion: 1,
    sequence: 25,
    sourceCommit: protectedProofPr10Head,
  });
  assert.equal(
    protectedProofPr10Proposal.record.approvalEvidenceDigest,
    sha256CanonicalJson(protectedProofPr10Proposal.approval),
  );
  assert.equal(protectedProofPr10Proposal.approval.approvedBy, "Rockyyy-S");
  assert.equal(
    protectedProofPr10Proposal.approval.producerWorkflowSha,
    "de09eb873e3d28718e644b48a2ee0bdd550b2995",
  );

  assert.deepEqual(nodePathPr10Proposal.record, {
    approvalEvidenceDigest: "a05fc0e066b4afb34955967cacab9d9ec1b5238d52ce513c5be6271e2aa6f435",
    baseGateRegistryDigest: currentRecord.gateRegistryDigest,
    effectiveAt: "2026-08-14T11:47:00+08:00",
    expiresAt: "2026-08-21T11:47:00+08:00",
    gateImplementationDigest: "59d84ab8a86b7cdc0b8261be8ce80b9c51832753ca95eb71e8255478f1d436fb",
    gateRegistryDigest: "9ad6333b4ce12c2bb5cd3516a51c9d16f0de700875f087ec933783fed5e9c0b6",
    headOid: nodePathPr10Head,
    providerRepositoryId: "1303415307",
    pullNumber: 10,
    schemaVersion: 1,
    sequence: 25,
    sourceCommit: nodePathPr10Head,
  });
  assert.equal(
    nodePathPr10Proposal.record.approvalEvidenceDigest,
    sha256CanonicalJson(nodePathPr10Proposal.approval),
  );
  assert.equal(nodePathPr10Proposal.approval.approvedBy, "Rockyyy-S");
  assert.equal(
    nodePathPr10Proposal.approval.producerWorkflowSha,
    "ebaeedc619e6099b3ee39c681c7bf3f58df1a618",
  );

  assert.deepEqual(helperLifecyclePr10Proposal.record, {
    approvalEvidenceDigest: "fa672108c185acbc929a6c97372341ca66422492ecc07eb33e5cbab1fa8f4476",
    baseGateRegistryDigest: currentRecord.gateRegistryDigest,
    effectiveAt: "2026-08-14T12:13:00+08:00",
    expiresAt: "2026-08-21T12:13:00+08:00",
    gateImplementationDigest: "59d84ab8a86b7cdc0b8261be8ce80b9c51832753ca95eb71e8255478f1d436fb",
    gateRegistryDigest: "9ad6333b4ce12c2bb5cd3516a51c9d16f0de700875f087ec933783fed5e9c0b6",
    headOid: helperLifecyclePr10Head,
    providerRepositoryId: "1303415307",
    pullNumber: 10,
    schemaVersion: 1,
    sequence: 25,
    sourceCommit: helperLifecyclePr10Head,
  });
  assert.equal(
    helperLifecyclePr10Proposal.record.approvalEvidenceDigest,
    sha256CanonicalJson(helperLifecyclePr10Proposal.approval),
  );
  assert.equal(helperLifecyclePr10Proposal.approval.approvedBy, "Rockyyy-S");
  assert.equal(
    helperLifecyclePr10Proposal.approval.producerWorkflowSha,
    "ebaeedc619e6099b3ee39c681c7bf3f58df1a618",
  );

  // 同一 sequence 的历史 proposal 必须共存，并由 repository/PR/exact head 唯一选择。
  for (const proposal of [
    oldProposal,
    newProposal,
    currentProposal,
    pr10Proposal,
    repinnedPr10Proposal,
    protectedProofPr10Proposal,
    nodePathPr10Proposal,
    helperLifecyclePr10Proposal,
  ]) {
    const selected = selectCandidateAuthorization({
      canonicalProducerWorkflowSha,
      currentRecord,
      headOid: proposal.record.headOid,
      now,
      proposals,
      providerRepositoryId: proposal.record.providerRepositoryId,
      pullNumber: proposal.record.pullNumber,
      registryDigest: proposal.record.gateRegistryDigest,
    });
    assert.equal(selected.producerWorkflowSha, proposal.approval.producerWorkflowSha);
    assert.equal(selected.record.sourceCommit, proposal.record.headOid);
  }
});

test("Harness 当前 exact head 不受其他合法 proposal 的 producer 污染", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "harness-multi-proposal-"));
  const currentRecord = {
    approvalEvidenceDigest: "1".repeat(64),
    effectiveAt: "2026-08-09T00:00:00Z",
    gateImplementationDigest: "2".repeat(64),
    gateRegistryDigest: "3".repeat(64),
    providerRepositoryId: "1303415307",
    schemaVersion: 1,
    sequence: 24,
    sourceCommit: "4".repeat(40),
  };
  const currentProducerWorkflowSha = "b".repeat(40);
  const fixtures = [
    ["old", createProposedPair({
      currentRecord,
      effectiveAt: "2026-08-09T01:00:00Z",
      expiresAt: "2026-08-10T01:00:00Z",
      gateRegistryDigest: "5".repeat(64),
      headOid: "6".repeat(40),
      producerWorkflowSha: "a".repeat(40),
      pullNumber: 9,
    })],
    ["current", createProposedPair({
      currentRecord,
      effectiveAt: "2026-08-09T02:00:00Z",
      expiresAt: "2026-08-10T02:00:00Z",
      gateRegistryDigest: "7".repeat(64),
      headOid: "8".repeat(40),
      producerWorkflowSha: currentProducerWorkflowSha,
      pullNumber: 9,
    })],
  ];
  try {
    for (const [name, fixture] of fixtures) {
      await writeProposedPair(directory, name, fixture);
    }

    const selected = await loadHarnessTrustedRecordForCandidate({
      currentRecord,
      headOid: fixtures[1][1].record.headOid,
      now: Date.parse("2026-08-09T12:00:00Z"),
      proposedRecordDirectory: directory,
      providerRepositoryId: currentRecord.providerRepositoryId,
      pullNumber: fixtures[1][1].record.pullNumber,
      registryDigest: fixtures[1][1].record.gateRegistryDigest,
      workflowSha: currentProducerWorkflowSha,
    });
    assert.equal(selected.sourceCommit, fixtures[1][1].record.headOid);
  } finally {
    await rm(directory, { force: true, recursive: true });
  }
});

test("Harness exact-head 选择对 duplicate、wrong producer、expiry、digest mix、missing approval 与 canonical drift fail closed", async () => {
  const currentRecord = {
    approvalEvidenceDigest: "1".repeat(64),
    effectiveAt: "2026-08-09T00:00:00Z",
    gateImplementationDigest: "2".repeat(64),
    gateRegistryDigest: "3".repeat(64),
    providerRepositoryId: "1303415307",
    schemaVersion: 1,
    sequence: 24,
    sourceCommit: "4".repeat(40),
  };
  const currentHead = "5".repeat(40);
  const currentProducerWorkflowSha = "6".repeat(40);
  const requestedRegistryDigest = "7".repeat(64);
  const now = Date.parse("2026-08-09T12:00:00Z");
  const createCurrentPair = (overrides = {}) => createProposedPair({
    currentRecord,
    effectiveAt: "2026-08-09T01:00:00Z",
    expiresAt: "2026-08-10T01:00:00Z",
    gateRegistryDigest: requestedRegistryDigest,
    headOid: currentHead,
    producerWorkflowSha: currentProducerWorkflowSha,
    pullNumber: 9,
    ...overrides,
  });
  const select = (directory, overrides = {}) => loadHarnessTrustedRecordForCandidate({
    currentRecord,
    headOid: currentHead,
    now,
    proposedRecordDirectory: directory,
    providerRepositoryId: currentRecord.providerRepositoryId,
    pullNumber: 9,
    registryDigest: requestedRegistryDigest,
    workflowSha: currentProducerWorkflowSha,
    ...overrides,
  });
  const scenarios = [
    {
      name: "duplicate",
      pattern: /多个|冲突/u,
      prepare: async (directory) => {
        await Promise.all([
          writeProposedPair(directory, "first", createCurrentPair()),
          writeProposedPair(directory, "second", createCurrentPair()),
        ]);
      },
    },
    {
      name: "wrong-producer",
      pattern: /ProposedGateRegistryApprovalV1/u,
      prepare: (directory) => writeProposedPair(
        directory,
        "wrong-producer",
        createCurrentPair({ producerWorkflowSha: "8".repeat(40) }),
      ),
    },
    {
      name: "expired",
      pattern: /ProposedGateRegistryApprovalV1/u,
      prepare: (directory) => writeProposedPair(
        directory,
        "expired",
        createCurrentPair({ expiresAt: "2026-08-09T11:00:00Z" }),
      ),
    },
    {
      name: "digest-mix",
      pattern: /digest/u,
      prepare: (directory) => writeProposedPair(directory, "digest-mix", createCurrentPair()),
      selectionOverrides: { registryDigest: "9".repeat(64) },
    },
    {
      name: "missing-approval",
      pattern: /ENOENT|no such file/u,
      prepare: (directory) => writeProposedPair(
        directory,
        "missing-approval",
        createCurrentPair(),
        { includeApproval: false },
      ),
    },
    {
      name: "canonical-drift",
      pattern: /ProposedGateRegistryApprovalV1/u,
      prepare: (directory) => {
        const pair = createCurrentPair();
        pair.approval.baseGateRegistryDigest = "a".repeat(64);
        pair.record.baseGateRegistryDigest = pair.approval.baseGateRegistryDigest;
        pair.record.approvalEvidenceDigest = sha256CanonicalJson(pair.approval);
        return writeProposedPair(directory, "canonical-drift", pair);
      },
    },
  ];

  for (const scenario of scenarios) {
    const directory = await mkdtemp(path.join(tmpdir(), `harness-${scenario.name}-`));
    try {
      await scenario.prepare(directory);
      await assert.rejects(
        select(directory, scenario.selectionOverrides),
        scenario.pattern,
      );
    } finally {
      await rm(directory, { force: true, recursive: true });
    }
  }
});

test("exact-head proposal 在 canonical fallback 前拒绝 duplicate、digest mix 与 producer mismatch", () => {
  const canonicalProducerWorkflowSha = "a".repeat(40);
  const currentRecord = {
    approvalEvidenceDigest: "1".repeat(64),
    effectiveAt: "2026-08-09T00:00:00Z",
    gateImplementationDigest: "2".repeat(64),
    gateRegistryDigest: "3".repeat(64),
    providerRepositoryId: "1303415307",
    schemaVersion: 1,
    sequence: 24,
    sourceCommit: "4".repeat(40),
  };
  const proposal = createProposedPair({
    currentRecord,
    effectiveAt: "2026-08-09T01:00:00Z",
    expiresAt: "2026-08-10T01:00:00Z",
    gateRegistryDigest: currentRecord.gateRegistryDigest,
    headOid: "5".repeat(40),
    producerWorkflowSha: "b".repeat(40),
    pullNumber: 9,
  });
  const selection = {
    canonicalProducerWorkflowSha,
    currentRecord,
    headOid: proposal.record.headOid,
    now: Date.parse("2026-08-09T12:00:00Z"),
    proposals: [proposal],
    providerRepositoryId: currentRecord.providerRepositoryId,
    pullNumber: 9,
    registryDigest: currentRecord.gateRegistryDigest,
  };

  const conflict = createProposedPair({
    currentRecord,
    effectiveAt: proposal.record.effectiveAt,
    expiresAt: proposal.record.expiresAt,
    gateRegistryDigest: currentRecord.gateRegistryDigest,
    headOid: proposal.record.headOid,
    producerWorkflowSha: "c".repeat(40),
    pullNumber: 9,
  });
  assert.throws(
    () => selectCandidateAuthorization({ ...selection, proposals: [proposal, conflict] }),
    /多个|冲突/u,
  );
  assert.throws(
    () => selectCandidateAuthorization({ ...selection, registryDigest: "d".repeat(64) }),
    /digest/u,
  );
  assert.throws(
    () =>
      selectCandidateAuthorization({
        ...selection,
        expectedProducerWorkflowSha: canonicalProducerWorkflowSha,
      }),
    /ProposedGateRegistryApprovalV1/u,
  );
});

test("proposal replay、字段混配、approval digest 漂移与时间窗均 fail closed", () => {
  const currentRecord = {
    approvalEvidenceDigest: "1".repeat(64),
    effectiveAt: "2026-08-09T00:00:00Z",
    gateImplementationDigest: "2".repeat(64),
    gateRegistryDigest: "3".repeat(64),
    providerRepositoryId: "1303415307",
    schemaVersion: 1,
    sequence: 24,
    sourceCommit: "4".repeat(40),
  };
  const pair = createProposedPair({
    currentRecord,
    effectiveAt: "2026-08-09T01:00:00Z",
    expiresAt: "2026-08-10T01:00:00Z",
    headOid: "5".repeat(40),
    producerWorkflowSha: "b".repeat(40),
    pullNumber: 9,
  });
  const validate = (candidate) =>
    validateProposedRegistryApproval({
      ...candidate,
      currentRecord,
      expectedProducerWorkflowSha: candidate.approval.producerWorkflowSha,
      now: Date.parse("2026-08-09T12:00:00Z"),
    });

  const mutations = [
    (candidate) => (candidate.record.providerRepositoryId = "1"),
    (candidate) => (candidate.record.pullNumber = 10),
    (candidate) => (candidate.record.sequence = 26),
    (candidate) => (candidate.record.sourceCommit = "6".repeat(40)),
    (candidate) => (candidate.record.headOid = "6".repeat(40)),
    (candidate) => (candidate.record.baseGateRegistryDigest = "7".repeat(64)),
    (candidate) => (candidate.record.gateRegistryDigest = "8".repeat(64)),
    (candidate) => (candidate.record.gateImplementationDigest = "9".repeat(64)),
    (candidate) => (candidate.record.approvalEvidenceDigest = "0".repeat(64)),
    (candidate) => (candidate.approval.producerWorkflowSha = "c".repeat(40)),
  ];
  for (const mutate of mutations) {
    const candidate = structuredClone(pair);
    mutate(candidate);
    assert.throws(() => validate(candidate), /ProposedGateRegistryApprovalV1/u);
  }

  const oldPair = createProposedPair({
    currentRecord,
    effectiveAt: pair.record.effectiveAt,
    expiresAt: pair.record.expiresAt,
    headOid: "6".repeat(40),
    producerWorkflowSha: pair.approval.producerWorkflowSha,
    pullNumber: 9,
  });
  const replay = {
    approval: oldPair.approval,
    record: {
      ...pair.record,
      approvalEvidenceDigest: sha256CanonicalJson(oldPair.approval),
    },
  };
  assert.throws(() => validate(replay), /ProposedGateRegistryApprovalV1/u);

  for (const [effectiveAt, expiresAt, now] of [
    ["2026-08-09T13:00:00Z", "2026-08-10T01:00:00Z", "2026-08-09T12:00:00Z"],
    ["2026-08-09T01:00:00Z", "2026-08-09T11:00:00Z", "2026-08-09T12:00:00Z"],
    ["2026-08-09T01:00:00Z", "2026-08-09T01:00:00Z", "2026-08-09T01:00:00Z"],
  ]) {
    const windowPair = createProposedPair({
      currentRecord,
      effectiveAt,
      expiresAt,
      headOid: pair.record.headOid,
      producerWorkflowSha: pair.approval.producerWorkflowSha,
      pullNumber: 9,
    });
    assert.throws(
      () =>
        validateProposedRegistryApproval({
          ...windowPair,
          currentRecord,
          expectedProducerWorkflowSha: windowPair.approval.producerWorkflowSha,
          now: Date.parse(now),
        }),
      /ProposedGateRegistryApprovalV1/u,
    );
  }
});

test("proposal loader 对缺失 approval fail closed，Harness 继续强制 expected workflow", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "controller-missing-approval-"));
  const currentRecord = {
    approvalEvidenceDigest: "1".repeat(64),
    effectiveAt: "2026-08-09T00:00:00Z",
    gateImplementationDigest: "2".repeat(64),
    gateRegistryDigest: "3".repeat(64),
    providerRepositoryId: "1303415307",
    schemaVersion: 1,
    sequence: 24,
    sourceCommit: "4".repeat(40),
  };
  const pair = createProposedPair({
    currentRecord,
    effectiveAt: "2026-08-09T01:00:00Z",
    expiresAt: "2026-08-10T01:00:00Z",
    headOid: "5".repeat(40),
    producerWorkflowSha: "b".repeat(40),
    pullNumber: 9,
  });
  try {
    await writeFile(path.join(directory, "missing.json"), JSON.stringify(pair.record));
    await assert.rejects(
      loadApprovedProposals(directory, { currentRecord }),
      /ENOENT|no such file/u,
    );
  } finally {
    await rm(directory, { force: true, recursive: true });
  }

  assert.throws(
    () =>
      selectTrustedRecordForCandidate({
        currentRecord,
        headOid: pair.record.headOid,
        now: Date.parse("2026-08-09T12:00:00Z"),
        proposals: [pair],
        providerRepositoryId: currentRecord.providerRepositoryId,
        pullNumber: 9,
        registryDigest: pair.record.gateRegistryDigest,
        workflowSha: "c".repeat(40),
      }),
    /ProposedGateRegistryApprovalV1/u,
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

    const controllerProposals = await loadApprovedProposals(directory, {
      currentRecord,
      now: Date.parse("2026-07-24T12:00:00Z"),
    });
    assert.deepEqual(
      controllerProposals.map(({ record }) => record.pullNumber),
      [1, 2, 3],
    );
    assert.throws(
      () =>
        selectCandidateAuthorization({
          canonicalProducerWorkflowSha: workflowSha,
          currentRecord,
          headOid: fixtures[2][1].record.headOid,
          now: Date.parse("2026-07-24T12:00:00Z"),
          proposals: controllerProposals,
          providerRepositoryId: currentRecord.providerRepositoryId,
          pullNumber: fixtures[2][1].record.pullNumber,
          registryDigest: fixtures[2][1].record.gateRegistryDigest,
        }),
      /ProposedGateRegistryApprovalV1/u,
    );

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

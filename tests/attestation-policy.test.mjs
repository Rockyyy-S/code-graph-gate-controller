import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import {
  validateProviderGateJob,
  validateProviderWorkflowRun,
  validateVerifiedAttestations,
} from "../lib/attestation-policy.mjs";

const evidenceBytes = Buffer.from('{"schemaVersion":1}\n', "utf8");
const evidenceDigest = createHash("sha256").update(evidenceBytes).digest("hex");
const mergeCommitOid = "a".repeat(40);
const headOid = "b".repeat(40);
const producerWorkflowSha = "c".repeat(40);
const runId = "29979602524";
const runAttempt = 2;
const pullNumber = 5;
const repository = "Rockyyy-S/code-graph";
const repositoryId = "1303415307";
const signerWorkflowRef =
  `Rockyyy-S/code-graph-gate-controller/.github/workflows/produce-gate-evidence.yml@${producerWorkflowSha}`;
const signerUri = `https://github.com/${signerWorkflowRef}`;
const sourceRef = `refs/pull/${pullNumber}/merge`;
const invocationUri = `https://github.com/${repository}/actions/runs/${runId}/attempts/${runAttempt}`;

/** 创建与 GitHub attestation verify JSON 输出等价的最小可信 fixture。 */
function createAttestationFixture() {
  return [
    {
      verificationResult: {
        signature: {
          certificate: {
            buildConfigDigest: mergeCommitOid,
            buildConfigURI:
              `https://github.com/${repository}/.github/workflows/architecture-required.yml@${sourceRef}`,
            buildSignerDigest: producerWorkflowSha,
            buildSignerURI: signerUri,
            buildTrigger: "pull_request",
            githubWorkflowName: "child-gate-evidence",
            githubWorkflowRef: sourceRef,
            githubWorkflowRepository: repository,
            githubWorkflowSHA: mergeCommitOid,
            githubWorkflowTrigger: "pull_request",
            issuer: "https://token.actions.githubusercontent.com",
            runnerEnvironment: "github-hosted",
            sourceRepositoryDigest: mergeCommitOid,
            sourceRepositoryIdentifier: repositoryId,
            sourceRepositoryRef: sourceRef,
            sourceRepositoryURI: `https://github.com/${repository}`,
            sourceRepositoryVisibilityAtSigning: "public",
            subjectAlternativeName: signerUri,
          },
        },
        statement: {
          predicate: {
            buildDefinition: {
              externalParameters: {
                workflow: {
                  path: ".github/workflows/architecture-required.yml",
                  ref: sourceRef,
                  repository: `https://github.com/${repository}`,
                },
              },
              internalParameters: {
                github: {
                  event_name: "pull_request",
                  repository_id: repositoryId,
                  runner_environment: "github-hosted",
                },
              },
              resolvedDependencies: [
                {
                  digest: { gitCommit: mergeCommitOid },
                  uri: `git+https://github.com/${repository}@${sourceRef}`,
                },
              ],
            },
            runDetails: {
              builder: { id: signerUri },
              metadata: { invocationId: invocationUri },
            },
          },
          predicateType: "https://slsa.dev/provenance/v1",
          subject: [{ digest: { sha256: evidenceDigest }, name: "gate-evidence.json" }],
        },
      },
    },
  ];
}

/** 创建 provider API 返回的 gate job 与 GitHub Actions check fixture。 */
function createProviderJobFixture() {
  return {
    checkRun: {
      app: { id: 15368, slug: "github-actions" },
      conclusion: "success",
      head_sha: headOid,
      id: 89118921608,
      name: "gate-evidence / gate-evidence",
      status: "completed",
    },
    jobs: [
      {
        conclusion: "success",
        head_sha: headOid,
        id: 89118921608,
        name: "gate-evidence / gate-evidence",
        run_attempt: runAttempt,
        run_id: Number(runId),
        runner_group_name: "GitHub Actions",
        status: "completed",
      },
    ],
  };
}

const expectedAttestation = {
  mergeCommitOid,
  producerWorkflowSha,
  providerRepository: repository,
  providerRepositoryId: repositoryId,
  pullNumber,
  runAttempt,
  runId,
};

test("接受绑定 issuer/repository/run/signer/source/artifact 的 GitHub attestation", () => {
  const result = validateVerifiedAttestations({
    evidenceBytes,
    expected: expectedAttestation,
    verifiedAttestations: createAttestationFixture(),
  });

  assert.equal(result.artifactDigest, evidenceDigest);
  assert.equal(result.jobWorkflowRef, signerWorkflowRef);
  assert.equal(result.providerRunId, runId);
  assert.equal(result.runAttempt, runAttempt);
});

test("attestation issuer、repository、run、source、signer 或 artifact 漂移均 fail closed", () => {
  const mutations = [
    (fixture) => (fixture[0].verificationResult.signature.certificate.issuer = "https://attacker"),
    (fixture) =>
      (fixture[0].verificationResult.signature.certificate.sourceRepositoryIdentifier = "1"),
    (fixture) =>
      (fixture[0].verificationResult.statement.predicate = undefined),
    (fixture) =>
      (fixture[0].verificationResult.statement.predicate.runDetails.metadata.invocationId =
        invocationUri.replace(runId, "1")),
    (fixture) =>
      (fixture[0].verificationResult.signature.certificate.sourceRepositoryDigest = "d".repeat(40)),
    (fixture) =>
      (fixture[0].verificationResult.signature.certificate.buildSignerDigest = "e".repeat(40)),
    (fixture) =>
      (fixture[0].verificationResult.statement.subject[0].digest.sha256 = "f".repeat(64)),
  ];

  for (const mutate of mutations) {
    const fixture = createAttestationFixture();
    mutate(fixture);
    assert.throws(
      () =>
        validateVerifiedAttestations({
          evidenceBytes,
          expected: expectedAttestation,
          verifiedAttestations: fixture,
        }),
      /attestation/u,
    );
  }
});

test("拒绝多个可接受 attestation，避免来源歧义", () => {
  const fixture = createAttestationFixture();
  fixture.push(structuredClone(fixture[0]));
  assert.throws(
    () =>
      validateVerifiedAttestations({
        evidenceBytes,
        expected: expectedAttestation,
        verifiedAttestations: fixture,
      }),
    /唯一/u,
  );
});

test("provider gate job 必须来自 GitHub Actions App 15368 且绑定当前 run/head", () => {
  const fixture = createProviderJobFixture();
  const result = validateProviderGateJob({
    ...fixture,
    expected: { headOid, runAttempt, runId },
  });
  assert.equal(result.githubActionsAppId, 15368);
  assert.equal(result.jobId, "89118921608");
});

test("provider gate job 的 App、run、head 或唯一性漂移均 fail closed", () => {
  const mutations = [
    (fixture) => (fixture.checkRun.app.id = 1),
    (fixture) => (fixture.jobs[0].run_attempt = 1),
    (fixture) => (fixture.jobs[0].head_sha = "f".repeat(40)),
    (fixture) => fixture.jobs.push(structuredClone(fixture.jobs[0])),
  ];
  for (const mutate of mutations) {
    const fixture = createProviderJobFixture();
    mutate(fixture);
    assert.throws(
      () =>
        validateProviderGateJob({
          ...fixture,
          expected: { headOid, runAttempt, runId },
        }),
      /provider gate job/u,
    );
  }
});

test("provider workflow run 必须绑定可信仓库、路径、事件、attempt 与候选 head", () => {
  const run = {
    conclusion: "success",
    event: "pull_request",
    head_repository: { id: Number(repositoryId) },
    head_sha: headOid,
    id: Number(runId),
    path: ".github/workflows/architecture-required.yml",
    repository: { id: Number(repositoryId) },
    run_attempt: runAttempt,
    status: "completed",
  };
  assert.doesNotThrow(() =>
    validateProviderWorkflowRun({
      expected: { headOid, providerRepositoryId: repositoryId, runAttempt, runId },
      run,
    }),
  );

  for (const mutate of [
    (value) => (value.event = "push"),
    (value) => (value.path = ".github/workflows/attacker.yml"),
    (value) => (value.repository.id = 1),
    (value) => (value.head_sha = "f".repeat(40)),
    (value) => (value.run_attempt = 1),
  ]) {
    const drifted = structuredClone(run);
    mutate(drifted);
    assert.throws(
      () =>
        validateProviderWorkflowRun({
          expected: { headOid, providerRepositoryId: repositoryId, runAttempt, runId },
          run: drifted,
        }),
      /provider workflow run/u,
    );
  }
});

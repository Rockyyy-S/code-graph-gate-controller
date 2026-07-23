import { createHash } from "node:crypto";

const githubActionsAppId = 15368;
const oidcIssuer = "https://token.actions.githubusercontent.com";
const predicateType = "https://slsa.dev/provenance/v1";

/**
 * 验证 `gh attestation verify --format json` 的不可伪造证书字段与 SLSA 声明绑定。
 *
 * 候选 head 不直接出现在 PR merge-ref 的 attestation 中，因此调用方还必须把同一
 * provider run 的 head SHA 与 GateEvidence evaluation context 做最终 CAS 校验。
 */
export function validateVerifiedAttestations({ evidenceBytes, expected, verifiedAttestations }) {
  if (!Array.isArray(verifiedAttestations)) {
    throw new Error("GitHub attestation 验证结果必须是数组。");
  }
  const artifactDigest = createHash("sha256").update(evidenceBytes).digest("hex");
  const sourceRef = `refs/pull/${expected.pullNumber}/merge`;
  const sourceRepositoryUri = `https://github.com/${expected.providerRepository}`;
  const signerWorkflowRef =
    `Rockyyy-S/code-graph-gate-controller/.github/workflows/produce-gate-evidence.yml@${expected.producerWorkflowSha}`;
  const signerUri = `https://github.com/${signerWorkflowRef}`;
  const invocationUri =
    `https://github.com/${expected.providerRepository}/actions/runs/${expected.runId}/attempts/${expected.runAttempt}`;
  const buildConfigUri =
    `${sourceRepositoryUri}/.github/workflows/architecture-required.yml@${sourceRef}`;

  const matching = verifiedAttestations.filter((entry) => {
    const result = entry?.verificationResult;
    const certificate = result?.signature?.certificate;
    const statement = result?.statement;
    const buildDefinition = statement?.predicate?.buildDefinition;
    const workflow = buildDefinition?.externalParameters?.workflow;
    const internalGithub = buildDefinition?.internalParameters?.github;
    const dependencies = buildDefinition?.resolvedDependencies;
    const runDetails = statement?.predicate?.runDetails;
    const subjects = statement?.subject;
    return (
      certificate?.issuer === oidcIssuer &&
      certificate?.subjectAlternativeName === signerUri &&
      certificate?.buildSignerURI === signerUri &&
      certificate?.buildSignerDigest === expected.producerWorkflowSha &&
      certificate?.runnerEnvironment === "github-hosted" &&
      certificate?.sourceRepositoryURI === sourceRepositoryUri &&
      certificate?.sourceRepositoryIdentifier === expected.providerRepositoryId &&
      certificate?.sourceRepositoryVisibilityAtSigning === "public" &&
      certificate?.sourceRepositoryRef === sourceRef &&
      certificate?.sourceRepositoryDigest === expected.mergeCommitOid &&
      certificate?.githubWorkflowRepository === expected.providerRepository &&
      certificate?.githubWorkflowName === "child-gate-evidence" &&
      certificate?.githubWorkflowRef === sourceRef &&
      certificate?.githubWorkflowSHA === expected.mergeCommitOid &&
      certificate?.githubWorkflowTrigger === "pull_request" &&
      certificate?.buildTrigger === "pull_request" &&
      certificate?.buildConfigURI === buildConfigUri &&
      certificate?.buildConfigDigest === expected.mergeCommitOid &&
      statement?.predicateType === predicateType &&
      Array.isArray(subjects) &&
      subjects.length === 1 &&
      subjects[0]?.name === "gate-evidence.json" &&
      subjects[0]?.digest?.sha256 === artifactDigest &&
      workflow?.path === ".github/workflows/architecture-required.yml" &&
      workflow?.ref === sourceRef &&
      workflow?.repository === sourceRepositoryUri &&
      internalGithub?.event_name === "pull_request" &&
      `${internalGithub?.repository_id ?? ""}` === expected.providerRepositoryId &&
      internalGithub?.runner_environment === "github-hosted" &&
      Array.isArray(dependencies) &&
      dependencies.length === 1 &&
      dependencies[0]?.uri === `git+${sourceRepositoryUri}@${sourceRef}` &&
      dependencies[0]?.digest?.gitCommit === expected.mergeCommitOid &&
      runDetails?.builder?.id === signerUri &&
      runDetails?.metadata?.invocationId === invocationUri
    );
  });

  if (matching.length !== 1) {
    throw new Error("GitHub attestation 必须唯一匹配可信 issuer、repository、run、signer、source 与 artifact。\n");
  }
  return {
    artifactDigest,
    eventName: "pull_request",
    jobWorkflowRef: signerWorkflowRef,
    oidcIssuer,
    oidcVerificationResult: "verified-by-gh-attestation",
    providerRepositoryId: expected.providerRepositoryId,
    providerRunId: expected.runId,
    runAttempt: expected.runAttempt,
    sourceRepositoryDigest: expected.mergeCommitOid,
  };
}

/** 验证 provider run 中唯一 gate job 及其 GitHub Actions App check 来源。 */
export function validateProviderGateJob({ checkRun, expected, jobs }) {
  if (!Array.isArray(jobs)) {
    throw new Error("provider gate job 列表无效。");
  }
  const matching = jobs.filter(
    (job) =>
      job?.name === "gate-evidence / gate-evidence" &&
      `${job.run_id ?? ""}` === expected.runId &&
      job.run_attempt === expected.runAttempt &&
      job.head_sha === expected.headOid &&
      job.status === "completed" &&
      job.conclusion === "success" &&
      job.runner_group_name === "GitHub Actions",
  );
  if (matching.length !== 1) {
    throw new Error("provider gate job 必须唯一绑定当前 run/attempt/head 并成功完成。");
  }
  const job = matching[0];
  if (
    `${checkRun?.id ?? ""}` !== `${job.id}` ||
    checkRun?.name !== job.name ||
    checkRun?.head_sha !== expected.headOid ||
    checkRun?.status !== "completed" ||
    checkRun?.conclusion !== "success" ||
    checkRun?.app?.id !== githubActionsAppId ||
    checkRun?.app?.slug !== "github-actions"
  ) {
    throw new Error("provider gate job 的 check/App identity 与 GitHub Actions 可信来源不一致。");
  }
  return {
    githubActionsAppId,
    jobId: `${job.id}`,
  };
}

/** 验证 provider workflow run 本身来自固定候选入口并绑定当前 attempt/head。 */
export function validateProviderWorkflowRun({ expected, run }) {
  if (
    `${run?.id ?? ""}` !== expected.runId ||
    run?.run_attempt !== expected.runAttempt ||
    run?.event !== "pull_request" ||
    run?.path !== ".github/workflows/architecture-required.yml" ||
    run?.head_sha !== expected.headOid ||
    `${run?.repository?.id ?? ""}` !== expected.providerRepositoryId ||
    `${run?.head_repository?.id ?? ""}` !== expected.providerRepositoryId ||
    run?.status !== "completed" ||
    run?.conclusion !== "success"
  ) {
    throw new Error("provider workflow run 未绑定可信仓库、入口、事件、attempt 或候选 head。");
  }
  return {
    providerRunId: expected.runId,
    runAttempt: expected.runAttempt,
  };
}

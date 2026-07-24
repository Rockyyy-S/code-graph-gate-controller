import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import {
  validateProviderGateJob,
  validateProviderWorkflowRun,
  validateVerifiedAttestations,
} from "../lib/attestation-policy.mjs";
import { runBestEffort } from "../lib/best-effort.mjs";
import {
  evaluateControllerCandidate,
  selectFreshDriftMonitorRun,
} from "../lib/controller-policy.mjs";
import { sha256CanonicalJson } from "../lib/canonical-json.mjs";
import { publishControllerCheck } from "../lib/controller-check-publisher.mjs";
import { downloadArtifact, githubJson, runTool } from "../lib/github-api.mjs";
import {
  collectGithubPages,
  collectGithubPagesBestEffort,
} from "../lib/github-pagination.mjs";
import { validateTrustedRegistryApproval } from "../lib/registry.mjs";

const targetRepository = process.env.TARGET_REPOSITORY ?? "Rockyyy-S/code-graph";
const targetRepositoryId = process.env.TARGET_REPOSITORY_ID ?? "1303415307";
const controllerRepository = "Rockyyy-S/code-graph-gate-controller";
const producerWorkflowSha = "48a9ee8b1034f4b656a209bc6f1138dcd3755311";
const controllerAppId = process.env.CONTROLLER_APP_ID;
const controllerRepositoryToken = process.env.CONTROLLER_REPOSITORY_TOKEN;

/** 标记必须撤销旧成功并令 workflow 失败的 monitor 无效状态。 */
class DriftMonitorInvalidError extends Error {
  constructor(cause) {
    super(
      cause instanceof Error ? cause.message : "drift monitor 状态不可验证。",
      { cause },
    );
    this.name = "DriftMonitorInvalidError";
  }
}

if (!/^[1-9][0-9]*$/u.test(controllerAppId ?? "") || !controllerRepositoryToken) {
  throw new Error("Controller App identity 或 controller repository token 缺失。\n");
}

const trustedRecord = JSON.parse(await readFile("trusted/registry.json", "utf8"));
const trustedApproval = JSON.parse(
  await readFile("trusted/registry-approval.json", "utf8"),
);
const previousTrustedRecord = JSON.parse(
  await readFile("trusted/previous-registry.json", "utf8"),
);
const previousTrustedApproval = JSON.parse(
  await readFile("trusted/previous-registry-approval.json", "utf8"),
);
validateTrustedRegistryApproval({
  approval: trustedApproval,
  expectedProducerWorkflowSha: producerWorkflowSha,
  previousApproval: previousTrustedApproval,
  previousRecord: previousTrustedRecord,
  record: trustedRecord,
});
let pulls = [];
try {
  await assertFreshDriftMonitor();
  pulls = await listOpenPulls();
  for (const pull of pulls) {
    await processPullRequest(pull, trustedRecord);
  }
} catch (caughtError) {
  let error = caughtError;
  const revocationFailures = [];
  if (!(error instanceof DriftMonitorInvalidError)) {
    try {
      await assertFreshDriftMonitor();
    } catch (monitorError) {
      error = monitorError;
      revocationFailures.push(caughtError);
    }
    if (!(error instanceof DriftMonitorInvalidError)) {
      throw error;
    }
  }
  const refreshed = await listOpenPullsBestEffort();
  if (refreshed.error !== null) {
    revocationFailures.push(refreshed.error);
  }
  const revocationPulls = mergePullSnapshots(pulls, refreshed.values);
  revocationFailures.push(...await publishDriftFailureForOpenPulls(
    revocationPulls,
    trustedRecord,
    error,
  ));
  if (revocationFailures.length > 0) {
    throw new AggregateError(
      [error, ...revocationFailures],
      `drift monitor 无效，且撤销过程发生 ${revocationFailures.length} 个错误。`,
    );
  }
  throw error;
}

/** 完整读取当前全部开放 PR；分页不完整时拒绝继续发布正常结论。 */
async function listOpenPulls() {
  return collectGithubPages({
    endpoint: `repos/${targetRepository}/pulls?state=open`,
    field: null,
    request: githubJson,
  });
}

/** drift 撤销路径保留已成功读取的 PR，即使后续分页 API 失败。 */
async function listOpenPullsBestEffort() {
  return collectGithubPagesBestEffort({
    endpoint: `repos/${targetRepository}/pulls?state=open`,
    field: null,
    request: githubJson,
  });
}

/** 合并运行开始与 drift 失败时的 PR/head 快照，覆盖两次采样间已观察到的变化。 */
function mergePullSnapshots(...snapshots) {
  const pullsByHead = new Map();
  for (const snapshot of snapshots) {
    for (const pull of snapshot) {
      pullsByHead.set(`${pull?.number ?? "unknown"}:${pull?.head?.sha ?? "unknown"}`, pull);
    }
  }
  return [...pullsByHead.values()];
}

/** 对单个 PR 只消费 provider API 返回的 run/artifact，并发布 App-owned umbrella check。 */
async function processPullRequest(pull, trustedRecord) {
  const headOid = pull.head.sha;
  const runs = await collectGithubPages({
    endpoint:
      `repos/${targetRepository}/actions/workflows/architecture-required.yml/runs` +
      `?event=pull_request&head_sha=${headOid}`,
    field: "workflow_runs",
    request: githubJson,
  });
  const run = runs
    .filter((candidate) => candidate.head_sha === headOid)
    .sort((left, right) => right.run_attempt - left.run_attempt || right.id - left.id)[0];
  if (run === undefined || run.status !== "completed") {
    await publishCheck(headOid, "in_progress", null, "等待可信 child evidence workflow 完成。", null);
    return;
  }
  if (run.conclusion !== "success") {
    await publishCheck(
      headOid,
      "completed",
      "failure",
      `child evidence workflow run ${run.id}/${run.run_attempt} 未成功。`,
      null,
    );
    return;
  }
  const artifacts = await collectGithubPages({
    endpoint: `repos/${targetRepository}/actions/runs/${run.id}/artifacts`,
    field: "artifacts",
    request: githubJson,
  });
  const expectedPrefix = `gate-evidence-${run.id}-${run.run_attempt}-${headOid}`;
  const matching = artifacts.filter(
    (artifact) => artifact.name === expectedPrefix && !artifact.expired,
  );
  if (matching.length !== 1) {
    await publishCheck(headOid, "completed", "failure", "required evidence artifact 缺失或重复。", null);
    return;
  }
  const temporaryRoot = await mkdtemp(path.join(tmpdir(), "architecture-controller-"));
  try {
    const expectedRun = {
      headOid,
      providerRepositoryId: targetRepositoryId,
      runAttempt: run.run_attempt,
      runId: `${run.id}`,
    };
    validateProviderWorkflowRun({ expected: expectedRun, run });
    const jobs = await collectGithubPages({
      endpoint:
        `repos/${targetRepository}/actions/runs/${run.id}/attempts/` +
        `${run.run_attempt}/jobs`,
      field: "jobs",
      request: githubJson,
    });
    const jobsResponse = { jobs };
    const namedJobs = jobs.filter(
      (job) => job.name === "gate-evidence / gate-evidence",
    );
    if (namedJobs.length !== 1) {
      throw new Error("provider gate job 缺失、重复或名称漂移。\n");
    }
    const checkRun = await githubJson(
      `repos/${targetRepository}/check-runs/${namedJobs[0].id}`,
    );
    const providerJobRecord = validateProviderGateJob({
      checkRun,
      expected: expectedRun,
      jobs: jobsResponse.jobs,
    });
    const archivePath = path.join(temporaryRoot, "artifact.zip");
    const archive = await downloadArtifact(matching[0].archive_download_url);
    await writeFile(archivePath, archive);
    await runTool("unzip", ["-q", archivePath, "-d", temporaryRoot]);
    const evidencePath = path.join(temporaryRoot, "gate-evidence.json");
    const attestationOutput = await runTool("gh", [
      "attestation",
      "verify",
      evidencePath,
      "--repo",
      targetRepository,
      "--cert-oidc-issuer",
      "https://token.actions.githubusercontent.com",
      "--signer-workflow",
      `github.com/${controllerRepository}/.github/workflows/produce-gate-evidence.yml`,
      "--signer-digest",
      producerWorkflowSha,
      "--deny-self-hosted-runners",
      "--format",
      "json",
    ]);
    const verifiedAttestations = JSON.parse(attestationOutput.toString("utf8"));
    const evidenceBytes = await readFile(evidencePath);
    const currentPull = await githubJson(`repos/${targetRepository}/pulls/${pull.number}`);
    if (!/^[a-f0-9]{40}$/u.test(currentPull.merge_commit_sha ?? "")) {
      throw new Error("provider 当前 PR merge commit OID 缺失或非法。\n");
    }
    const attestationRecord = validateVerifiedAttestations({
      evidenceBytes,
      expected: {
        mergeCommitOid: currentPull.merge_commit_sha,
        producerWorkflowSha,
        providerRepository: targetRepository,
        providerRepositoryId: targetRepositoryId,
        pullNumber: pull.number,
        runAttempt: run.run_attempt,
        runId: `${run.id}`,
      },
      verifiedAttestations,
    });
    const artifact = JSON.parse(evidenceBytes.toString("utf8"));
    const registry = await readCandidateRegistry(headOid);
    const result = evaluateControllerCandidate({
      artifact,
      currentProviderContext: {
        baseOid: currentPull.base.sha,
        headOid: currentPull.head.sha,
        providerRepositoryId: `${currentPull.base.repo.id}`,
      },
      registry,
      trustedRecord,
    });
    const providerEvidenceRecord = {
      ...attestationRecord,
      ...providerJobRecord,
      gateEvidenceDigests: result.gateEvidenceDigests ?? [],
      headOid,
      jobName: "gate-evidence / gate-evidence",
      schemaVersion: 1,
      workflowRef:
        `${targetRepository}/.github/workflows/architecture-required.yml@refs/pull/${pull.number}/merge`,
    };
    const replayDigest = sha256CanonicalJson({
      artifactDigest: attestationRecord.artifactDigest,
      gateEvidenceDigests: result.gateEvidenceDigests ?? [],
    });
    const summary = JSON.stringify({ providerEvidenceRecord, replayDigest, result });
    await publishCheck(
      headOid,
      "completed",
      result.conclusion,
      summary,
      result.casKey ?? null,
      replayDigest,
    );
  } catch (error) {
    if (error instanceof DriftMonitorInvalidError) {
      throw error;
    }
    await publishCheck(
      headOid,
      "completed",
      "failure",
      error instanceof Error ? error.message : "Controller 未知验证错误。",
      null,
    );
  } finally {
    await rm(temporaryRoot, { force: true, recursive: true });
  }
}

/** 从 candidate head 的唯一 registry 路径读取 data，不执行候选代码。 */
async function readCandidateRegistry(headOid) {
  const response = await githubJson(
    `repos/${targetRepository}/contents/ci/quality-gates.v1.yaml?ref=${headOid}`,
  );
  return JSON.parse(Buffer.from(response.content, "base64").toString("utf8"));
}

/** Controller 只在独立 monitor 最近成功且未过期时发布正式结论。 */
async function assertFreshDriftMonitor() {
  try {
    const runs = await githubJson(
      `repos/${controllerRepository}/actions/workflows/drift-monitor.yml/runs?per_page=10`,
      { token: controllerRepositoryToken },
    );
    return selectFreshDriftMonitorRun(runs.workflow_runs);
  } catch (error) {
    throw new DriftMonitorInvalidError(error);
  }
}

/** monitor 失败或过期时 best-effort 覆盖全部开放 PR，并返回未撤销成功的异常。 */
async function publishDriftFailureForOpenPulls(pulls, trustedRecord, error) {
  const reason = error instanceof Error ? error.message : "drift monitor 状态不可验证。";
  return runBestEffort(pulls, async (pull) => {
    const headOid = pull.head.sha;
    const casKey = `${targetRepositoryId}:${headOid}:drift-monitor:${trustedRecord.sequence}`;
    const replayDigest = sha256CanonicalJson({
      reason,
      schemaVersion: 1,
      trustedSequence: trustedRecord.sequence,
    });
    await publishCheck(
      headOid,
      "completed",
      "failure",
      JSON.stringify({
        casKey,
        reason,
        replayDigest,
        status: "drift-monitor-invalid",
        trustedSequence: trustedRecord.sequence,
      }),
      casKey,
      replayDigest,
      true,
    );
  });
}

/** 使用 Controller GitHub App installation token 发布唯一 architecture-required check。 */
async function publishCheck(
  headOid,
  status,
  conclusion,
  summary,
  casKey,
  replayDigest = null,
  allowFailureOnHistoryError = false,
) {
  return publishControllerCheck({
    allowFailureOnHistoryError,
    assertFreshMonitor: assertFreshDriftMonitor,
    casKey,
    conclusion,
    headOid,
    loadChecks: async () => {
      const existing = await collectGithubPages({
        endpoint: `repos/${targetRepository}/commits/${headOid}/check-runs?filter=all`,
        field: "check_runs",
        request: githubJson,
      });
      return existing.filter(
        (check) =>
          check.name === "architecture-required" &&
          `${check.app?.id ?? ""}` === controllerAppId,
      );
    },
    postCheck: async (body) =>
      githubJson(`repos/${targetRepository}/check-runs`, {
        body,
        method: "POST",
      }),
    replayDigest,
    status,
    summary,
  });
}

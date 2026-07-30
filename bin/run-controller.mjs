import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { AsyncLocalStorage } from "node:async_hooks";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  validateProviderGateJob,
  validateProviderWorkflowRun,
  validateVerifiedAttestations,
} from "../lib/attestation-policy.mjs";
import { runBestEffort } from "../lib/best-effort.mjs";
import {
  DRIFT_MONITOR_REFRESH_AFTER_MS,
  evaluateDriftMonitorLease,
  evaluateControllerCandidate,
  selectLatestWorkflowRun,
} from "../lib/controller-policy.mjs";
import { sha256CanonicalJson } from "../lib/canonical-json.mjs";
import { publishControllerCheck } from "../lib/controller-check-publisher.mjs";
import { downloadArtifact, githubJson, runTool } from "../lib/github-api.mjs";
import {
  collectGithubPages,
  collectGithubPagesBestEffort,
} from "../lib/github-pagination.mjs";
import {
  loadApprovedProposals,
  selectTrustedRecordForCandidate,
  validateTrustedRegistryApproval,
} from "../lib/registry.mjs";

const targetRepository = process.env.TARGET_REPOSITORY ?? "Rockyyy-S/code-graph";
const targetRepositoryId = process.env.TARGET_REPOSITORY_ID ?? "1303415307";
const controllerRepository = "Rockyyy-S/code-graph-gate-controller";
const producerWorkflowSha = "162b714d56a3c4f864daac6c2ac5c8336578871c";
const controllerAppId = process.env.CONTROLLER_APP_ID;
const controllerRepositoryToken = process.env.CONTROLLER_REPOSITORY_TOKEN;
const controllerTrustedSha = process.env.CONTROLLER_TRUSTED_SHA;
const controllerDefaultBranch = "main";
const driftMonitorWorkflowPath = ".github/workflows/drift-monitor.yml";
const defaultControllerCycleTimeoutMs = 9 * 60 * 1000;
const defaultControllerRevocationTimeoutMs = 45_000;
const controllerRuntimeStorage = new AsyncLocalStorage();
const controllerMonitorRefreshState = { attemptedAt: null };

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

/** 标记当前运行的固定 Controller SHA 已不再是默认分支尖端。 */
export class ControllerRevisionDriftError extends Error {
  constructor() {
    super("Controller 默认分支 SHA 已漂移，当前 monitor 证据不可复用。");
    this.name = "ControllerRevisionDriftError";
  }
}

/** 执行一次 Controller 聚合；任意可信配置、provider 或验证错误都先撤销旧 success。 */
export async function runControllerCycle(options = {}) {
  const runtime = createControllerRuntime(options);
  return controllerRuntimeStorage.run(runtime, () =>
    executeControllerCycle({
      assertFresh: assertFreshDriftMonitor,
      listPulls: listOpenPulls,
      loadState: loadTrustedState,
      processPull: processPullRequest,
      revokePulls: (pulls, trustedRecord, error) =>
        runControllerRevocation(pulls, trustedRecord, error, options),
    }),
  );
}

/** 超时后的撤销使用独立预算，禁止复用已 aborted 的正常 cycle runtime。 */
function runControllerRevocation(pulls, trustedRecord, error, options) {
  const runtime = createControllerRevocationRuntime(options);
  return controllerRuntimeStorage.run(runtime, () =>
    revokeOpenPullsUntilStable(pulls, trustedRecord, error),
  );
}

/** 可注入边界的单轮状态机，供全局 fail-closed 回归测试验证。 */
export async function executeControllerCycle({
  assertFresh,
  listPulls,
  loadState,
  processPull,
  revokePulls,
}) {
  let trustedState = null;
  let pulls = [];
  try {
    trustedState = await loadState();
    await assertFresh();
    pulls = await listPulls();
    assertUniqueOpenPullHeads(pulls);
    for (const pull of pulls) {
      await processPull(pull, trustedState);
    }
  } catch (error) {
    const revocationFailures = await revokePulls(
      pulls,
      trustedState,
      error,
    );
    if (revocationFailures.length > 0) {
      throw new AggregateError(
        [error, ...revocationFailures],
        `Controller fail closed，且撤销过程发生 ${revocationFailures.length} 个错误。`,
      );
    }
    throw error;
  }
}

/** 在进入正常路径前校验 App、monitor token、可信提交与 registry 审批链。 */
async function loadTrustedState() {
  if (
    !/^[1-9][0-9]*$/u.test(controllerAppId ?? "") ||
    !controllerRepositoryToken ||
    !/^[a-f0-9]{40}$/u.test(controllerTrustedSha ?? "")
  ) {
    throw new Error("Controller App identity、controller token 或可信提交 SHA 缺失。\n");
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
    expectedProducerWorkflowSha: trustedApproval.producerWorkflowSha,
    previousApproval: previousTrustedApproval,
    previousRecord: previousTrustedRecord,
    record: trustedRecord,
  });
  const proposals = await loadApprovedProposals("trusted/proposed", {
    currentRecord: trustedRecord,
    expectedProducerWorkflowSha: producerWorkflowSha,
  });
  return { currentRecord: trustedRecord, proposals };
}

/** 完整读取当前全部开放 PR；分页不完整时拒绝继续发布正常结论。 */
async function listOpenPulls() {
  return collectGithubPages({
    endpoint: `repos/${targetRepository}/pulls?state=open`,
    field: null,
    request: controllerGithubJson,
  });
}

/** drift 撤销路径保留已成功读取的 PR，即使后续分页 API 失败。 */
async function listOpenPullsBestEffort() {
  return collectGithubPagesBestEffort({
    endpoint: `repos/${targetRepository}/pulls?state=open`,
    field: null,
    request: controllerGithubJson,
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

/**
 * 重复采样开放 PR，直到发布 failure 前后的 head/base 集合稳定。
 *
 * 该循环覆盖撤销期间的 force-push、reopen 与新 PR；持续抖动或分页失败会保留已完成撤销并
 * 汇总失败，交由常驻 lease guardian 下一轮继续 fail closed。
 */
async function revokeOpenPullsUntilStable(initialPulls, trustedRecord, error) {
  const failures = [];
  let observedPulls = initialPulls;
  for (let attempt = 0; attempt < 5; attempt += 1) {
    const before = await listOpenPullsBestEffort();
    if (before.error !== null) {
      failures.push(before.error);
    }
    observedPulls = mergePullSnapshots(observedPulls, before.values);
    failures.push(...await publishDriftFailureForOpenPulls(
      observedPulls,
      trustedRecord,
      error,
    ));
    const after = await listOpenPullsBestEffort();
    if (after.error !== null) {
      failures.push(after.error);
      continue;
    }
    observedPulls = mergePullSnapshots(observedPulls, after.values);
    if (sameCurrentPullSnapshot(before.values, after.values)) {
      return failures;
    }
  }
  failures.push(new Error("开放 PR 在撤销窗口持续变化，未能取得稳定 provider 快照。"));
  return failures;
}

/** 比较当前开放 PR 的 number/base/head 集合，不把已关闭历史快照误判为仍开放。 */
export function sameCurrentPullSnapshot(left, right) {
  const keys = (pulls) => pulls
    .map(
      (pull) =>
        `${pull?.number}:${pull?.base?.sha}:${pull?.head?.sha}:${pull?.merge_commit_sha}`,
    )
    .sort();
  return JSON.stringify(keys(left)) === JSON.stringify(keys(right));
}

/** 标记 PR 在验证期间发生 head/base/state 变化，需要从最新快照重新开始。 */
class PullSnapshotChangedError extends Error {
  constructor(currentPull) {
    super("PR provider 快照在 Controller 验证期间发生变化。");
    this.currentPull = currentPull;
    this.name = "PullSnapshotChangedError";
  }
}

/** 对单个 PR 最多重试三次 provider 快照变化，禁止向旧 head 发布结论。 */
async function processPullRequest(initialPull, trustedRecord) {
  let pull = await loadCurrentOpenPull(initialPull.number);
  for (let attempt = 0; attempt < 3 && pull !== null; attempt += 1) {
    try {
      await processPullRequestSnapshot(pull, trustedRecord);
      return;
    } catch (error) {
      if (error instanceof PublishedSuccessRevocationError) {
        throw error;
      }
      if (error instanceof DriftMonitorInvalidError) {
        throw error;
      }
      if (error instanceof PullSnapshotChangedError) {
        pull = error.currentPull;
        continue;
      }
      if (error instanceof WorkflowRunChangedError) {
        pull = await loadCurrentOpenPull(pull.number);
        continue;
      }
      const currentPull = await loadCurrentOpenPull(pull.number);
      if (currentPull !== null && !samePullIdentity(pull, currentPull)) {
        pull = currentPull;
        continue;
      }
      if (currentPull !== null) {
        await publishCheckForStablePull(
          currentPull,
          "completed",
          "failure",
          error instanceof Error ? error.message : "Controller 未知验证错误。",
          null,
        );
      }
      return;
    }
  }
  if (pull !== null) {
    throw new Error(`PR #${pull.number} 在验证期间持续变化，Controller fail closed。`);
  }
}

/** 对固定 PR 快照只消费 provider API 返回的 run/artifact。 */
async function processPullRequestSnapshot(pull, trustedRecord) {
  const headOid = pull.head.sha;
  const runs = await collectGithubPages({
    endpoint:
      `repos/${targetRepository}/actions/workflows/architecture-required.yml/runs` +
      `?event=pull_request&head_sha=${headOid}`,
    field: "workflow_runs",
    request: controllerGithubJson,
  });
  const run = selectLatestWorkflowRun(runs, headOid, pull.number);
  if (run === undefined || run.status !== "completed") {
    const pending = createPendingCheckRecord({
      headOid,
      pullNumber: pull.number,
      run,
    });
    await publishCheckForStablePull(
      pull,
      "in_progress",
      null,
      pending.summary,
      pending.casKey,
      pending.replayDigest,
    );
    return;
  }
  if (run.conclusion !== "success") {
    await publishCheckForStablePull(
      pull,
      "completed",
      "failure",
      `child evidence workflow run ${run.id}/${run.run_attempt} 未成功。`,
      null,
    );
    return;
  }
  const registry = await readCandidateRegistry(headOid);
  const registryDigest = sha256CanonicalJson(registry);
  const selectTrustedCandidate = () => selectTrustedRecordForCandidate({
    currentRecord: trustedRecord.currentRecord,
    headOid,
    now: Date.now(),
    proposals: trustedRecord.proposals,
    providerRepositoryId: `${pull.base.repo.id}`,
    pullNumber: pull.number,
    registryDigest,
    workflowSha: producerWorkflowSha,
  });
  const trustedCandidateRecord = selectTrustedCandidate();
  const artifacts = await collectGithubPages({
    endpoint: `repos/${targetRepository}/actions/runs/${run.id}/artifacts`,
    field: "artifacts",
    request: controllerGithubJson,
  });
  const expectedPrefix = `gate-evidence-${run.id}-${run.run_attempt}-${headOid}`;
  const matching = artifacts.filter(
    (artifact) => artifact.name === expectedPrefix && !artifact.expired,
  );
  if (matching.length !== 1) {
    await publishCheckForStablePull(
      pull,
      "completed",
      "failure",
      "required evidence artifact 缺失或重复。",
      null,
    );
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
      request: controllerGithubJson,
    });
    const jobsResponse = { jobs };
    const namedJobs = jobs.filter(
      (job) => job.name === "gate-evidence / gate-evidence",
    );
    if (namedJobs.length !== 1) {
      throw new Error("provider gate job 缺失、重复或名称漂移。\n");
    }
    const checkRun = await controllerGithubJson(
      `repos/${targetRepository}/check-runs/${namedJobs[0].id}`,
    );
    const providerJobRecord = validateProviderGateJob({
      checkRun,
      expected: expectedRun,
      jobs: jobsResponse.jobs,
    });
    const archivePath = path.join(temporaryRoot, "artifact.zip");
    const archive = await controllerDownloadArtifact(matching[0].archive_download_url);
    await writeFile(archivePath, archive);
    await controllerRunTool("unzip", ["-q", archivePath, "-d", temporaryRoot]);
    const evidencePath = path.join(temporaryRoot, "gate-evidence.json");
    const attestationOutput = await controllerRunTool("gh", [
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
    const currentPull = await assertPullSnapshotCurrent(pull);
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
    const result = evaluateControllerCandidate({
      artifact,
      currentProviderContext: {
        baseOid: currentPull.base.sha,
        headOid: currentPull.head.sha,
        providerRepositoryId: `${currentPull.base.repo.id}`,
      },
      registry,
      trustedRecord: trustedCandidateRecord,
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
      gateImplementationDigest: result.gateImplementationDigest,
      gateEvidenceDigests: result.gateEvidenceDigests ?? [],
      trustedSequence: result.trustedSequence,
    });
    const summary = JSON.stringify({ providerEvidenceRecord, replayDigest, result });
    await assertWorkflowRunCurrent(run, headOid, pull.number);
    assertTrustedCandidateSelectionCurrent(trustedCandidateRecord, selectTrustedCandidate);
    await publishCheckForStablePull(
      currentPull,
      "completed",
      result.conclusion,
      summary,
      result.casKey ?? null,
      replayDigest,
    );
    if (result.conclusion === "success") {
      await closePublishedSuccess({
        revalidate: () => revalidatePublishedSuccess({
          assertFresh: assertFreshDriftMonitor,
          assertProposal: () =>
            assertTrustedCandidateSelectionCurrent(
              trustedCandidateRecord,
              selectTrustedCandidate,
            ),
          assertPull: assertPullSnapshotCurrent,
          assertRun: assertWorkflowRunCurrent,
          assertUnique: assertPullOwnsUniqueOpenHeadCurrent,
          expectedPull: currentPull,
          expectedRun: run,
          headOid,
          pullNumber: pull.number,
        }),
        revoke: (error) => revokePublishedSuccess(currentPull, error),
      });
    }
  } finally {
    await rm(temporaryRoot, { force: true, recursive: true });
  }
}

/** 为同一 PR/head/child run 等待态生成稳定幂等键，避免 guardian 每轮追加新 check。 */
export function createPendingCheckRecord({
  headOid,
  pullNumber,
  repositoryId = targetRepositoryId,
  run,
}) {
  const runId = Number.isSafeInteger(run?.id) ? `${run.id}` : "missing";
  const runAttempt = Number.isSafeInteger(run?.run_attempt) ? `${run.run_attempt}` : "none";
  const casKey = `${repositoryId}:${headOid}:pending:${pullNumber}:${runId}:${runAttempt}`;
  const replayDigest = sha256CanonicalJson({
    headOid,
    pullNumber,
    reason: "awaiting-child-evidence",
    runAttempt,
    runId,
    schemaVersion: 1,
  });
  return {
    casKey,
    replayDigest,
    summary: JSON.stringify({
      casKey,
      reason: "等待可信 child evidence workflow 完成。",
      replayDigest,
      status: "pending",
    }),
  };
}

/** 标记 provider 在验证期间产生了更新的 workflow run/attempt，需要从新快照重试。 */
class WorkflowRunChangedError extends Error {
  constructor() {
    super("provider workflow run/attempt 在 Controller 验证期间发生变化。");
    this.name = "WorkflowRunChangedError";
  }
}

/** 发布 success 前重新读取最新 run，禁止旧 attempt 覆盖更新的 provider 状态。 */
async function assertWorkflowRunCurrent(expectedRun, headOid, pullNumber) {
  const runs = await collectGithubPages({
    endpoint:
      `repos/${targetRepository}/actions/workflows/architecture-required.yml/runs` +
      `?event=pull_request&head_sha=${headOid}`,
    field: "workflow_runs",
    request: controllerGithubJson,
  });
  const currentRun = selectLatestWorkflowRun(runs, headOid, pullNumber);
  if (!sameWorkflowRunIdentity(expectedRun, currentRun)) {
    throw new WorkflowRunChangedError();
  }
  return currentRun;
}

/** workflow run 的稳定身份同时绑定 ID、attempt、status 与 conclusion。 */
export function sameWorkflowRunIdentity(left, right) {
  return (
    left?.id === right?.id &&
    left?.run_attempt === right?.run_attempt &&
    left?.status === right?.status &&
    left?.conclusion === right?.conclusion
  );
}

/** success 发布后再次闭合 run、PR 与 monitor；变化由上层立即覆盖为 pending/failure。 */
export async function revalidatePublishedSuccess({
  assertFresh,
  assertProposal,
  assertPull,
  assertRun,
  assertUnique,
  expectedPull,
  expectedRun,
  headOid,
  pullNumber,
}) {
  await assertRun(expectedRun, headOid, pullNumber);
  const currentPull = await assertPull(expectedPull);
  await assertUnique(currentPull);
  await assertProposal();
  await assertFresh();
  return currentPull;
}

/** success 发布后的复验失败必须先覆盖绿色；覆盖失败交由全局撤销路径处理。 */
export async function closePublishedSuccess({ revalidate, revoke }) {
  try {
    return await revalidate();
  } catch (error) {
    try {
      await revoke(error);
    } catch (revocationError) {
      throw new PublishedSuccessRevocationError(error, revocationError);
    }
    throw error;
  }
}

/** 标记 success 后的即时撤销失败，禁止单 PR 错误处理吞掉全局 fail-closed。 */
class PublishedSuccessRevocationError extends AggregateError {
  constructor(revalidationError, revocationError) {
    super(
      [revalidationError, revocationError],
      "Controller success 复验失败，且即时撤销绿色失败。",
    );
    this.name = "PublishedSuccessRevocationError";
  }
}

/** proposed/current registry 必须在发布前后保持同一有效可信选择。 */
function assertTrustedCandidateSelectionCurrent(expectedRecord, selectCurrent) {
  let currentRecord;
  try {
    currentRecord = selectCurrent();
  } catch (error) {
    throw new ProposalSelectionChangedError(error);
  }
  if (sha256CanonicalJson(currentRecord) !== sha256CanonicalJson(expectedRecord)) {
    throw new ProposalSelectionChangedError(
      new Error("候选 registry 的可信选择在验证期间发生变化。"),
    );
  }
  return currentRecord;
}

/** proposed registry 过期、尚未生效或选择漂移时撤销已发布 success。 */
class ProposalSelectionChangedError extends Error {
  constructor(cause) {
    super(cause instanceof Error ? cause.message : "候选 registry 的可信选择无效。", {
      cause,
    });
    this.name = "ProposalSelectionChangedError";
  }
}

/** 按复验失败类型把刚发布的 success 覆盖为 pending 或 failure。 */
async function revokePublishedSuccess(pull, error) {
  const retryable =
    error instanceof PullSnapshotChangedError ||
    error instanceof WorkflowRunChangedError;
  await publishCheck(
    pull.head.sha,
    retryable ? "in_progress" : "completed",
    retryable ? null : "failure",
    error instanceof Error ? error.message : "Controller success 复验失败。",
    null,
    null,
    !retryable,
  );
}

/** 读取当前开放 PR；关闭或不存在的 PR 不再发布 required check。 */
async function loadCurrentOpenPull(pullNumber) {
  const pull = await controllerGithubJson(`repos/${targetRepository}/pulls/${pullNumber}`);
  return pull?.state === "open" ? pull : null;
}

/** 发布前重新读取 PR，并在 head/base/state 变化时让上层从新快照重试。 */
async function assertPullSnapshotCurrent(expectedPull) {
  const currentPull = await loadCurrentOpenPull(expectedPull.number);
  if (currentPull === null || !samePullIdentity(expectedPull, currentPull)) {
    throw new PullSnapshotChangedError(currentPull);
  }
  return currentPull;
}

/** PR 结论绑定 number、base/head SHA 与 provider 生成的 merge commit SHA。 */
export function samePullIdentity(left, right) {
  return (
    left?.number === right?.number &&
    left?.base?.sha === right?.base?.sha &&
    left?.head?.sha === right?.head?.sha &&
    left?.merge_commit_sha === right?.merge_commit_sha
  );
}

/** 同一开放 head 只能对应一个 PR，避免 PR 专属 proposal/run 折叠为 commit 级 check。 */
export function assertUniqueOpenPullHeads(pulls) {
  const pullNumbersByHead = new Map();
  for (const pull of pulls) {
    const headOid = pull?.head?.sha;
    if (typeof headOid !== "string" || headOid.length === 0) {
      throw new Error("开放 PR 缺少可信 head SHA。\n");
    }
    const pullNumbers = pullNumbersByHead.get(headOid) ?? [];
    pullNumbers.push(pull?.number);
    pullNumbersByHead.set(headOid, pullNumbers);
  }
  for (const [headOid, pullNumbers] of pullNumbersByHead) {
    if (pullNumbers.length > 1) {
      throw new Error(
        `多个开放 PR（${pullNumbers.join(", ")}）复用同一 head ${headOid}，Controller fail closed。`,
      );
    }
  }
}

/** 验证目标 PR 仍开放、快照未变，且当前全部开放 PR 中独占该 head。 */
export function assertPullOwnsUniqueOpenHead(expectedPull, pulls) {
  assertUniqueOpenPullHeads(pulls);
  const currentPull = pulls.find((pull) => pull?.number === expectedPull?.number) ?? null;
  if (currentPull === null || !samePullIdentity(expectedPull, currentPull)) {
    throw new PullSnapshotChangedError(currentPull);
  }
  return currentPull;
}

/** 发布临界区重新枚举全部开放 PR，缩小 duplicate-head ownership 的竞态窗口。 */
async function assertPullOwnsUniqueOpenHeadCurrent(expectedPull) {
  return assertPullOwnsUniqueOpenHead(expectedPull, await listOpenPulls());
}

/** 对仍为同一 provider 快照的 PR 发布结论。 */
async function publishCheckForStablePull(
  pull,
  status,
  conclusion,
  summary,
  casKey,
  replayDigest = null,
) {
  const currentPull = await assertPullSnapshotCurrent(pull);
  await assertPullOwnsUniqueOpenHeadCurrent(currentPull);
  return publishCheck(
    currentPull.head.sha,
    status,
    conclusion,
    summary,
    casKey,
    replayDigest,
  );
}

/** 从 candidate head 的唯一 registry 路径读取 data，不执行候选代码。 */
async function readCandidateRegistry(headOid) {
  const response = await controllerGithubJson(
    `repos/${targetRepository}/contents/ci/quality-gates.v1.yaml?ref=${headOid}`,
  );
  return JSON.parse(Buffer.from(response.content, "base64").toString("utf8"));
}

/**
 * 在 Controller 进程内复用刷新状态，覆盖多次 success 复验与相邻 cycle 的重复触发窗口。
 *
 * dispatch 只改善可用性：未过期 success 可继续使用；没有 fresh success 时，即使 dispatch
 * 已成功受理，本轮仍必须 fail closed。
 */
export async function assertDriftMonitorLease({
  dispatchRefresh,
  logError = console.error,
  monitorRuns,
  options,
  refreshState,
}) {
  if (typeof refreshState !== "object" || refreshState === null) {
    throw new TypeError("drift monitor refresh state 缺失。");
  }
  const evaluation = evaluateDriftMonitorLease(monitorRuns, options);
  const now = options?.now ?? Date.now();
  const refreshAgeMs = now - refreshState.attemptedAt;
  const cooldownElapsed =
    !Number.isFinite(refreshState.attemptedAt) ||
    refreshAgeMs >= DRIFT_MONITOR_REFRESH_AFTER_MS ||
    refreshAgeMs < -30_000;
  if (evaluation.shouldRefresh && cooldownElapsed) {
    // 先占用进程内冷却窗口，覆盖 runs API 尚未显现新运行的最终一致性间隙。
    refreshState.attemptedAt = now;
    const refreshPromise = attemptDriftMonitorRefresh(dispatchRefresh, logError);
    if (evaluation.freshRun !== null) {
      await refreshPromise;
    }
  }
  if (evaluation.freshRun === null) {
    throw new DriftMonitorInvalidError(
      new Error("独立 drift monitor 缺失、失败、来自未来或已过期，Controller fail closed。\n"),
    );
  }
  return evaluation.freshRun;
}

/** dispatch 与日志均为 best-effort，错误不能覆盖现有 fresh success。 */
async function attemptDriftMonitorRefresh(dispatchRefresh, logError) {
  try {
    await dispatchRefresh();
  } catch (error) {
    const reason = error instanceof Error ? error.message : "未知 dispatch 错误";
    try {
      logError(`drift monitor 预刷新 dispatch 失败，继续按现有租约判定：${reason}`);
    } catch {
      // 日志适配器异常不能改变 monitor lease 的安全结论。
    }
  }
}

/** Controller 只在独立 monitor 最近成功且未过期时发布正式结论。 */
async function assertFreshDriftMonitor() {
  try {
    await assertControllerDefaultBranchCurrent();
    const runs = await controllerGithubJson(
      `repos/${controllerRepository}/actions/workflows/drift-monitor.yml/runs` +
        `?branch=${encodeURIComponent(controllerDefaultBranch)}&per_page=100`,
      { token: controllerRepositoryToken },
    );
    const runtime = controllerRuntimeStorage.getStore();
    return await assertDriftMonitorLease({
      dispatchRefresh: dispatchDriftMonitor,
      monitorRuns: runs.workflow_runs,
      options: {
        defaultBranch: controllerDefaultBranch,
        repository: controllerRepository,
        trustedHeadSha: controllerTrustedSha,
        workflowPath: driftMonitorWorkflowPath,
      },
      refreshState: runtime?.monitorRefreshState,
    });
  } catch (error) {
    if (error instanceof DriftMonitorInvalidError) {
      throw error;
    }
    throw new DriftMonitorInvalidError(error);
  }
}

/** 使用 Controller 仓库自身 token 无输入触发固定 main monitor workflow。 */
async function dispatchDriftMonitor() {
  return controllerGithubJson(
    `repos/${controllerRepository}/actions/workflows/drift-monitor.yml/dispatches`,
    {
      body: { ref: controllerDefaultBranch },
      method: "POST",
      token: controllerRepositoryToken,
      timeoutMs: 5_000,
    },
  );
}

/** monitor 证据只信任仍位于 Controller 默认分支尖端的固定部署 SHA。 */
export async function assertControllerDefaultBranchCurrent({
  defaultBranch = controllerDefaultBranch,
  repository = controllerRepository,
  request = controllerGithubJson,
  token = controllerRepositoryToken,
  trustedSha = controllerTrustedSha,
} = {}) {
  if (!/^[a-f0-9]{40}$/u.test(trustedSha ?? "")) {
    throw new Error("Controller 可信部署 SHA 缺失或非法。");
  }
  const currentCommit = await request(
    `repos/${repository}/commits/${encodeURIComponent(defaultBranch)}`,
    { token },
  );
  if (currentCommit?.sha !== trustedSha) {
    throw new ControllerRevisionDriftError();
  }
  return currentCommit;
}

/** monitor 失败或过期时 best-effort 覆盖全部开放 PR，并返回未撤销成功的异常。 */
async function publishDriftFailureForOpenPulls(pulls, trustedRecord, error) {
  const reason = error instanceof Error ? error.message : "drift monitor 状态不可验证。";
  const currentTrustedRecord = trustedRecord?.currentRecord ?? trustedRecord;
  const trustedSequence = Number.isSafeInteger(currentTrustedRecord?.sequence)
    ? currentTrustedRecord.sequence
    : null;
  return runBestEffort(pulls, async (pull) => {
    const headOid = pull.head.sha;
    const casKey = `${targetRepositoryId}:${headOid}:controller-invalid:${trustedSequence ?? "untrusted"}`;
    const replayDigest = sha256CanonicalJson({
      reason,
      schemaVersion: 1,
      trustedSequence,
    });
    await publishCheck(
      headOid,
      "completed",
      "failure",
      JSON.stringify({
        casKey,
        reason,
        replayDigest,
        status: error instanceof DriftMonitorInvalidError
          ? "drift-monitor-invalid"
          : "controller-invalid",
        trustedSequence,
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
      // 同一 head/name 的最近一页足以覆盖稳定 CAS；禁止每分钟完整分页历史。
      const response = await controllerGithubJson(
        `repos/${targetRepository}/commits/${headOid}/check-runs?filter=all&check_name=architecture-required&per_page=100`,
      );
      const existing = response.check_runs ?? [];
      return existing.filter(
        (check) =>
          check.name === "architecture-required" &&
          `${check.app?.id ?? ""}` === controllerAppId,
      );
    },
    postCheck: async (body) =>
      controllerGithubJson(`repos/${targetRepository}/check-runs`, {
        body,
        method: "POST",
      }),
    replayDigest,
    status,
    summary,
  });
}

/** 创建受 guardian AbortSignal 与绝对 deadline 约束的单轮 Controller runtime。 */
function createControllerRuntime(options) {
  const deadlineAt = options.deadlineAt ?? Date.now() + defaultControllerCycleTimeoutMs;
  if (!Number.isFinite(deadlineAt) || deadlineAt <= Date.now()) {
    throw new Error("Controller cycle deadline 缺失或已耗尽。");
  }
  return {
    deadlineAt,
    monitorRefreshState: controllerMonitorRefreshState,
    signal: options.signal,
  };
}

/** 创建与正常 cycle signal 隔离的紧急撤销 runtime。 */
function createControllerRevocationRuntime(options) {
  const timeoutMs = options.revocationTimeoutMs ?? defaultControllerRevocationTimeoutMs;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0) {
    throw new TypeError("Controller revocation timeout 必须是正安全整数。");
  }
  return { deadlineAt: Date.now() + timeoutMs, signal: options.revocationSignal };
}

/** 返回当前单轮剩余预算；耗尽或 guardian 已取消时立即 fail closed。 */
function controllerRemainingMs(limitMs) {
  const runtime = controllerRuntimeStorage.getStore();
  if (runtime === undefined) {
    throw new Error("Controller runtime 未初始化。");
  }
  if (runtime.signal?.aborted) {
    throw runtime.signal.reason instanceof Error
      ? runtime.signal.reason
      : new Error("Controller cycle 已被 guardian 取消。");
  }
  const remainingMs = runtime.deadlineAt - Date.now();
  if (remainingMs <= 0) {
    throw new Error("Controller cycle deadline 已耗尽。");
  }
  return Math.max(1, Math.min(limitMs, remainingMs));
}

/** 将全部 GitHub 请求绑定到当前 cycle 的 signal 与剩余 deadline。 */
function controllerGithubJson(endpoint, options = {}) {
  const runtime = controllerRuntimeStorage.getStore();
  return githubJson(endpoint, {
    ...options,
    signal: runtime?.signal,
    timeoutMs: controllerRemainingMs(options.timeoutMs ?? 15_000),
  });
}

/** 将 artifact 下载绑定到当前 cycle 的 signal 与剩余 deadline。 */
function controllerDownloadArtifact(url) {
  const runtime = controllerRuntimeStorage.getStore();
  return downloadArtifact(url, undefined, {
    signal: runtime?.signal,
    timeoutMs: controllerRemainingMs(15_000),
  });
}

/** 将 gh/unzip 子进程绑定到当前 cycle 的剩余 deadline。 */
function controllerRunTool(executable, args) {
  return runTool(executable, args, {
    timeoutMs: controllerRemainingMs(30_000),
  });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  await runControllerCycle();
}

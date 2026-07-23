import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import {
  validateProviderGateJob,
  validateProviderWorkflowRun,
  validateVerifiedAttestations,
} from "../lib/attestation-policy.mjs";
import {
  evaluateControllerCandidate,
  selectFreshDriftMonitorRun,
} from "../lib/controller-policy.mjs";
import { downloadArtifact, githubJson, runTool } from "../lib/github-api.mjs";
import { validateTrustedRegistryApproval } from "../lib/registry.mjs";

const targetRepository = process.env.TARGET_REPOSITORY ?? "Rockyyy-S/code-graph";
const targetRepositoryId = process.env.TARGET_REPOSITORY_ID ?? "1303415307";
const controllerRepository = "Rockyyy-S/code-graph-gate-controller";
const producerWorkflowSha = "3a0b53163e91bf14d4a3d1e911292b267e1e968a";
const controllerAppId = process.env.CONTROLLER_APP_ID;
const controllerRepositoryToken = process.env.CONTROLLER_REPOSITORY_TOKEN;

if (!/^[1-9][0-9]*$/u.test(controllerAppId ?? "") || !controllerRepositoryToken) {
  throw new Error("Controller App identity 或 controller repository token 缺失。\n");
}

await assertFreshDriftMonitor();
const trustedRecord = JSON.parse(await readFile("trusted/registry.json", "utf8"));
const trustedApproval = JSON.parse(
  await readFile("trusted/registry-approval.json", "utf8"),
);
validateTrustedRegistryApproval({
  approval: trustedApproval,
  expectedProducerWorkflowSha: producerWorkflowSha,
  record: trustedRecord,
});
const pulls = await githubJson(`repos/${targetRepository}/pulls?state=open&per_page=100`);
for (const pull of pulls) {
  await processPullRequest(pull, trustedRecord);
}

/** 对单个 PR 只消费 provider API 返回的 run/artifact，并发布 App-owned umbrella check。 */
async function processPullRequest(pull, trustedRecord) {
  const headOid = pull.head.sha;
  const runs = await githubJson(
    `repos/${targetRepository}/actions/workflows/architecture-required.yml/runs?event=pull_request&head_sha=${headOid}&per_page=20`,
  );
  const run = runs.workflow_runs
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
  const artifacts = await githubJson(`repos/${targetRepository}/actions/runs/${run.id}/artifacts`);
  const expectedPrefix = `gate-evidence-${run.id}-${run.run_attempt}-${headOid}`;
  const matching = artifacts.artifacts.filter(
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
    const jobsResponse = await githubJson(
      `repos/${targetRepository}/actions/runs/${run.id}/attempts/${run.run_attempt}/jobs?per_page=100`,
    );
    const namedJobs = jobsResponse.jobs.filter(
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
    const summary = JSON.stringify({ providerEvidenceRecord, result });
    await publishCheck(
      headOid,
      "completed",
      result.conclusion,
      summary,
      result.casKey ?? null,
    );
  } catch (error) {
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
  const runs = await githubJson(
    `repos/${controllerRepository}/actions/workflows/drift-monitor.yml/runs?per_page=10`,
    { token: controllerRepositoryToken },
  );
  selectFreshDriftMonitorRun(runs.workflow_runs);
}

/** 使用 Controller GitHub App installation token 发布唯一 architecture-required check。 */
async function publishCheck(headOid, status, conclusion, summary, casKey) {
  const existing = await githubJson(`repos/${targetRepository}/commits/${headOid}/check-runs`);
  const appOwned = existing.check_runs.filter(
    (check) => check.name === "architecture-required" && `${check.app?.id ?? ""}` === controllerAppId,
  );
  const exactReplay = appOwned.find(
    (check) => casKey !== null && check.output?.summary?.includes(`\"casKey\":\"${casKey}\"`),
  );
  if (exactReplay !== undefined && exactReplay.status === status && exactReplay.conclusion === conclusion) {
    return;
  }
  await githubJson(`repos/${targetRepository}/check-runs`, {
    body: {
      ...(conclusion === null ? {} : { conclusion }),
      head_sha: headOid,
      name: "architecture-required",
      output: {
        summary: summary.slice(0, 60_000),
        title:
          conclusion === "success"
            ? "Architecture gates passed"
            : status === "in_progress"
              ? "Architecture gates pending"
              : "Architecture gates failed closed",
      },
      status,
    },
    method: "POST",
  });
}

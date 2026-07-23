import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { evaluateControllerCandidate } from "../lib/controller-policy.mjs";
import { downloadArtifact, githubJson, runTool } from "../lib/github-api.mjs";

const targetRepository = process.env.TARGET_REPOSITORY ?? "Rockyyy-S/code-graph";
const targetRepositoryId = process.env.TARGET_REPOSITORY_ID ?? "1303415307";
const controllerRepository = "Rockyyy-S/code-graph-gate-controller";
const producerWorkflowSha = "616633c1e594174e4964672f1d04e94718995940";
const controllerAppId = process.env.CONTROLLER_APP_ID;
const controllerRepositoryToken = process.env.CONTROLLER_REPOSITORY_TOKEN;

if (!/^[1-9][0-9]*$/u.test(controllerAppId ?? "") || !controllerRepositoryToken) {
  throw new Error("Controller App identity 或 controller repository token 缺失。\n");
}

await assertFreshDriftMonitor();
const trustedRecord = JSON.parse(await readFile("trusted/registry.json", "utf8"));
const pulls = await githubJson(`repos/${targetRepository}/pulls?state=open&per_page=100`);
for (const pull of pulls) {
  await processPullRequest(pull, trustedRecord);
}

/** 对单个 PR 只消费 provider API 返回的 run/artifact，并发布 App-owned umbrella check。 */
async function processPullRequest(pull, trustedRecord) {
  const headOid = pull.head.sha;
  const baseOid = pull.base.sha;
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
      "--signer-repo",
      controllerRepository,
      "--signer-workflow",
      `github.com/${controllerRepository}/.github/workflows/produce-gate-evidence.yml`,
      "--signer-digest",
      producerWorkflowSha,
      "--source-digest",
      headOid,
      "--deny-self-hosted-runners",
      "--format",
      "json",
    ]);
    const verifiedAttestations = JSON.parse(attestationOutput.toString("utf8"));
    if (!Array.isArray(verifiedAttestations) || verifiedAttestations.length === 0) {
      throw new Error("GitHub attestation verification 未返回验证结果。\n");
    }
    const artifact = JSON.parse(await readFile(evidencePath, "utf8"));
    const registry = await readCandidateRegistry(headOid);
    const currentPull = await githubJson(`repos/${targetRepository}/pulls/${pull.number}`);
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
    const attestationRecord = {
      artifactDigest: createHash("sha256").update(await readFile(evidencePath)).digest("hex"),
      eventName: run.event,
      gateEvidenceDigests: result.gateEvidenceDigests ?? [],
      githubActionsAppId: 15368,
      headOid,
      jobId: "gate-evidence",
      jobWorkflowRef: `${controllerRepository}/.github/workflows/produce-gate-evidence.yml@${producerWorkflowSha}`,
      oidcIssuer: "https://token.actions.githubusercontent.com",
      oidcVerificationResult: "verified-by-gh-attestation",
      providerRepositoryId: targetRepositoryId,
      providerRunId: `${run.id}`,
      runAttempt: run.run_attempt,
      schemaVersion: 1,
      workflowRef: `${targetRepository}/.github/workflows/architecture-required.yml@${headOid}`,
    };
    const summary = JSON.stringify({ attestationRecord, result });
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
    `repos/${controllerRepository}/actions/workflows/drift-monitor.yml/runs?event=schedule&per_page=10`,
    { token: controllerRepositoryToken },
  );
  const latest = runs.workflow_runs
    .filter((run) => run.status === "completed")
    .sort((left, right) => new Date(right.updated_at) - new Date(left.updated_at))[0];
  if (
    latest === undefined ||
    latest.conclusion !== "success" ||
    Date.now() - Date.parse(latest.updated_at) > 15 * 60 * 1000
  ) {
    throw new Error("独立 drift monitor 缺失、失败或已过期，Controller fail closed。\n");
  }
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

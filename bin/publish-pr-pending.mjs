import { fileURLToPath } from "node:url";
import { sha256CanonicalJson } from "../lib/canonical-json.mjs";
import { publishControllerCheck } from "../lib/controller-check-publisher.mjs";
import { githubJson } from "../lib/github-api.mjs";

const allowedActions = new Set([
  "edited",
  "opened",
  "ready_for_review",
  "reopened",
  "synchronize",
]);

/** 为受信任 pull_request_target 事件发布 Controller App 所有的 pending check。 */
export async function publishPullLifecyclePending(input, dependencies = {}) {
  validateInput(input);
  const request = dependencies.request ?? githubJson;
  const pull = await request(`repos/${input.repository}/pulls/${input.pullNumber}`);
  assertCurrentPull(input, pull);
  const casKey = [
    input.providerRepositoryId,
    input.headOid,
    "pr-lifecycle",
    input.pullNumber,
    input.lifecycleAction,
  ].join(":");
  const replayDigest = sha256CanonicalJson({
    headOid: input.headOid,
    lifecycleAction: input.lifecycleAction,
    providerRepositoryId: input.providerRepositoryId,
    pullNumber: input.pullNumber,
    schemaVersion: 1,
  });
  const summary = JSON.stringify({
    casKey,
    lifecycleAction: input.lifecycleAction,
    pullNumber: input.pullNumber,
    reason: "PR 生命周期变化，等待可信 child evidence 与 Controller 重新聚合。",
    replayDigest,
    status: "pending",
  });
  const action = await publishControllerCheck({
    assertFreshMonitor: async () => undefined,
    casKey,
    conclusion: null,
    headOid: input.headOid,
    loadChecks: async () => {
      const response = await request(
        `repos/${input.repository}/commits/${input.headOid}/check-runs?filter=all&check_name=architecture-required&per_page=100`,
      );
      return (response.check_runs ?? []).filter(
        (check) =>
          check.name === "architecture-required" &&
          `${check.app?.id ?? ""}` === input.controllerAppId,
      );
    },
    postCheck: async (body) =>
      request(`repos/${input.repository}/check-runs`, { body, method: "POST" }),
    replayDigest,
    status: "in_progress",
    summary,
  });
  assertCurrentPull(input, await request(`repos/${input.repository}/pulls/${input.pullNumber}`));
  return { action, casKey, replayDigest };
}

/** 校验 workflow 传入的仓库、App、PR 与不可变 SHA。 */
function validateInput(input) {
  if (
    input.repository !== "Rockyyy-S/code-graph" ||
    input.providerRepositoryId !== "1303415307" ||
    !/^[1-9][0-9]*$/u.test(input.controllerAppId ?? "") ||
    !/^[a-f0-9]{40}$/u.test(input.controllerWorkflowSha ?? "") ||
    !/^[a-f0-9]{40}$/u.test(input.headOid ?? "") ||
    !Number.isSafeInteger(input.pullNumber) ||
    input.pullNumber <= 0 ||
    !allowedActions.has(input.lifecycleAction)
  ) {
    throw new Error("PR 生命周期 pending 输入未与可信 Controller 合同闭合。");
  }
}

/** Provider API 返回的开放 PR 必须仍绑定事件中的精确 head 与仓库 ID。 */
function assertCurrentPull(input, pull) {
  if (
    pull?.state !== "open" ||
    pull?.number !== input.pullNumber ||
    pull?.head?.sha !== input.headOid ||
    `${pull?.base?.repo?.id ?? ""}` !== input.providerRepositoryId
  ) {
    throw new Error("PR 生命周期 pending 发布前后快照已变化，Controller fail closed。");
  }
}

/** 从 workflow 环境读取封闭输入。 */
function inputFromEnvironment(environment) {
  return {
    controllerAppId: environment.CONTROLLER_APP_ID,
    controllerWorkflowSha: environment.CONTROLLER_WORKFLOW_SHA,
    headOid: environment.HEAD_OID,
    lifecycleAction: environment.LIFECYCLE_ACTION,
    providerRepositoryId: environment.PROVIDER_REPOSITORY_ID,
    pullNumber: Number(environment.PULL_NUMBER),
    repository: environment.TARGET_REPOSITORY,
  };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const result = await publishPullLifecyclePending(inputFromEnvironment(process.env));
  process.stdout.write(`${JSON.stringify(result)}\n`);
}

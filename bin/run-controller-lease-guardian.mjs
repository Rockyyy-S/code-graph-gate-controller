import { fileURLToPath } from "node:url";
import { setTimeout as delay } from "node:timers/promises";
import {
  ControllerRevisionDriftError,
  runControllerCycle,
} from "./run-controller.mjs";
import { githubJson } from "../lib/github-api.mjs";

const defaultPollIntervalMs = 60_000;
const defaultRuntimeMs = 50 * 60 * 1000;
const defaultCycleTimeoutMs = 4 * 60 * 1000;
const defaultRevocationWaitMs = 60_000;
const defaultHandoffLeadMs = 60_000;
const controllerRepository = "Rockyyy-S/code-graph-gate-controller";
const controllerWorkflowPath = "controller.yml";
const controllerDefaultBranch = "main";

/** 标记真实已启动 cycle 到达自身 deadline，正常 lease 边界不得构造此错误。 */
class ControllerCycleDeadlineError extends Error {
  constructor() {
    super("Controller lease guardian cycle deadline 已耗尽。");
    this.name = "ControllerCycleDeadlineError";
  }
}

/** 标记上一轮 cycle 在撤销预算后仍未结算，禁止 guardian 启动重叠轮次。 */
class ControllerCycleUnsettledError extends AggregateError {
  constructor(deadlineError) {
    super(
      [deadlineError],
      "Controller cycle 已超时，且紧急撤销未在独立预算内完成；本轮仍未结算。",
    );
    this.name = "ControllerCycleUnsettledError";
  }
}

/**
 * 在单个受信任运行中持续重验 monitor lease，并在过期后一轮内撤销旧 success。
 *
 * 该 guardian 不绑定具体云平台或 webhook；外层运行器只需保证进程在声明的运行窗口内存活。
 */
export async function runControllerLeaseGuardian(options = {}) {
  const pollIntervalMs = options.pollIntervalMs ?? defaultPollIntervalMs;
  const runtimeMs = options.runtimeMs ?? defaultRuntimeMs;
  const cycleTimeoutMs = options.cycleTimeoutMs ?? defaultCycleTimeoutMs;
  const revocationWaitMs = options.revocationWaitMs ?? defaultRevocationWaitMs;
  const handoffLeadMs = options.handoffLeadMs ?? defaultHandoffLeadMs;
  if (
    !Number.isSafeInteger(pollIntervalMs) ||
    pollIntervalMs <= 0 ||
    !Number.isSafeInteger(runtimeMs) ||
    runtimeMs < pollIntervalMs ||
    !Number.isSafeInteger(cycleTimeoutMs) ||
    cycleTimeoutMs <= 0 ||
    !Number.isSafeInteger(revocationWaitMs) ||
    revocationWaitMs <= 0 ||
    !Number.isSafeInteger(handoffLeadMs) ||
    handoffLeadMs <= 0 ||
    !Number.isSafeInteger(cycleTimeoutMs + revocationWaitMs + handoffLeadMs)
  ) {
    throw new TypeError("Controller lease guardian 的 interval/runtime/cycle/revocation/handoff 必须是正安全整数。");
  }
  const leaseDeadlineAt = Date.now() + runtimeMs;
  const requiredCycleReservationMs = cycleTimeoutMs + revocationWaitMs + handoffLeadMs;
  let lastError = null;
  while (Date.now() < leaseDeadlineAt) {
    const remainingLeaseMs = leaseDeadlineAt - Date.now();
    if (remainingLeaseMs <= requiredCycleReservationMs) {
      break;
    }
    try {
      await runCycleWithDeadline({
        cycleTimeoutMs,
        revocationWaitMs,
        runCycle: options.runCycle ?? runControllerCycle,
      });
      lastError = null;
    } catch (error) {
      lastError = error instanceof Error ? error : new Error("Controller lease guardian 未知错误。");
      console.error(
        lastError.message,
      );
      if (lastError instanceof ControllerCycleUnsettledError) {
        throw lastError;
      }
      if (lastError instanceof ControllerCycleDeadlineError) {
        throw lastError;
      }
      if (containsControllerRevisionDrift(lastError)) {
        throw lastError;
      }
    }
    const delayBudgetMs = leaseDeadlineAt - Date.now() - requiredCycleReservationMs;
    if (delayBudgetMs <= 0) {
      break;
    }
    await (options.delay ?? delay)(Math.min(pollIntervalMs, delayBudgetMs));
  }
  let handoffError = null;
  try {
    await (options.dispatchSuccessor ?? dispatchSuccessorController)();
  } catch (error) {
    handoffError = error instanceof Error
      ? error
      : new Error("Controller successor handoff 未知错误。");
    console.error(`Controller successor handoff 失败：${handoffError.message}`);
  }
  if (handoffError !== null) {
    throw new AggregateError(
      lastError === null ? [handoffError] : [lastError, handoffError],
      "Controller lease guardian successor handoff 失败。",
    );
  }
  if (lastError !== null) {
    throw lastError;
  }
}

/** 使用当前仓库 GITHUB_TOKEN 至多一次排队同一 concurrency group 的 successor。 */
export async function dispatchSuccessorController(options = {}) {
  const token = options.token ?? process.env.CONTROLLER_REPOSITORY_TOKEN;
  if (typeof token !== "string" || token.length === 0) {
    throw new Error("Controller successor handoff 缺少当前仓库 actions:write token。");
  }
  await (options.request ?? githubJson)(
    `repos/${controllerRepository}/actions/workflows/${controllerWorkflowPath}/dispatches`,
    {
      body: { ref: controllerDefaultBranch },
      method: "POST",
      timeoutMs: 5_000,
      token,
    },
  );
}

/** 默认分支已推进时立即结束旧 guardian，让排队的新可信 revision 接管。 */
function containsControllerRevisionDrift(error, seen = new Set()) {
  if (!(error instanceof Error) || seen.has(error)) {
    return false;
  }
  seen.add(error);
  if (error instanceof ControllerRevisionDriftError) {
    return true;
  }
  if (error.cause instanceof Error && containsControllerRevisionDrift(error.cause, seen)) {
    return true;
  }
  return error instanceof AggregateError &&
    error.errors.some((nested) => containsControllerRevisionDrift(nested, seen));
}

/** 以可传播 AbortSignal 的绝对 deadline 约束单轮 Controller cycle。 */
async function runCycleWithDeadline({
  cycleTimeoutMs,
  revocationWaitMs,
  runCycle,
}) {
  const abortController = new AbortController();
  let timeout;
  const cyclePromise = Promise.resolve().then(() =>
    runCycle({
      deadlineAt: Date.now() + cycleTimeoutMs,
      signal: abortController.signal,
    }),
  );
  const timeoutPromise = new Promise((resolve) => {
    timeout = setTimeout(() => {
      const error = new ControllerCycleDeadlineError();
      abortController.abort(error);
      resolve({ error, timedOut: true });
    }, cycleTimeoutMs);
  });
  try {
    const first = await Promise.race([
      cyclePromise.then(
        (value) => ({ done: true, value }),
        (error) => ({ done: true, error }),
      ),
      timeoutPromise,
    ]);
    if (first.done === true) {
      if (first.error !== undefined) {
        throw first.error;
      }
      return first.value;
    }

    // abort 只结束正常 cycle；继续等待同一 cycle 用独立预算完成 fail-closed 撤销。
    let revocationTimeout;
    const revocationTimeoutPromise = new Promise((resolve) => {
      revocationTimeout = setTimeout(() => resolve({ done: false }), revocationWaitMs);
    });
    let afterAbort;
    try {
      afterAbort = await Promise.race([
        cyclePromise.then(
          (value) => ({ done: true, value }),
          (error) => ({ done: true, error }),
        ),
        revocationTimeoutPromise,
      ]);
    } finally {
      clearTimeout(revocationTimeout);
    }
    if (afterAbort.done !== true) {
      throw new ControllerCycleUnsettledError(first.error);
    }
    // deadline 一旦触发，本轮绝不能因被取消任务随后正常 resolve 而恢复为成功。
    throw first.error;
  } finally {
    clearTimeout(timeout);
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  await runControllerLeaseGuardian();
}

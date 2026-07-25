import { fileURLToPath } from "node:url";
import { setTimeout as delay } from "node:timers/promises";
import { runControllerCycle } from "./run-controller.mjs";

const defaultPollIntervalMs = 60_000;
const defaultRuntimeMs = 50 * 60 * 1000;
const defaultCycleTimeoutMs = 4 * 60 * 1000;
const defaultRevocationWaitMs = 60_000;

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
  if (
    !Number.isSafeInteger(pollIntervalMs) ||
    pollIntervalMs <= 0 ||
    !Number.isSafeInteger(runtimeMs) ||
    runtimeMs < pollIntervalMs ||
    !Number.isSafeInteger(cycleTimeoutMs) ||
    cycleTimeoutMs <= 0 ||
    !Number.isSafeInteger(revocationWaitMs) ||
    revocationWaitMs <= 0
  ) {
    throw new TypeError("Controller lease guardian 的 interval/runtime/cycle timeout 必须是正安全整数。");
  }
  const deadlineAt = Date.now() + runtimeMs;
  let lastError = null;
  do {
    try {
      await runCycleWithDeadline({
        cycleTimeoutMs,
        deadlineAt,
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
    }
    const remainingMs = deadlineAt - Date.now();
    if (remainingMs <= 0) {
      break;
    }
    await (options.delay ?? delay)(Math.min(pollIntervalMs, remainingMs));
  } while (Date.now() < deadlineAt);
  if (lastError !== null) {
    throw lastError;
  }
}

/** 以可传播 AbortSignal 的绝对 deadline 约束单轮 Controller cycle。 */
async function runCycleWithDeadline({
  cycleTimeoutMs,
  deadlineAt,
  revocationWaitMs,
  runCycle,
}) {
  const remainingMs = Math.min(cycleTimeoutMs, deadlineAt - Date.now());
  if (remainingMs <= 0) {
    throw new Error("Controller lease guardian cycle deadline 已耗尽。");
  }
  const abortController = new AbortController();
  let timeout;
  const cyclePromise = Promise.resolve().then(() =>
    runCycle({
      deadlineAt: Date.now() + remainingMs,
      signal: abortController.signal,
    }),
  );
  const timeoutPromise = new Promise((resolve) => {
    timeout = setTimeout(() => {
      const error = new Error("Controller lease guardian cycle deadline 已耗尽。");
      abortController.abort(error);
      resolve({ error, timedOut: true });
    }, remainingMs);
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

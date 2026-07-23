import { spawn } from "node:child_process";

/** 以 shell:false 执行进程，并用绝对 deadline、升级终止和有界输出保证收敛。 */
export function runProcessWithDeadline(options) {
  const timeoutMs = options.timeoutMs;
  const killGraceMs = options.killGraceMs ?? 2_000;
  const outputLimitBytes = options.outputLimitBytes ?? 16 * 1024 * 1024;
  if (
    !Number.isSafeInteger(timeoutMs) || timeoutMs <= 0 ||
    !Number.isSafeInteger(killGraceMs) || killGraceMs <= 0 ||
    !Number.isSafeInteger(outputLimitBytes) || outputLimitBytes <= 0
  ) {
    throw new TypeError("进程 deadline、终止宽限和输出上限必须是正安全整数。");
  }
  return new Promise((resolve) => {
    const stdout = createBoundedCollector(outputLimitBytes);
    const stderr = createBoundedCollector(outputLimitBytes);
    let child;
    let deadline;
    let forceKill;
    let settleFallback;
    let settled = false;
    let timedOut = false;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      clearTimeout(deadline);
      clearTimeout(forceKill);
      clearTimeout(settleFallback);
      resolve({
        ...result,
        stderr: stderr.bytes(),
        stderrBytes: stderr.totalBytes(),
        stderrTruncated: stderr.truncated(),
        stdout: stdout.bytes(),
        stdoutBytes: stdout.totalBytes(),
        stdoutTruncated: stdout.truncated(),
      });
    };
    try {
      child = spawn(options.executable, options.args, {
        cwd: options.cwd,
        env: options.env ?? process.env,
        shell: false,
        stdio: ["ignore", "pipe", "pipe"],
      });
    } catch (error) {
      finish(spawnError(error));
      return;
    }
    child.stdout.on("data", (chunk) => stdout.append(chunk));
    child.stderr.on("data", (chunk) => stderr.append(chunk));
    child.once("error", (error) => finish(timedOut ? timeoutResult() : spawnError(error)));
    child.once("close", (code, signal) => {
      if (timedOut) {
        finish(timeoutResult());
        return;
      }
      finish({
        status: code === 0 ? "pass" : "fail",
        termination:
          signal === null
            ? { code: code ?? 1, kind: "exit" }
            : { kind: "signal", signalName: signal },
      });
    });
    deadline = setTimeout(() => {
      timedOut = true;
      child.kill("SIGTERM");
      forceKill = setTimeout(() => {
        child.kill("SIGKILL");
        settleFallback = setTimeout(() => finish(timeoutResult()), killGraceMs);
      }, killGraceMs);
    }, timeoutMs);
  });
}

/** 创建只保留固定上限、同时记录原始总字节数的 collector。 */
function createBoundedCollector(limitBytes) {
  const chunks = [];
  let capturedBytes = 0;
  let totalBytes = 0;
  return {
    append(chunk) {
      const buffer = Buffer.from(chunk);
      totalBytes += buffer.length;
      const remaining = limitBytes - capturedBytes;
      if (remaining > 0) {
        const captured = buffer.subarray(0, remaining);
        chunks.push(captured);
        capturedBytes += captured.length;
      }
    },
    bytes: () => Buffer.concat(chunks),
    totalBytes: () => totalBytes,
    truncated: () => totalBytes > capturedBytes,
  };
}

/** 将启动异常收敛为稳定 invalid。 */
function spawnError(error) {
  return {
    status: "invalid",
    termination: {
      kind: "spawn-error",
      stableCode:
        typeof error === "object" && error !== null && typeof error.code === "string"
          ? error.code
          : "UNKNOWN",
    },
  };
}

/** deadline 到期统一使用稳定 ETIMEDOUT。 */
function timeoutResult() {
  return {
    status: "invalid",
    termination: { kind: "spawn-error", stableCode: "ETIMEDOUT" },
  };
}

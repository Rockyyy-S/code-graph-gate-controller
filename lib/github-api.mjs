import { runProcessWithDeadline } from "./run-process-with-deadline.mjs";

const defaultRequestTimeoutMs = 15_000;
const defaultToolTimeoutMs = 30_000;

/** 使用 installation token 调用 GitHub REST API，并返回 JSON。 */
export async function githubJson(endpoint, options = {}) {
  const token = options.token ?? process.env.GH_TOKEN;
  if (!token) {
    throw new Error("缺少 GitHub installation token。\n");
  }
  const response = await fetch(`https://api.github.com/${endpoint.replace(/^\//u, "")}`, {
    headers: {
      Accept: "application/vnd.github+json",
      Authorization: `Bearer ${token}`,
      "User-Agent": "code-graph-gate-controller",
      "X-GitHub-Api-Version": "2022-11-28",
    },
    method: options.method ?? "GET",
    signal: createDeadlineSignal(options.timeoutMs, options.signal),
    ...(options.body === undefined ? {} : { body: JSON.stringify(options.body) }),
  });
  if (!response.ok) {
    throw new Error(`GitHub API ${response.status} ${endpoint} 调用失败。`);
  }
  return response.status === 204 ? null : response.json();
}

/** 使用 installation token 调用 GitHub GraphQL API，并拒绝部分成功或 schema 错误。 */
export async function githubGraphql(query, variables = {}, token = process.env.GH_TOKEN) {
  if (!token) {
    throw new Error("缺少 GitHub installation token。\n");
  }
  const response = await fetch("https://api.github.com/graphql", {
    body: JSON.stringify({ query, variables }),
    headers: {
      Accept: "application/vnd.github+json",
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
      "User-Agent": "code-graph-gate-controller",
      "X-GitHub-Api-Version": "2022-11-28",
    },
    method: "POST",
    signal: createDeadlineSignal(),
  });
  if (!response.ok) {
    throw new Error(`GitHub GraphQL API 调用失败：HTTP ${response.status}。`);
  }
  const body = await response.json();
  if (Array.isArray(body.errors) && body.errors.length > 0) {
    throw new Error("GitHub GraphQL API 返回不可接受的部分错误。\n");
  }
  return body.data;
}

/** 下载 provider artifact 原始 zip 字节。 */
export async function downloadArtifact(url, token = process.env.GH_TOKEN, options = {}) {
  const response = await fetch(url, {
    headers: {
      Accept: "application/vnd.github+json",
      Authorization: `Bearer ${token}`,
      "User-Agent": "code-graph-gate-controller",
    },
    signal: createDeadlineSignal(options.timeoutMs, options.signal),
  });
  if (!response.ok) {
    throw new Error(`artifact 下载失败：HTTP ${response.status}。`);
  }
  return Buffer.from(await response.arrayBuffer());
}

/** 以 shell:false 执行 gh/unzip 等固定工具，并返回 stdout。 */
export async function runTool(executable, args, options = {}) {
  const result = await runProcessWithDeadline({
    args,
    cwd: options.cwd,
    env: options.env ?? process.env,
    executable,
    killGraceMs: options.killGraceMs ?? 2_000,
    outputLimitBytes: options.outputLimitBytes ?? 16 * 1024 * 1024,
    timeoutMs: options.timeoutMs ?? defaultToolTimeoutMs,
  });
  if (result.status !== "pass") {
    const reason = result.termination.kind === "spawn-error"
      ? result.termination.stableCode
      : result.termination.kind === "signal"
        ? result.termination.signalName
        : `exit-${result.termination.code}`;
    throw new Error(
      `${executable} 失败（${reason}）：${result.stderr.toString("utf8").trim()}`,
    );
  }
  return result.stdout;
}

/** 为 REST/GraphQL/artifact 请求创建内部绝对 deadline。 */
function createDeadlineSignal(timeoutMs = defaultRequestTimeoutMs, externalSignal) {
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0) {
    throw new TypeError("GitHub 请求 timeout 必须是正安全整数。");
  }
  const deadlineSignal = AbortSignal.timeout(timeoutMs);
  return externalSignal === undefined
    ? deadlineSignal
    : AbortSignal.any([externalSignal, deadlineSignal]);
}

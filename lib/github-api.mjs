import { spawn } from "node:child_process";

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
    ...(options.body === undefined ? {} : { body: JSON.stringify(options.body) }),
  });
  if (!response.ok) {
    throw new Error(`GitHub API ${response.status} ${endpoint} 调用失败。`);
  }
  return response.status === 204 ? null : response.json();
}

/** 下载 provider artifact 原始 zip 字节。 */
export async function downloadArtifact(url, token = process.env.GH_TOKEN) {
  const response = await fetch(url, {
    headers: {
      Accept: "application/vnd.github+json",
      Authorization: `Bearer ${token}`,
      "User-Agent": "code-graph-gate-controller",
    },
  });
  if (!response.ok) {
    throw new Error(`artifact 下载失败：HTTP ${response.status}。`);
  }
  return Buffer.from(await response.arrayBuffer());
}

/** 以 shell:false 执行 gh/unzip 等固定工具，并返回 stdout。 */
export function runTool(executable, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(executable, args, {
      cwd: options.cwd,
      env: options.env ?? process.env,
      shell: false,
      stdio: ["ignore", "pipe", "pipe"],
    });
    const stdout = [];
    const stderr = [];
    child.stdout.on("data", (chunk) => stdout.push(chunk));
    child.stderr.on("data", (chunk) => stderr.push(chunk));
    child.once("error", reject);
    child.once("close", (code, signal) => {
      if (code !== 0) {
        reject(
          new Error(
            `${executable} 失败（code=${code ?? "null"}, signal=${signal ?? "none"}）：${Buffer.concat(stderr).toString("utf8").trim()}`,
          ),
        );
        return;
      }
      resolve(Buffer.concat(stdout));
    });
  });
}

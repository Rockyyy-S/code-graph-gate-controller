import assert from "node:assert/strict";
import test from "node:test";
import { githubJson, runTool } from "../lib/github-api.mjs";

test("GitHub REST 请求使用内部 deadline", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (_url, options) => new Promise((_resolve, reject) => {
    options.signal.addEventListener("abort", () => reject(options.signal.reason), { once: true });
  });
  try {
    await assert.rejects(
      githubJson("repos/example/repository", { timeoutMs: 10, token: "test-token" }),
      /timeout|aborted|operation/iu,
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("固定工具在 deadline 后终止并返回稳定超时错误", async () => {
  await assert.rejects(
    runTool(process.execPath, ["-e", "setTimeout(() => {}, 10000)"], {
      killGraceMs: 10,
      timeoutMs: 20,
    }),
    /ETIMEDOUT/u,
  );
});

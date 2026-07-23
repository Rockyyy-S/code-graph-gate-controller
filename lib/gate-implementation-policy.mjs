import { readFile } from "node:fs/promises";
import path from "node:path";
import { sha256CanonicalJson, sha256Hex } from "./canonical-json.mjs";

/**
 * 影响 Gate 真实执行语义的受保护文件集合。
 *
 * 该列表由不可变 GateHarness 持有，候选提交不能自行缩小；产品源码和测试内容不在此
 * 信任根中，避免普通功能 PR 都要求外部批准。
 */
export const GATE_IMPLEMENTATION_PATHS_V1 = Object.freeze([
  "apps/cli/tsconfig.build.json",
  "apps/cli/tsconfig.json",
  "apps/extension/esbuild.mjs",
  "apps/extension/tsconfig.json",
  "apps/graph-service/tsconfig.build.json",
  "apps/graph-service/tsconfig.json",
  "apps/webview/tsconfig.build.json",
  "apps/webview/tsconfig.json",
  "eslint.config.mjs",
  "packages/adapters/analyzer-typescript/tsconfig.build.json",
  "packages/adapters/analyzer-typescript/tsconfig.json",
  "packages/adapters/git-local/tsconfig.build.json",
  "packages/adapters/git-local/tsconfig.json",
  "packages/adapters/store-sqlite/tsconfig.build.json",
  "packages/adapters/store-sqlite/tsconfig.json",
  "packages/application/tsconfig.build.json",
  "packages/application/tsconfig.json",
  "packages/contracts/tsconfig.build.json",
  "packages/contracts/tsconfig.json",
  "packages/domain/tsconfig.build.json",
  "packages/domain/tsconfig.json",
  "packages/service-client/tsconfig.build.json",
  "packages/service-client/tsconfig.json",
  "scripts/architecture/check-dependency-boundaries.mjs",
  "scripts/contracts/validate-repository-contract.mjs",
  "scripts/planning/check-planning-traceability.mjs",
  "scripts/quality/check-test-markers.mjs",
  "scripts/quality/relative-eslint-formatter.mjs",
  "scripts/quality/run-workspace-script.mjs",
  "scripts/security/check-basic-security.mjs",
  "scripts/workspace/discover-workspaces.mjs",
  "tsconfig.base.json",
  "tsconfig.quality.json",
  "vitest.config.ts",
  "vitest.contract.config.ts",
]);

/** 计算候选 gate 实现投影及其 JCS SHA-256，供外部可信记录批准。 */
export async function computeGateImplementationDigest(
  candidateRoot,
  registry,
  protectedPaths = GATE_IMPLEMENTATION_PATHS_V1,
) {
  const manifest = JSON.parse(
    await readFile(path.join(candidateRoot, "package.json"), "utf8"),
  );
  const rootScripts = {};
  const directNodeEntries = [];
  for (const { gateDefinition } of registry.gates) {
    const [executable, ...args] = gateDefinition.command;
    if (executable === "pnpm" && args.length === 1) {
      const implementation = manifest.scripts?.[args[0]];
      if (typeof implementation !== "string" || implementation.trim().length === 0) {
        throw new Error(`gate ${gateDefinition.gateId} 的根脚本缺失或为空。`);
      }
      rootScripts[args[0]] = implementation;
      continue;
    }
    if (executable === "node" && args.length === 1 && isSafeRelativePath(args[0])) {
      directNodeEntries.push(args[0]);
      continue;
    }
    throw new Error(`gate ${gateDefinition.gateId} 使用未批准的实现入口形状。`);
  }
  const files = [];
  const allProtectedPaths = [...new Set([...protectedPaths, ...directNodeEntries])].sort();
  for (const relativePath of allProtectedPaths) {
    if (!isSafeRelativePath(relativePath)) {
      throw new Error(`受保护 gate 实现路径 '${relativePath}' 非法。`);
    }
    const bytes = await readFile(path.join(candidateRoot, ...relativePath.split("/")));
    files.push({ contentDigest: sha256Hex(bytes), path: relativePath });
  }
  const projection = {
    files,
    rootScripts: Object.fromEntries(Object.entries(rootScripts).sort(([left], [right]) => left.localeCompare(right))),
    schemaVersion: 1,
    toolchain: {
      devDependencies: manifest.devDependencies ?? {},
      engines: manifest.engines ?? {},
      packageManager: manifest.packageManager ?? null,
    },
  };
  return {
    digest: sha256CanonicalJson(projection),
    projection,
  };
}

/** 受保护入口只能指向候选仓库内规范 POSIX 相对文件。 */
function isSafeRelativePath(value) {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    !value.includes("\0") &&
    !value.includes("\\") &&
    !path.posix.isAbsolute(value) &&
    value.split("/").every((segment) => segment !== "" && segment !== "." && segment !== "..")
  );
}

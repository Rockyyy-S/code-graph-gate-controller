import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { computeGateImplementationDigest } from "../lib/gate-implementation-policy.mjs";

/** 创建只含一个 pnpm gate 和一个受保护 checker 的候选 fixture。 */
async function createFixture() {
  const root = await mkdtemp(path.join(tmpdir(), "gate-implementation-policy-"));
  await mkdir(path.join(root, "scripts"), { recursive: true });
  await writeFile(
    path.join(root, "package.json"),
    JSON.stringify({
      devDependencies: { vitest: "4.1.10" },
      engines: { node: "24.18.0" },
      packageManager: "pnpm@11.12.0",
      scripts: { unit: "node scripts/check.mjs" },
    }),
  );
  await writeFile(path.join(root, "scripts", "check.mjs"), "process.exitCode = 0;\n");
  const registry = {
    gates: [
      {
        gateDefinition: {
          command: ["pnpm", "unit"],
          gateId: "unit",
        },
      },
    ],
  };
  return { registry, root };
}

test("gate 实现摘要绑定根脚本文本和受保护 checker 内容", async (context) => {
  const fixture = await createFixture();
  context.after(() => rm(fixture.root, { force: true, recursive: true }));
  const baseline = await computeGateImplementationDigest(
    fixture.root,
    fixture.registry,
    {
      protectedDirectories: [],
      optionalProtectedPaths: [],
      protectedPaths: ["scripts/check.mjs"],
    },
  );

  await writeFile(
    path.join(fixture.root, "package.json"),
    JSON.stringify({ scripts: { unit: "node scripts/other.mjs" } }),
  );
  const scriptDrift = await computeGateImplementationDigest(
    fixture.root,
    fixture.registry,
    {
      protectedDirectories: [],
      optionalProtectedPaths: [],
      protectedPaths: ["scripts/check.mjs"],
    },
  );
  assert.notEqual(scriptDrift.digest, baseline.digest);

  await writeFile(
    path.join(fixture.root, "package.json"),
    JSON.stringify({ scripts: { unit: "node scripts/check.mjs" } }),
  );
  await writeFile(path.join(fixture.root, "scripts", "check.mjs"), "process.exitCode = 1;\n");
  const checkerDrift = await computeGateImplementationDigest(
    fixture.root,
    fixture.registry,
    {
      protectedDirectories: [],
      optionalProtectedPaths: [],
      protectedPaths: ["scripts/check.mjs"],
    },
  );
  assert.notEqual(checkerDrift.digest, baseline.digest);

  await writeFile(
    path.join(fixture.root, "package.json"),
    JSON.stringify({
      devDependencies: { vitest: "4.1.11" },
      engines: { node: "24.18.0" },
      packageManager: "pnpm@11.12.0",
      scripts: { unit: "node scripts/check.mjs" },
    }),
  );
  const toolchainDrift = await computeGateImplementationDigest(
    fixture.root,
    fixture.registry,
    {
      protectedDirectories: [],
      optionalProtectedPaths: [],
      protectedPaths: ["scripts/check.mjs"],
    },
  );
  assert.notEqual(toolchainDrift.digest, baseline.digest);
});

test("受保护目录整体绑定传递 helper", async (context) => {
  const fixture = await createFixture();
  context.after(() => rm(fixture.root, { force: true, recursive: true }));
  await writeFile(path.join(fixture.root, "scripts", "helper.mjs"), "export const ok = true;\n");
  const baseline = await computeGateImplementationDigest(fixture.root, fixture.registry, {
    protectedDirectories: ["scripts"],
    optionalProtectedPaths: [],
    protectedPaths: [],
  });

  await writeFile(path.join(fixture.root, "scripts", "helper.mjs"), "export const ok = false;\n");
  const helperDrift = await computeGateImplementationDigest(fixture.root, fixture.registry, {
    protectedDirectories: ["scripts"],
    optionalProtectedPaths: [],
    protectedPaths: [],
  });
  assert.notEqual(helperDrift.digest, baseline.digest);
});

test("被忽略的本地生成目录不污染 clean checkout 实现摘要", async (context) => {
  const fixture = await createFixture();
  context.after(() => rm(fixture.root, { force: true, recursive: true }));
  await mkdir(path.join(fixture.root, "scripts", "generated"), { recursive: true });
  await writeFile(
    path.join(fixture.root, "scripts", "generated", "cache.json"),
    "first\n",
  );
  const policy = {
    excludedDirectories: ["scripts/generated"],
    protectedDirectories: ["scripts"],
    optionalProtectedPaths: [],
    protectedPaths: [],
  };
  const baseline = await computeGateImplementationDigest(
    fixture.root,
    fixture.registry,
    policy,
  );

  await writeFile(
    path.join(fixture.root, "scripts", "generated", "cache.json"),
    "second\n",
  );
  const changedCache = await computeGateImplementationDigest(
    fixture.root,
    fixture.registry,
    policy,
  );

  assert.equal(changedCache.digest, baseline.digest);
  assert.equal(
    changedCache.projection.files.some(({ path: relativePath }) =>
      relativePath.startsWith("scripts/generated/"),
    ),
    false,
  );
});

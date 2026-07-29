import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { deflateRawSync } from "node:zlib";
import { installTrustedPnpmWin32 } from "../bin/install-trusted-pnpm-win32.mjs";

/** 构造可精确控制 central directory 的最小 synthetic ZIP。 */
function createZip(entries) {
  const localParts = [];
  const centralParts = [];
  let localOffset = 0;
  for (const entry of entries) {
    const name = Buffer.from(entry.name, "utf8");
    const content = Buffer.from(entry.content ?? "", "utf8");
    const method = entry.method ?? (entry.name.endsWith("/") ? 0 : 8);
    const compressed = method === 8 ? deflateRawSync(content) : content;
    const crc32 = calculateCrc32(content);
    const flags = entry.flags ?? 0x0800;
    const uncompressedSize = entry.declaredUncompressedSize ?? content.length;
    const externalAttributes =
      entry.externalAttributes ?? (entry.name.endsWith("/") ? 0x41ed0010 : 0x81a40000);
    const local = Buffer.alloc(30 + name.length);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(flags, 6);
    local.writeUInt16LE(method, 8);
    local.writeUInt32LE(crc32, 14);
    local.writeUInt32LE(compressed.length, 18);
    local.writeUInt32LE(uncompressedSize, 22);
    local.writeUInt16LE(name.length, 26);
    name.copy(local, 30);
    localParts.push(local, compressed);

    const central = Buffer.alloc(46 + name.length);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE((3 << 8) | 20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(flags, 8);
    central.writeUInt16LE(method, 10);
    central.writeUInt32LE(crc32, 16);
    central.writeUInt32LE(compressed.length, 20);
    central.writeUInt32LE(uncompressedSize, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt32LE(externalAttributes >>> 0, 38);
    central.writeUInt32LE(localOffset, 42);
    name.copy(central, 46);
    centralParts.push(central);
    localOffset += local.length + compressed.length;
  }
  const centralDirectory = Buffer.concat(centralParts);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(centralDirectory.length, 12);
  eocd.writeUInt32LE(localOffset, 16);
  return Buffer.concat([...localParts, centralDirectory, eocd]);
}

/** 计算 synthetic ZIP central directory 使用的 CRC32。 */
function calculateCrc32(bytes) {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) {
      crc = (crc & 1) !== 0 ? 0xedb88320 ^ (crc >>> 1) : crc >>> 1;
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

/** 构造跨越多个读取块且不可被高度压缩的确定性字节序列。 */
function createDeterministicBytes(length) {
  const bytes = Buffer.allocUnsafe(length);
  let state = 0x12345678;
  for (let index = 0; index < bytes.length; index += 1) {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    bytes[index] = state >>> 24;
  }
  return bytes;
}

/** 写入 ZIP 并生成与 synthetic pnpm.exe 内容闭合的安装参数。 */
async function createFixture(root, entries) {
  const archivePath = path.join(root, "pnpm.zip");
  const trustedRoot = path.join(root, "trusted-pnpm");
  const archive = createZip(entries);
  await writeFile(archivePath, archive);
  const pnpm = entries.find((entry) => entry.name.toLowerCase() === "pnpm.exe");
  const pnpmBytes = Buffer.from(pnpm?.content ?? "", "utf8");
  return {
    archivePath,
    expectedArchiveSha256: createHash("sha256").update(archive).digest("hex"),
    expectedEntrySha256: createHash("sha256").update(pnpmBytes).digest("hex"),
    expectedEntrySize: pnpmBytes.length,
    trustedRoot,
  };
}

test("完整扫描并只安装根 pnpm.exe 与固定 dist 运行时", async (context) => {
  const root = await mkdtemp(path.join(tmpdir(), "pnpm-safe-zip-"));
  context.after(() => rm(root, { force: true, recursive: true }));
  const fixture = await createFixture(root, [
    { content: "trusted-pnpm", name: "pnpm.exe" },
    { name: "dist/" },
    { content: "not-installed", name: "dist/pnpm.mjs" },
  ]);

  const result = await installTrustedPnpmWin32(fixture);

  assert.equal(result.archiveEntryCount, 3);
  assert.equal(await readFile(result.pnpmPath, "utf8"), "trusted-pnpm");
  assert.deepEqual(await readdir(fixture.trustedRoot), ["dist", "pnpm.exe"]);
  assert.equal(
    await readFile(path.join(fixture.trustedRoot, "dist", "pnpm.mjs"), "utf8"),
    "not-installed",
  );
});

test("大量条目复用唯一归档句柄时不累积 FileHandle stream listener", async (context) => {
  const root = await mkdtemp(path.join(tmpdir(), "pnpm-many-entries-"));
  context.after(() => rm(root, { force: true, recursive: true }));
  const runtimeEntries = Array.from({ length: 24 }, (_, index) => ({
    content: `runtime-${index}`,
    name: `dist/runtime-${index}.mjs`,
  }));
  const fixture = await createFixture(root, [
    { content: "trusted-pnpm", name: "pnpm.exe" },
    { name: "dist/" },
    ...runtimeEntries,
  ]);

  const result = await installTrustedPnpmWin32(fixture);

  assert.equal(result.archiveEntryCount, 26);
  assert.equal(await readFile(result.pnpmPath, "utf8"), "trusted-pnpm");
  assert.equal((await readdir(path.join(fixture.trustedRoot, "dist"))).length, 24);
});

test("单条目跨越多个压缩读取块时保持字节完整", async (context) => {
  const root = await mkdtemp(path.join(tmpdir(), "pnpm-large-entry-"));
  context.after(() => rm(root, { force: true, recursive: true }));
  const runtime = createDeterministicBytes(2_500_000);
  const fixture = await createFixture(root, [
    { content: "trusted-pnpm", name: "pnpm.exe" },
    { content: runtime, name: "dist/pnpm.mjs" },
  ]);

  await installTrustedPnpmWin32(fixture);

  assert.deepEqual(await readFile(path.join(fixture.trustedRoot, "dist", "pnpm.mjs")), runtime);
});

test("拒绝 traversal、绝对/drive/UNC、反斜线与 ADS 路径", async (context) => {
  const root = await mkdtemp(path.join(tmpdir(), "pnpm-unsafe-path-"));
  context.after(() => rm(root, { force: true, recursive: true }));
  for (const [index, name] of [
    "../pnpm.exe",
    "/pnpm.exe",
    "C:/pnpm.exe",
    "//server/share/pnpm.exe",
    "dir\\pnpm.exe",
    "pnpm.exe:payload",
  ].entries()) {
    const caseRoot = path.join(root, String(index));
    await mkdir(caseRoot);
    const fixture = await createFixture(caseRoot, [
      { content: "trusted", name: "pnpm.exe" },
      { content: "evil", name },
    ]);
    await assert.rejects(installTrustedPnpmWin32(fixture), /路径|ADS|穿越/u);
  }
});

test("拒绝重复目标与大小写折叠冲突", async (context) => {
  const root = await mkdtemp(path.join(tmpdir(), "pnpm-collision-"));
  context.after(() => rm(root, { force: true, recursive: true }));
  const duplicateRoot = path.join(root, "duplicate");
  const collisionRoot = path.join(root, "collision");
  await mkdir(duplicateRoot);
  await mkdir(collisionRoot);
  await assert.rejects(
    installTrustedPnpmWin32(
      await createFixture(duplicateRoot, [
        { content: "one", name: "pnpm.exe" },
        { content: "two", name: "pnpm.exe" },
      ]),
    ),
    /重复/u,
  );
  await assert.rejects(
    installTrustedPnpmWin32(
      await createFixture(collisionRoot, [
        { content: "one", name: "pnpm.exe" },
        { content: "two", name: "PNPM.EXE" },
      ]),
    ),
    /大小写折叠冲突/u,
  );
});

test("拒绝 symlink/reparse、异常算法、加密标志与 zip bomb", async (context) => {
  const root = await mkdtemp(path.join(tmpdir(), "pnpm-entry-policy-"));
  context.after(() => rm(root, { force: true, recursive: true }));
  const cases = [
    {
      entry: { content: "target", externalAttributes: 0xa1ff0000, name: "link" },
      pattern: /symlink|特殊文件/u,
    },
    {
      entry: { content: "data", method: 12, name: "unsupported" },
      pattern: /压缩算法/u,
    },
    {
      entry: { content: "data", flags: 0x0801, name: "encrypted" },
      pattern: /加密|flags/u,
    },
    {
      entry: {
        content: "tiny",
        declaredUncompressedSize: 20_000_000,
        name: "bomb",
      },
      pattern: /zip-bomb|压缩比|大小/u,
    },
  ];
  for (const [index, item] of cases.entries()) {
    const caseRoot = path.join(root, String(index));
    await mkdir(caseRoot);
    const fixture = await createFixture(caseRoot, [
      { content: "trusted", name: "pnpm.exe" },
      item.entry,
    ]);
    await assert.rejects(installTrustedPnpmWin32(fixture), item.pattern);
  }
});

test("拒绝归档摘要错误与已存在的多余安装文件", async (context) => {
  const root = await mkdtemp(path.join(tmpdir(), "pnpm-final-state-"));
  context.after(() => rm(root, { force: true, recursive: true }));
  const digestRoot = path.join(root, "digest");
  const existingRoot = path.join(root, "existing");
  await mkdir(digestRoot);
  await mkdir(existingRoot);
  const digestFixture = await createFixture(digestRoot, [
    { content: "trusted", name: "pnpm.exe" },
  ]);
  digestFixture.expectedArchiveSha256 = "0".repeat(64);
  await assert.rejects(installTrustedPnpmWin32(digestFixture), /摘要不匹配/u);

  const existingFixture = await createFixture(existingRoot, [
    { content: "trusted", name: "pnpm.exe" },
  ]);
  await mkdir(existingFixture.trustedRoot);
  await writeFile(path.join(existingFixture.trustedRoot, "extra.txt"), "untrusted");
  await assert.rejects(installTrustedPnpmWin32(existingFixture), /必须不存在/u);
});

test("拒绝固定 pnpm.exe/dist 白名单之外的多余归档安装文件", async (context) => {
  const root = await mkdtemp(path.join(tmpdir(), "pnpm-extra-entry-"));
  context.after(() => rm(root, { force: true, recursive: true }));
  const fixture = await createFixture(root, [
    { content: "trusted", name: "pnpm.exe" },
    { content: "runtime", name: "dist/pnpm.mjs" },
    { content: "extra", name: "extra.txt" },
  ]);

  await assert.rejects(installTrustedPnpmWin32(fixture), /多余安装文件/u);
});

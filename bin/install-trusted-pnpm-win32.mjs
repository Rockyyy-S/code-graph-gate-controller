import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { createWriteStream } from "node:fs";
import {
  lstat,
  mkdir,
  mkdtemp,
  open,
  readdir,
  realpath,
  rename,
  rm,
} from "node:fs/promises";
import path from "node:path";
import { pipeline } from "node:stream/promises";
import { Readable, Transform } from "node:stream";
import { setTimeout as delay } from "node:timers/promises";
import { promisify } from "node:util";
import { pathToFileURL } from "node:url";
import { createInflateRaw } from "node:zlib";

const execFileAsync = promisify(execFile);
const END_OF_CENTRAL_DIRECTORY_SIGNATURE = 0x06054b50;
const CENTRAL_DIRECTORY_SIGNATURE = 0x02014b50;
const LOCAL_FILE_HEADER_SIGNATURE = 0x04034b50;
const ZIP64_EXTRA_FIELD_ID = 0x0001;
const UTF8_FLAG = 0x0800;
const DATA_DESCRIPTOR_FLAG = 0x0008;
const ALLOWED_GENERAL_PURPOSE_FLAGS = 0x080e;
const UNIX_FILE_TYPE_MASK = 0xf000;
const UNIX_REGULAR_FILE = 0x8000;
const UNIX_DIRECTORY = 0x4000;
const WINDOWS_REPARSE_POINT_ATTRIBUTE = 0x0400;
const MAX_END_RECORD_SEARCH_BYTES = 22 + 0xffff;
const MAX_ARCHIVE_BYTES = 128 * 1024 * 1024;
const MAX_CENTRAL_DIRECTORY_BYTES = 8 * 1024 * 1024;
const MAX_ENTRY_COUNT = 4096;
const MAX_ENTRY_NAME_BYTES = 1024;
const MAX_ENTRY_UNCOMPRESSED_BYTES = 128 * 1024 * 1024;
const MAX_TOTAL_UNCOMPRESSED_BYTES = 160 * 1024 * 1024;
const MAX_COMPRESSION_RATIO = 100;

export const PNPM_WIN32_VERSION = "11.12.0";
export const PNPM_WIN32_ARCHIVE_SHA256 =
  "7ac25ba81b8a9f213a307ae89198ba7e636e6c74fa0d775d554ba46e0187358b";
export const PNPM_WIN32_ENTRY_SIZE = 98_099_528;
export const PNPM_WIN32_ENTRY_SHA256 =
  "0a8b6b9d6f391bb83e868a3f951eec74fb8f745c176fce523a9359f40b20fb7b";

/**
 * 扫描完整 ZIP central directory，并把已验证的根 pnpm.exe 与必要 dist 运行时流式安装到可信目录。
 *
 * @param {{
 *   archivePath: string;
 *   trustedRoot: string;
 *   expectedArchiveSha256?: string;
 *   expectedEntrySha256?: string;
 *   expectedEntrySize?: number;
 * }} options 安装参数。
 * @returns {Promise<{archiveEntryCount: number; pnpmPath: string}>} 安装结果。
 */
export async function installTrustedPnpmWin32(options) {
  const expectedArchiveSha256 =
    options.expectedArchiveSha256 ?? PNPM_WIN32_ARCHIVE_SHA256;
  const expectedEntrySha256 =
    options.expectedEntrySha256 ?? PNPM_WIN32_ENTRY_SHA256;
  const expectedEntrySize = options.expectedEntrySize ?? PNPM_WIN32_ENTRY_SIZE;
  assertAbsolutePath(options.archivePath, "archivePath");
  assertAbsolutePath(options.trustedRoot, "trustedRoot");
  assertDigest(expectedArchiveSha256, "archive SHA-256");
  assertDigest(expectedEntrySha256, "pnpm.exe SHA-256");
  if (!Number.isSafeInteger(expectedEntrySize) || expectedEntrySize <= 0) {
    throw new Error("pnpm.exe 期望大小必须是正安全整数。");
  }

  await assertPathAbsent(options.trustedRoot, "可信 pnpm 目录");
  const archivePathMetadata = await lstat(options.archivePath);
  if (!archivePathMetadata.isFile() || archivePathMetadata.isSymbolicLink()) {
    throw new Error("pnpm Win32 ZIP 路径必须直接指向普通文件，禁止 symlink/reparse。");
  }
  const resolvedArchivePath = await realpath(options.archivePath);
  if (
    path.resolve(resolvedArchivePath).toLowerCase() !==
    path.resolve(options.archivePath).toLowerCase()
  ) {
    throw new Error("pnpm Win32 ZIP 路径经 realpath 后发生重定向。");
  }
  const archiveHandle = await open(options.archivePath, "r");
  let stagingRoot;
  try {
    const archiveMetadata = await archiveHandle.stat();
    if (
      !archiveMetadata.isFile() ||
      archiveMetadata.isSymbolicLink() ||
      archiveMetadata.size <= 0 ||
      archiveMetadata.size > MAX_ARCHIVE_BYTES
    ) {
      throw new Error("pnpm Win32 ZIP 必须是大小受限的普通文件。");
    }
    const archiveDigest = await sha256FileHandle(archiveHandle, archiveMetadata.size);
    if (archiveDigest !== expectedArchiveSha256) {
      throw new Error("pnpm Win32 ZIP 摘要不匹配。");
    }

    const archive = await inspectZipArchive(archiveHandle, archiveMetadata.size);
    const pnpmEntries = archive.entries.filter(
      (entry) => !entry.isDirectory && entry.caseFoldedPath === "pnpm.exe",
    );
    if (pnpmEntries.length !== 1) {
      throw new Error("根 pnpm.exe 忽略大小写后必须恰好存在一个。");
    }
    const pnpmEntry = pnpmEntries[0];
    if (pnpmEntry.uncompressedSize !== expectedEntrySize) {
      throw new Error("pnpm.exe 未压缩大小不匹配。");
    }

    assertArchiveInstallLayout(archive.entries);
    stagingRoot = await mkdtemp(
      path.join(path.dirname(options.trustedRoot), ".trusted-pnpm-staging-"),
    );
    for (const entry of archive.entries
      .filter((candidate) => !candidate.isDirectory)
      .sort((left, right) => left.targetPath.localeCompare(right.targetPath))) {
      const outputPath = path.join(stagingRoot, ...entry.targetPath.split("/"));
      await mkdir(path.dirname(outputPath), { recursive: true });
      const integrity = await extractEntry({ archiveHandle, entry, outputPath });
      if (integrity.size !== entry.uncompressedSize || integrity.crc32 !== entry.crc32) {
        throw new Error(`ZIP 条目流式提取后的大小或 CRC 不匹配：${entry.name}`);
      }
      if (
        entry === pnpmEntry &&
        (integrity.size !== expectedEntrySize || integrity.sha256 !== expectedEntrySha256)
      ) {
        throw new Error("pnpm.exe 流式提取后的固定大小或 SHA-256 不匹配。");
      }
    }
    const stagingPnpmPath = path.join(stagingRoot, "pnpm.exe");
    await assertOrdinaryFile(stagingPnpmPath, expectedEntrySize);
    await assertTrustedTreeMatchesArchive(stagingRoot, archive.entries);

    const secondArchiveDigest = await sha256FileHandle(
      archiveHandle,
      archiveMetadata.size,
    );
    if (secondArchiveDigest !== expectedArchiveSha256) {
      throw new Error("pnpm Win32 ZIP 在验证期间发生漂移。");
    }

    await renameWithRetry(stagingRoot, options.trustedRoot);
    stagingRoot = undefined;
    await assertOrdinaryDirectory(options.trustedRoot);
    await assertTrustedTreeMatchesArchive(options.trustedRoot, archive.entries);
    const trustedPnpmPath = path.join(options.trustedRoot, "pnpm.exe");
    await assertOrdinaryFile(trustedPnpmPath, expectedEntrySize);
    return {
      archiveEntryCount: archive.entries.length,
      pnpmPath: trustedPnpmPath,
    };
  } finally {
    await archiveHandle.close();
    if (stagingRoot !== undefined) {
      await rm(stagingRoot, { force: true, recursive: true });
    }
  }
}

/** 官方固定归档只允许根 pnpm.exe 与其相邻 dist 运行时，禁止额外安装顶层。 */
function assertArchiveInstallLayout(entries) {
  for (const entry of entries) {
    if (
      entry.caseFoldedPath !== "pnpm.exe" &&
      entry.caseFoldedPath !== "dist" &&
      !entry.caseFoldedPath.startsWith("dist/")
    ) {
      throw new Error(`ZIP 包含白名单外的多余安装文件：${entry.name}`);
    }
  }
}

/**
 * Windows 安全软件可能在新 PE 文件关闭后的极短窗口持有扫描句柄；仅对 EPERM 做有界重试。
 *
 * @param {string} source 唯一 staging 目录。
 * @param {string} destination 尚不存在的最终目录。
 */
async function renameWithRetry(source, destination) {
  for (let attempt = 0; attempt < 60; attempt += 1) {
    try {
      await rename(source, destination);
      return;
    } catch (error) {
      if (
        !(
          error &&
          typeof error === "object" &&
          (error.code === "EPERM" || error.code === "EACCES")
        ) ||
        attempt === 59
      ) {
        throw error;
      }
      await delay(500);
    }
  }
}

/**
 * 以绝对路径运行已安装的 pnpm.exe，并要求版本输出精确等于固定版本。
 *
 * @param {string} pnpmPath pnpm.exe 绝对路径。
 * @returns {Promise<void>}
 */
export async function verifyTrustedPnpmVersion(pnpmPath) {
  assertAbsolutePath(pnpmPath, "pnpmPath");
  await assertOrdinaryFile(pnpmPath, PNPM_WIN32_ENTRY_SIZE);
  const { stdout, stderr } = await execFileAsync(pnpmPath, ["--version"], {
    encoding: "utf8",
    env: {
      SystemRoot: process.env.SystemRoot ?? "C:\\Windows",
      TEMP: process.env.TEMP ?? path.dirname(pnpmPath),
      TMP: process.env.TMP ?? path.dirname(pnpmPath),
    },
    timeout: 30_000,
    windowsHide: true,
  });
  if (stdout.trim() !== PNPM_WIN32_VERSION || stderr.trim() !== "") {
    throw new Error("可信 pnpm.exe 版本输出无效。");
  }
}

/**
 * 解析 ZIP 目录并验证每个条目的路径、属性、压缩边界与 local header。
 *
 * @param {import("node:fs/promises").FileHandle} archiveHandle ZIP 文件句柄。
 * @param {number} archiveSize ZIP 文件大小。
 */
async function inspectZipArchive(archiveHandle, archiveSize) {
  const eocd = await readEndOfCentralDirectory(archiveHandle, archiveSize);
  if (
    eocd.entryCount <= 0 ||
    eocd.entryCount > MAX_ENTRY_COUNT ||
    eocd.centralDirectorySize <= 0 ||
    eocd.centralDirectorySize > MAX_CENTRAL_DIRECTORY_BYTES ||
    eocd.centralDirectoryOffset + eocd.centralDirectorySize !== eocd.offset
  ) {
    throw new Error("ZIP central directory 数量或边界无效。");
  }
  const centralDirectory = await readExactly(
    archiveHandle,
    eocd.centralDirectorySize,
    eocd.centralDirectoryOffset,
  );
  const entries = [];
  const exactTargets = new Set();
  const foldedTargets = new Map();
  let cursor = 0;
  let totalUncompressedSize = 0;
  for (let index = 0; index < eocd.entryCount; index += 1) {
    if (
      cursor + 46 > centralDirectory.length ||
      centralDirectory.readUInt32LE(cursor) !== CENTRAL_DIRECTORY_SIGNATURE
    ) {
      throw new Error("ZIP central directory 条目截断或签名无效。");
    }
    const versionMadeBy = centralDirectory.readUInt16LE(cursor + 4);
    const flags = centralDirectory.readUInt16LE(cursor + 8);
    const method = centralDirectory.readUInt16LE(cursor + 10);
    const crc32 = centralDirectory.readUInt32LE(cursor + 16);
    const compressedSize = centralDirectory.readUInt32LE(cursor + 20);
    const uncompressedSize = centralDirectory.readUInt32LE(cursor + 24);
    const nameLength = centralDirectory.readUInt16LE(cursor + 28);
    const extraLength = centralDirectory.readUInt16LE(cursor + 30);
    const commentLength = centralDirectory.readUInt16LE(cursor + 32);
    const diskStart = centralDirectory.readUInt16LE(cursor + 34);
    const externalAttributes = centralDirectory.readUInt32LE(cursor + 38);
    const localHeaderOffset = centralDirectory.readUInt32LE(cursor + 42);
    const end = cursor + 46 + nameLength + extraLength + commentLength;
    if (nameLength <= 0 || nameLength > MAX_ENTRY_NAME_BYTES || end > centralDirectory.length) {
      throw new Error("ZIP 条目名称或可变字段边界无效。");
    }
    if (
      diskStart !== 0 ||
      compressedSize === 0xffffffff ||
      uncompressedSize === 0xffffffff ||
      localHeaderOffset === 0xffffffff
    ) {
      throw new Error("ZIP64 或多磁盘条目不受信任。");
    }
    assertSafeFlagsAndMethod(flags, method);
    const nameBytes = centralDirectory.subarray(cursor + 46, cursor + 46 + nameLength);
    const extraBytes = centralDirectory.subarray(
      cursor + 46 + nameLength,
      cursor + 46 + nameLength + extraLength,
    );
    assertExtraFields(extraBytes);
    const name = decodeEntryName(nameBytes, flags);
    const pathIdentity = validateEntryPath(name);
    if (exactTargets.has(pathIdentity.targetPath)) {
      throw new Error(`ZIP 条目目标重复：${pathIdentity.targetPath}`);
    }
    const priorFolded = foldedTargets.get(pathIdentity.caseFoldedPath);
    if (priorFolded !== undefined) {
      throw new Error(
        `ZIP 条目存在大小写折叠冲突：${priorFolded} / ${pathIdentity.targetPath}`,
      );
    }
    exactTargets.add(pathIdentity.targetPath);
    foldedTargets.set(pathIdentity.caseFoldedPath, pathIdentity.targetPath);
    assertEntryType({
      externalAttributes,
      isDirectory: pathIdentity.isDirectory,
      versionMadeBy,
    });
    assertCompressionBounds({ compressedSize, isDirectory: pathIdentity.isDirectory, uncompressedSize });
    totalUncompressedSize += uncompressedSize;
    if (totalUncompressedSize > MAX_TOTAL_UNCOMPRESSED_BYTES) {
      throw new Error("ZIP 总未压缩大小超过安全上限。");
    }
    entries.push({
      ...pathIdentity,
      compressedSize,
      crc32,
      flags,
      localHeaderOffset,
      method,
      name,
      uncompressedSize,
    });
    cursor = end;
  }
  if (cursor !== centralDirectory.length) {
    throw new Error("ZIP central directory 未被完整且唯一地解析。");
  }
  for (const entry of entries) {
    Object.assign(
      entry,
      await validateLocalHeader(archiveHandle, entry, eocd.centralDirectoryOffset),
    );
  }
  const byLocalOffset = [...entries].sort(
    (left, right) => left.localHeaderOffset - right.localHeaderOffset,
  );
  for (let index = 1; index < byLocalOffset.length; index += 1) {
    if (byLocalOffset[index - 1].dataEnd > byLocalOffset[index].localHeaderOffset) {
      throw new Error("ZIP local entry 数据范围发生重叠。");
    }
  }
  return { entries };
}

/** 读取并验证单磁盘、非 ZIP64 的 EOCD。 */
async function readEndOfCentralDirectory(archiveHandle, archiveSize) {
  const searchLength = Math.min(archiveSize, MAX_END_RECORD_SEARCH_BYTES);
  const searchOffset = archiveSize - searchLength;
  const tail = await readExactly(archiveHandle, searchLength, searchOffset);
  for (let offset = tail.length - 22; offset >= 0; offset -= 1) {
    if (tail.readUInt32LE(offset) !== END_OF_CENTRAL_DIRECTORY_SIGNATURE) {
      continue;
    }
    const commentLength = tail.readUInt16LE(offset + 20);
    if (offset + 22 + commentLength !== tail.length) {
      continue;
    }
    const diskNumber = tail.readUInt16LE(offset + 4);
    const centralDiskNumber = tail.readUInt16LE(offset + 6);
    const diskEntryCount = tail.readUInt16LE(offset + 8);
    const entryCount = tail.readUInt16LE(offset + 10);
    if (
      diskNumber !== 0 ||
      centralDiskNumber !== 0 ||
      diskEntryCount !== entryCount ||
      entryCount === 0xffff
    ) {
      throw new Error("ZIP EOCD 使用多磁盘或 ZIP64 表示。");
    }
    return {
      centralDirectoryOffset: tail.readUInt32LE(offset + 16),
      centralDirectorySize: tail.readUInt32LE(offset + 12),
      entryCount,
      offset: searchOffset + offset,
    };
  }
  throw new Error("ZIP 缺失唯一有效的 EOCD。");
}

/** 验证 central entry 对应 local header 与数据范围。 */
async function validateLocalHeader(archiveHandle, entry, centralDirectoryOffset) {
  const header = await readExactly(archiveHandle, 30, entry.localHeaderOffset);
  if (header.readUInt32LE(0) !== LOCAL_FILE_HEADER_SIGNATURE) {
    throw new Error(`ZIP local header 签名无效：${entry.name}`);
  }
  const localFlags = header.readUInt16LE(6);
  const localMethod = header.readUInt16LE(8);
  const localCrc32 = header.readUInt32LE(14);
  const localCompressedSize = header.readUInt32LE(18);
  const localUncompressedSize = header.readUInt32LE(22);
  const localNameLength = header.readUInt16LE(26);
  const localExtraLength = header.readUInt16LE(28);
  if (localFlags !== entry.flags || localMethod !== entry.method) {
    throw new Error(`ZIP local/central flags 或算法不一致：${entry.name}`);
  }
  const variable = await readExactly(
    archiveHandle,
    localNameLength + localExtraLength,
    entry.localHeaderOffset + 30,
  );
  const localName = decodeEntryName(variable.subarray(0, localNameLength), localFlags);
  assertExtraFields(variable.subarray(localNameLength));
  if (localName !== entry.name) {
    throw new Error(`ZIP local/central 名称不一致：${entry.name}`);
  }
  const usesDescriptor = (localFlags & DATA_DESCRIPTOR_FLAG) !== 0;
  if (
    (!usesDescriptor &&
      (localCrc32 !== entry.crc32 ||
        localCompressedSize !== entry.compressedSize ||
        localUncompressedSize !== entry.uncompressedSize)) ||
    (usesDescriptor &&
      ((localCrc32 !== 0 && localCrc32 !== entry.crc32) ||
        (localCompressedSize !== 0 && localCompressedSize !== entry.compressedSize) ||
        (localUncompressedSize !== 0 && localUncompressedSize !== entry.uncompressedSize)))
  ) {
    throw new Error(`ZIP local/central 摘要或大小不一致：${entry.name}`);
  }
  const dataOffset = entry.localHeaderOffset + 30 + localNameLength + localExtraLength;
  const dataEnd = dataOffset + entry.compressedSize;
  if (
    dataOffset < 0 ||
    dataEnd < dataOffset ||
    dataEnd > centralDirectoryOffset ||
    !Number.isSafeInteger(dataEnd)
  ) {
    throw new Error(`ZIP entry 数据边界越界：${entry.name}`);
  }
  return { dataEnd, dataOffset };
}

/** 只允许未加密的 stored/deflate 条目及其必要标志。 */
function assertSafeFlagsAndMethod(flags, method) {
  if ((flags & ~ALLOWED_GENERAL_PURPOSE_FLAGS) !== 0 || (flags & 0x2041) !== 0) {
    throw new Error("ZIP 加密或异常 general purpose flags 不受信任。");
  }
  if (method !== 0 && method !== 8) {
    throw new Error("ZIP 使用异常压缩算法。");
  }
  if (method === 0 && (flags & 0x0006) !== 0) {
    throw new Error("stored ZIP 条目携带无效压缩选项。");
  }
}

/** 拒绝 ZIP64 与截断的 extra field。 */
function assertExtraFields(extraBytes) {
  let offset = 0;
  while (offset < extraBytes.length) {
    if (offset + 4 > extraBytes.length) {
      throw new Error("ZIP extra field 截断。");
    }
    const identifier = extraBytes.readUInt16LE(offset);
    const size = extraBytes.readUInt16LE(offset + 2);
    offset += 4;
    if (offset + size > extraBytes.length) {
      throw new Error("ZIP extra field 数据越界。");
    }
    if (identifier === ZIP64_EXTRA_FIELD_ID) {
      throw new Error("ZIP64 extra field 不受信任。");
    }
    offset += size;
  }
}

/** 按 UTF-8 标志或安全 ASCII 解码条目名称。 */
function decodeEntryName(bytes, flags) {
  if ((flags & UTF8_FLAG) === 0 && bytes.some((byte) => byte > 0x7f)) {
    throw new Error("未声明 UTF-8 的非 ASCII ZIP 名称不受信任。");
  }
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new Error("ZIP 条目名称不是严格 UTF-8。");
  }
}

/** 验证条目不会映射到绝对路径、ADS、穿越或 Windows 模糊目标。 */
function validateEntryPath(name) {
  if (
    name.includes("\\") ||
    name.includes(":") ||
    name.startsWith("/") ||
    /^[A-Za-z]:/u.test(name) ||
    /[\u0000-\u001f\u007f-\u009f]/u.test(name)
  ) {
    throw new Error(`ZIP 条目路径包含绝对、UNC、drive、ADS、反斜线或控制字符：${name}`);
  }
  const isDirectory = name.endsWith("/");
  const targetPath = isDirectory ? name.slice(0, -1) : name;
  const segments = targetPath.split("/");
  if (
    targetPath.length === 0 ||
    segments.some(
      (segment) =>
        segment === "" ||
        segment === "." ||
        segment === ".." ||
        /[ .]$/u.test(segment) ||
        /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?$/iu.test(segment),
    )
  ) {
    throw new Error(`ZIP 条目路径包含空、点、穿越或 Windows 保留段：${name}`);
  }
  return {
    caseFoldedPath: targetPath.normalize("NFC").toLowerCase(),
    isDirectory,
    targetPath,
  };
}

/** 拒绝 symlink、reparse、特殊文件及文件/目录属性冲突。 */
function assertEntryType({ externalAttributes, isDirectory, versionMadeBy }) {
  const madeByPlatform = versionMadeBy >>> 8;
  const unixMode = externalAttributes >>> 16;
  const unixType = unixMode & UNIX_FILE_TYPE_MASK;
  const windowsAttributes = externalAttributes & 0xffff;
  if ((windowsAttributes & WINDOWS_REPARSE_POINT_ATTRIBUTE) !== 0) {
    throw new Error("ZIP 条目带 Windows reparse 属性。");
  }
  if (madeByPlatform === 3 && unixType !== 0) {
    const expectedType = isDirectory ? UNIX_DIRECTORY : UNIX_REGULAR_FILE;
    if (unixType !== expectedType) {
      throw new Error("ZIP 条目是 symlink 或其他特殊文件类型。");
    }
  }
  if (isDirectory !== ((windowsAttributes & 0x10) !== 0) && madeByPlatform === 0) {
    throw new Error("ZIP Windows 文件/目录属性与名称冲突。");
  }
}

/** 应用单条目、总量与压缩比 zip-bomb 上限。 */
function assertCompressionBounds({ compressedSize, isDirectory, uncompressedSize }) {
  if (
    uncompressedSize > MAX_ENTRY_UNCOMPRESSED_BYTES ||
    compressedSize > MAX_ARCHIVE_BYTES ||
    (isDirectory && (compressedSize !== 0 || uncompressedSize !== 0)) ||
    (!isDirectory && uncompressedSize > 0 && compressedSize === 0) ||
    (uncompressedSize > 0 && uncompressedSize / compressedSize > MAX_COMPRESSION_RATIO)
  ) {
    throw new Error("ZIP 条目大小、压缩比或 zip-bomb 边界无效。");
  }
}

/** 把已批准条目流式写入独占普通文件并同步计算摘要。 */
async function extractEntry({ archiveHandle, entry, outputPath }) {
  const source = Readable.from(readFileHandleRange(archiveHandle, entry));
  const integrity = new IntegrityTransform(entry.uncompressedSize);
  const output = createWriteStream(outputPath, { flags: "wx", mode: 0o700 });
  if (entry.method === 8) {
    await pipeline(source, createInflateRaw(), integrity, output);
  } else {
    await pipeline(source, integrity, output);
  }
  return integrity.result();
}

/**
 * 从共享归档句柄按固定范围读取，避免为大量条目在同一 FileHandle 上累积 stream close listener。
 *
 * @param {import("node:fs/promises").FileHandle} archiveHandle 已验证归档句柄。
 * @param {{dataOffset: number; dataEnd: number; name: string}} entry 条目数据边界。
 * @returns {AsyncGenerator<Buffer>} 有界压缩数据块。
 */
async function* readFileHandleRange(archiveHandle, entry) {
  let position = entry.dataOffset;
  while (position < entry.dataEnd) {
    const length = Math.min(1024 * 1024, entry.dataEnd - position);
    const buffer = Buffer.allocUnsafe(length);
    const { bytesRead } = await archiveHandle.read(buffer, 0, length, position);
    if (bytesRead !== length) {
      throw new Error(`ZIP 条目压缩数据在流式读取时截断：${entry.name}`);
    }
    yield buffer;
    position += bytesRead;
  }
}

/** 在流式写入时限制解压大小并计算 SHA-256 与 CRC32。 */
class IntegrityTransform extends Transform {
  /** @param {number} expectedSize central directory 声明的未压缩大小。 */
  constructor(expectedSize) {
    super();
    this.expectedSize = expectedSize;
    this.hash = createHash("sha256");
    this.size = 0;
    this.crc = 0xffffffff;
  }

  /** @param {Buffer} chunk @param {BufferEncoding} _encoding @param {(error?: Error | null) => void} callback */
  _transform(chunk, _encoding, callback) {
    this.size += chunk.length;
    if (this.size > this.expectedSize) {
      callback(new Error("ZIP 条目解压输出超过 central directory 声明大小。"));
      return;
    }
    this.hash.update(chunk);
    this.crc = updateCrc32(this.crc, chunk);
    callback(null, chunk);
  }

  /** 返回完整流的摘要结果。 */
  result() {
    if (this.size !== this.expectedSize) {
      throw new Error("ZIP 条目解压输出大小不足。");
    }
    return {
      crc32: (this.crc ^ 0xffffffff) >>> 0,
      sha256: this.hash.digest("hex"),
      size: this.size,
    };
  }
}

const CRC32_TABLE = createCrc32Table();

/** 创建固定 CRC32 查找表。 */
function createCrc32Table() {
  const table = new Uint32Array(256);
  for (let index = 0; index < table.length; index += 1) {
    let value = index;
    for (let bit = 0; bit < 8; bit += 1) {
      value = (value & 1) !== 0 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
    }
    table[index] = value >>> 0;
  }
  return table;
}

/** 更新流式 CRC32 状态。 */
function updateCrc32(crc, bytes) {
  let value = crc;
  for (const byte of bytes) {
    value = CRC32_TABLE[(value ^ byte) & 0xff] ^ (value >>> 8);
  }
  return value >>> 0;
}

/** 对已打开文件句柄执行完整流式 SHA-256。 */
async function sha256FileHandle(fileHandle, size) {
  const hash = createHash("sha256");
  const buffer = Buffer.allocUnsafe(1024 * 1024);
  let offset = 0;
  while (offset < size) {
    const length = Math.min(buffer.length, size - offset);
    const { bytesRead } = await fileHandle.read(buffer, 0, length, offset);
    if (bytesRead !== length) {
      throw new Error("pnpm Win32 ZIP 在摘要读取时截断。");
    }
    hash.update(buffer.subarray(0, bytesRead));
    offset += bytesRead;
  }
  return hash.digest("hex");
}

/** 从固定偏移读取精确字节数。 */
async function readExactly(fileHandle, length, position) {
  if (!Number.isSafeInteger(length) || !Number.isSafeInteger(position) || length < 0 || position < 0) {
    throw new Error("ZIP 读取边界不是安全整数。");
  }
  const buffer = Buffer.allocUnsafe(length);
  let offset = 0;
  while (offset < length) {
    const { bytesRead } = await fileHandle.read(
      buffer,
      offset,
      length - offset,
      position + offset,
    );
    if (bytesRead <= 0) {
      throw new Error("ZIP 固定范围读取截断。");
    }
    offset += bytesRead;
  }
  return buffer;
}

/** 验证目录是非 reparse 的真实目录。 */
async function assertOrdinaryDirectory(directoryPath) {
  const metadata = await lstat(directoryPath);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw new Error("可信 pnpm 目录不是普通目录或为 reparse/junction。");
  }
  const resolved = await realpath(directoryPath);
  if (path.resolve(resolved).toLowerCase() !== path.resolve(directoryPath).toLowerCase()) {
    throw new Error("可信 pnpm 目录经 realpath 后发生重定向。");
  }
}

/** 验证文件是指定大小且不经 symlink/reparse 重定向的普通文件。 */
async function assertOrdinaryFile(filePath, expectedSize) {
  const metadata = await lstat(filePath);
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size !== expectedSize) {
    throw new Error("pnpm.exe 不是指定大小的普通文件或为 reparse/symlink。");
  }
  const resolved = await realpath(filePath);
  if (path.resolve(resolved).toLowerCase() !== path.resolve(filePath).toLowerCase()) {
    throw new Error("pnpm.exe 经 realpath 后发生重定向。");
  }
}

/** 验证最终树与已扫描的白名单文件集合精确一致，且根 pnpm.exe 恰好一个。 */
async function assertTrustedTreeMatchesArchive(directoryPath, archiveEntries) {
  const expectedFiles = archiveEntries
    .filter((entry) => !entry.isDirectory)
    .map((entry) => entry.targetPath)
    .sort();
  const actualFiles = await collectTrustedTreeFiles(directoryPath);
  if (
    JSON.stringify(actualFiles) !== JSON.stringify(expectedFiles) ||
    actualFiles.filter((entry) => path.posix.basename(entry).toLowerCase() === "pnpm.exe")
      .length !== 1 ||
    actualFiles.find((entry) => entry.toLowerCase() === "pnpm.exe") !== "pnpm.exe"
  ) {
    throw new Error("可信 pnpm 安装树与已验证归档白名单不一致。");
  }
}

/** 递归枚举可信安装树，并拒绝 symlink、junction、reparse 或特殊条目。 */
async function collectTrustedTreeFiles(directoryPath, relativeDirectory = "") {
  const absoluteDirectory = relativeDirectory === ""
    ? directoryPath
    : path.join(directoryPath, ...relativeDirectory.split("/"));
  await assertOrdinaryDirectory(absoluteDirectory);
  const entries = await readdir(absoluteDirectory, { withFileTypes: true });
  const files = [];
  for (const entry of entries.sort((left, right) => left.name.localeCompare(right.name))) {
    const relativePath = relativeDirectory === ""
      ? entry.name
      : `${relativeDirectory}/${entry.name}`;
    if (entry.isSymbolicLink()) {
      throw new Error(`可信 pnpm 安装树包含 symlink/reparse：${relativePath}`);
    }
    if (entry.isDirectory()) {
      files.push(...(await collectTrustedTreeFiles(directoryPath, relativePath)));
    } else if (entry.isFile()) {
      files.push(relativePath);
    } else {
      throw new Error(`可信 pnpm 安装树包含特殊条目：${relativePath}`);
    }
  }
  return files.sort();
}

/** 验证目标在安装前不存在，避免复用或覆盖不可信内容。 */
async function assertPathAbsent(targetPath, label) {
  try {
    await lstat(targetPath);
  } catch (error) {
    if (error && typeof error === "object" && error.code === "ENOENT") {
      return;
    }
    throw error;
  }
  throw new Error(`${label} 在安装前必须不存在。`);
}

/** 验证命令行只接受绝对路径。 */
function assertAbsolutePath(value, label) {
  if (typeof value !== "string" || !path.isAbsolute(value) || value.includes("\0")) {
    throw new Error(`${label} 必须是无 NUL 的绝对路径。`);
  }
}

/** 验证 SHA-256 使用小写完整十六进制表示。 */
function assertDigest(value, label) {
  if (!/^[a-f0-9]{64}$/u.test(value)) {
    throw new Error(`${label} 不是完整小写 SHA-256。`);
  }
}

/** 解析封闭命令行参数集合。 */
function parseArguments(argv) {
  if (argv.length % 2 !== 0) {
    throw new Error("参数必须使用 --name value 成对形式。");
  }
  const values = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    if (name !== "--archive" && name !== "--trusted-root") {
      throw new Error(`未知参数：${name}`);
    }
    if (values.has(name)) {
      throw new Error(`参数重复：${name}`);
    }
    values.set(name, argv[index + 1]);
  }
  if (!values.has("--archive") || !values.has("--trusted-root")) {
    throw new Error("缺失 --archive 或 --trusted-root。");
  }
  return {
    archivePath: values.get("--archive"),
    trustedRoot: values.get("--trusted-root"),
  };
}

const invokedPath = process.argv[1] === undefined
  ? undefined
  : pathToFileURL(path.resolve(process.argv[1])).href;
if (invokedPath === import.meta.url) {
  if (process.platform !== "win32") {
    throw new Error("可信 pnpm Win32 安装器只能在真实 Win32 runner 执行。");
  }
  const result = await installTrustedPnpmWin32(parseArguments(process.argv.slice(2)));
  await verifyTrustedPnpmVersion(result.pnpmPath);
  process.stdout.write(
    `${JSON.stringify({ ...result, version: PNPM_WIN32_VERSION })}\n`,
  );
}

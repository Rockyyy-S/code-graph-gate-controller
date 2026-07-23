import { createHash } from "node:crypto";

/** 按 RFC 8785 所需规则规范化纯 JSON 值。 */
export function canonicalizeJson(value) {
  return serialize(value, new Set());
}

/** 对 UTF-8 文本或原始字节计算小写十六进制 SHA-256。 */
export function sha256Hex(value) {
  return createHash("sha256").update(value).digest("hex");
}

/** 对纯 JSON 值执行 JCS、UTF-8 与 SHA-256。 */
export function sha256CanonicalJson(value) {
  return sha256Hex(canonicalizeJson(value));
}

/** @param {unknown} value @param {Set<object>} ancestors */
function serialize(value, ancestors) {
  if (value === null || typeof value === "boolean") {
    return JSON.stringify(value);
  }
  if (typeof value === "string") {
    assertUnicode(value);
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new TypeError("JCS 不接受非有限数字。");
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return serializeArray(value, ancestors);
  }
  if (typeof value === "object") {
    return serializeObject(value, ancestors);
  }
  throw new TypeError("JCS 输入必须是纯 JSON 值。");
}

/** @param {unknown[]} value @param {Set<object>} ancestors */
function serializeArray(value, ancestors) {
  enter(value, ancestors);
  try {
    const keys = Object.keys(value);
    if (keys.length !== value.length || keys.some((key, index) => key !== String(index))) {
      throw new TypeError("JCS 不接受稀疏数组或数组附加字段。");
    }
    return `[${value.map((entry) => serialize(entry, ancestors)).join(",")}]`;
  } finally {
    ancestors.delete(value);
  }
}

/** @param {object} value @param {Set<object>} ancestors */
function serializeObject(value, ancestors) {
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new TypeError("JCS 不接受非 JSON 对象。");
  }
  enter(value, ancestors);
  try {
    const ownKeys = Reflect.ownKeys(value);
    if (ownKeys.some((key) => typeof key !== "string")) {
      throw new TypeError("JCS 不接受 Symbol 字段。");
    }
    return `{${ownKeys
      .sort()
      .map((key) => {
        assertUnicode(key);
        const descriptor = Object.getOwnPropertyDescriptor(value, key);
        if (descriptor === undefined || !descriptor.enumerable || !("value" in descriptor)) {
          throw new TypeError("JCS 不接受访问器或不可枚举字段。");
        }
        return `${JSON.stringify(key)}:${serialize(descriptor.value, ancestors)}`;
      })
      .join(",")}}`;
  } finally {
    ancestors.delete(value);
  }
}

/** @param {object} value @param {Set<object>} ancestors */
function enter(value, ancestors) {
  if (ancestors.has(value)) {
    throw new TypeError("JCS 不接受循环引用。");
  }
  ancestors.add(value);
}

/** @param {string} value */
function assertUnicode(value) {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        throw new TypeError("JCS 不接受不成对的 UTF-16 高代理项。");
      }
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      throw new TypeError("JCS 不接受不成对的 UTF-16 低代理项。");
    }
  }
}

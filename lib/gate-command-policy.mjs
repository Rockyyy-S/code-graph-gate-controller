import path from "node:path";

const forbiddenExecutables = new Set(["echo", "printf", "true"]);

/** 拒绝直接恒成功、仅输出文本或以内联 Node 代码绕过受保护实现的 gate argv。 */
export function isNoOpGateCommand(command) {
  if (!Array.isArray(command) || command.length === 0) {
    return true;
  }
  const executable = path.basename(command[0]).toLowerCase().replace(/\.exe$/u, "");
  if (forbiddenExecutables.has(executable)) {
    return true;
  }
  return executable === "node" && command.slice(1).some(
    (argument) => /^(?:-e|-p).*/u.test(argument) || /^--(?:eval|print)(?:=|$)/u.test(argument),
  );
}

/** 拒绝 pnpm 根脚本中可静态证明为恒成功或内联执行的实现。 */
export function isNoOpRootScript(source) {
  if (typeof source !== "string") {
    return true;
  }
  const normalized = source.trim().replace(/[;\s]+$/u, "").toLowerCase();
  if ([":", "true", "exit 0", "exit /b 0"].includes(normalized)) {
    return true;
  }
  if (/^(?:echo|printf)(?:\s|$)/u.test(normalized)) {
    return true;
  }
  if (/^node(?:\.exe)?\s+(?:(?:-e|-p).*|--(?:eval|print)(?:=|\s))/u.test(normalized)) {
    return true;
  }
  return /^(?:ash|bash|dash|ksh|sh|zsh)\s+-c\s+["']?(?:true|:|exit\s+0)["']?$/u.test(
    normalized,
  );
}

/** triggerPaths 缺失表示 always applicable，否则按受限 POSIX glob 匹配。 */
export function evaluateApplicability(definition, affectedPaths) {
  if (!Object.hasOwn(definition, "triggerPaths")) {
    return "required";
  }
  return definition.triggerPaths.some((glob) => {
    const expression = globToRegExp(glob);
    return affectedPaths.some((relativePath) => expression.test(relativePath));
  })
    ? "required"
    : "not-applicable";
}

/** 将不含反选和字符类的受限 POSIX glob 转为整路径正则。 */
function globToRegExp(glob) {
  let pattern = "^";
  for (let index = 0; index < glob.length; index += 1) {
    const character = glob[index];
    const next = glob[index + 1];
    if (character === "*" && next === "*") {
      if (glob[index + 2] === "/") {
        pattern += "(?:[^/]+/)*";
        index += 2;
      } else {
        pattern += ".*";
        index += 1;
      }
    } else if (character === "*") {
      pattern += "[^/]*";
    } else if (character === "?") {
      pattern += "[^/]";
    } else {
      pattern += character.replace(/[\\^$.*+?()[\]{}|]/gu, "\\$&");
    }
  }
  return new RegExp(`${pattern}$`, "u");
}

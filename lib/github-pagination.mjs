/**
 * 读取 GitHub REST 列表接口的全部分页，并拒绝非数组响应或异常超长分页。
 *
 * @param {object} input 分页读取参数。
 * @param {string} input.endpoint 不含 page/per_page 的 REST endpoint。
 * @param {string|null} input.field 对象响应中的数组字段；顶层数组响应传 null。
 * @param {number} [input.maxPages] 最大允许页数，防止异常响应无限循环。
 * @param {object} [input.options] 透传给 GitHub 请求的选项。
 * @param {(endpoint: string, options?: object) => Promise<unknown>} input.request GitHub 请求函数。
 * @param {number} [input.retries] 每页瞬态请求失败后的额外重试次数。
 * @returns {Promise<unknown[]>} 全部分页元素。
 */
export async function collectGithubPages(input) {
  const result = await collectGithubPagesBestEffort(input);
  if (result.error !== null) {
    throw result.error;
  }
  return result.values;
}

/**
 * best-effort 读取 GitHub REST 分页，发生后续页错误时保留此前已经验证的元素。
 *
 * @param {object} input 分页读取参数，与 collectGithubPages 相同。
 * @returns {Promise<{error: Error|null, values: unknown[]}>} 已读取元素与首个分页错误。
 */
export async function collectGithubPagesBestEffort({
  endpoint,
  field,
  maxPages = 1_000,
  options = {},
  request,
  retries = 2,
}) {
  const values = [];
  const separator = endpoint.includes("?") ? "&" : "?";
  for (let page = 1; page <= maxPages; page += 1) {
    let response;
    let requestError = null;
    for (let attempt = 0; attempt <= retries; attempt += 1) {
      try {
        response = await request(
          `${endpoint}${separator}per_page=100&page=${page}`,
          options,
        );
        requestError = null;
        break;
      } catch (error) {
        requestError =
          error instanceof Error ? error : new Error("GitHub 分页接口调用失败。");
      }
    }
    if (requestError !== null) {
      return { error: requestError, values };
    }
    try {
      const pageValues = field === null ? response : response?.[field];
      if (!Array.isArray(pageValues)) {
        throw new Error(`GitHub 分页接口 ${endpoint} 未返回数组字段。`);
      }
      values.push(...pageValues);
      if (pageValues.length < 100) {
        return { error: null, values };
      }
    } catch (error) {
      return {
        error: error instanceof Error ? error : new Error("GitHub 分页接口调用失败。"),
        values,
      };
    }
  }
  return {
    error: new Error(`GitHub 分页接口 ${endpoint} 超过安全页数上限。`),
    values,
  };
}

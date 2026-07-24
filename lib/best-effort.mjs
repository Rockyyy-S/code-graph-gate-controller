/**
 * 按顺序尝试全部项目，即使单项失败也继续，并返回每项失败原因。
 *
 * @param {unknown[]} items 待处理项目。
 * @param {(item: unknown) => Promise<void>} action 单项异步动作。
 * @returns {Promise<unknown[]>} 所有失败原因。
 */
export async function runBestEffort(items, action) {
  const failures = [];
  for (const item of items) {
    try {
      await action(item);
    } catch (error) {
      failures.push(error);
    }
  }
  return failures;
}

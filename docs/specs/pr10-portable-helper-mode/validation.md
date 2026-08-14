# validation.md

> Generated on 2026-08-14 for `pr10-portable-helper-mode`.
> Route: `bugfix`

## Requirement-to-Validation Mapping

| Requirement or behavior | Validation method | Test type | Result |
| --- | --- | --- | --- |
| `gatecandidate` 实际子进程在 Cargo 前固定 `0022` umask | workflow contract 身份边界与顺序断言 | regression | pass |
| 禁止外层 umask 冒充目标进程策略 | workflow contract 负断言 | security regression | pass |
| 不以 chmod 修补候选产物 | workflow contract 负断言 | security regression | pass |
| 既有 producer 合同不回归 | `pnpm test` | unit/contract | pass（183/183） |
| Hosted portable helper mode 安全 | PR #10 `gate-execution-portable` | integration | pending（producer `303f54e...` 的外层 umask 已证实无效） |
| 精确 PR head 获可信授权 | sequence 25 proposal + registry tests | security contract | pass（head `06866f6...`） |

## Happy-Path Validation

- [x] `umask 0022` 位于 `gatecandidate` 的 Bash 子进程内且早于 `exec cargo build`。
- [ ] helper proof 在 Hosted runner 报告不可 group/world 写入的 mode。

## Boundary and Exception Validation

- [x] workflow 不包含对 `$bridge_source` / `$daemon_source` 的 chmod。
- [x] mode 若仍含 `0022` 写位，既有 proof 继续失败关闭。

## Bugfix-Specific Validation

- [x] The issue can be reproduced
- [x] The fix behaves correctly
- [x] Unchanged behavior stays unchanged

## Non-Functional Validation

- [x] Performance: 仅设置进程 umask，无额外构建或网络开销
- [x] Security: 产物从创建起不可 group/world 写入
- [x] Compatibility: reusable workflow 输入输出不变
- [x] Observability: 保留 numeric-mode 诊断

## Layered Review Record

- [x] Logic correctness
- [x] Edge handling
- [x] Rule consistency

## Execution Notes

- Executor: Codex
- Execution time: 2026-08-14
- Result summary: producer `303f54e...` 的 Hosted portable 复验仍产出 mode `775`，确认外层 umask 无法跨越目标身份进程边界；策略已移入真实 Cargo 子进程，定向合同测试与 controller 全量 183 项测试通过。
- Incomplete items and reasons: Hosted portable/Win32 evidence 与最终 `architecture-required` 尚待使用新 producer 重新验证。

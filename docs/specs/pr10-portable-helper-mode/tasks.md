# tasks.md

> Generated on 2026-08-14 for `pr10-portable-helper-mode`.
> Route: `bugfix`

## Task List

- [x] 1. 复现并界定失败
  - Inputs: PR #10 portable 日志、producer `2cc5b120...`
  - Outputs: `775` mode 与继承 umask 的根因记录
  - Scope: 只读日志与 workflow 检查
  - Completion criteria: 首个失败谓词和责任边界明确
  - Dependencies: 无
  - Can run in parallel: 是
  - Wait-for-confirmation point: 无
  - Stop condition: 证据不足时不修改代码
  - Required verification output: `helper-proof[bridge] numeric-mode: 775`

- [x] 2. 固定 helper 构建 umask 并补充回归测试
  - Inputs: provisioning step、workflow contract tests
  - Outputs: `umask 0022` 与顺序/禁止 chmod 断言
  - Scope: producer workflow 与单个测试文件
  - Completion criteria: 新测试先失败、修复后全量测试通过
  - Dependencies: Task 1
  - Can run in parallel: 否
  - Wait-for-confirmation point: 无
  - Stop condition: 若必须放宽 proof，则停止并重新设计
  - Required verification output: `pnpm test` 通过

- [ ] 3. 发布 producer 并完成候选信任闭环
  - Inputs: controller merge SHA、code-graph PR #10 head
  - Outputs: 新 producer pin、精确 head proposal、全绿门禁与远端 main 合并
  - Scope: controller PR、code-graph pin/proposal，不更改业务实现
  - Completion criteria: `architecture-required` 成功且 PR #10 合并
  - Dependencies: Task 2
  - Can run in parallel: 否
  - Wait-for-confirmation point: 无
  - Stop condition: 需要管理员绕过或降低规则时停止
  - Required verification output: GitHub checks 全绿、origin/main 包含候选提交

## Suggested Waves

### Wave 1: Core Path

- Goal: 建立失败证据并修复 producer 创建权限。
- Included tasks: 1、2
- Minimum validation: 新回归测试与 controller 全量测试
- Exit criteria: producer PR 可合并

### Wave 2: Edge Cases and Failures

- Goal: 回钉不可变 producer 并建立 exact-head proposal。
- Included tasks: 3 的 pin/proposal 部分
- Minimum validation: code-graph 本地 registry/contract 校验、controller proposal 测试
- Exit criteria: PR #10 重新触发全部 checks

### Wave 3: Enhancements and Cleanup

- Goal: 合并受保护分支并验证远端一致性。
- Included tasks: 3 的 hosted checks/merge 部分
- Minimum validation: `architecture-required` success、origin/main SHA 检查
- Exit criteria: 远端 main 完成更新

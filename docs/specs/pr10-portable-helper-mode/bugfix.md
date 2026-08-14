# bugfix.md

> Generated on 2026-08-14 for `pr10-portable-helper-mode`.
> Route: `bugfix`

## Background

- Bug title: Portable producer 继承宽松 umask，可信 helper 被构建为 `775`
- Discovery channel: `code-graph` PR #10，GitHub Actions run `31764555692`
- Impact scope: `gate-execution-portable` 无法完成 helper provisioning，受保护的 `main` 无法合并
- Priority: P1（阻断发布，但未影响已部署运行时）

## Current Incorrect Behavior

- Symptom: `helper-proof[bridge] numeric-mode` 报告 `775`，随后以 `group/world writable` 失败。
- Reproduction steps: 使用 producer `2cc5b120...` 对候选 `91b18ff...` 运行 reusable workflow。
- Actual result: Cargo 在 `gatecandidate` 身份下产出的 bridge/daemon 继承 runner 的 `0002` umask，安全证明拒绝继续安装与签名。

## Expected Correct Behavior

- Expected result: 构建动作在执行 Cargo 前固定 `0022` umask，两个 executable 从生成时即不可被 group/world 写入，并继续通过既有逐项证明。
- User-visible change: PR portable evidence 可以继续运行；不改变 helper 字节、CLI 或运行时协议。

## Invariant Behavior That Must Not Change

- Existing behavior that must remain true 1: 候选源码与生成目录的身份隔离、离线 Cargo、锁定 toolchain 和精确 executable 归因保持不变。
- Existing behavior that must remain true 2: 禁止在证明前用 `chmod` 修补候选产物；mode、owner、ELF、hash 和零参数 probe 仍然 fail-closed。

## Initial Root-Cause Hypotheses

- Hypothesis 1（已确认）: `sudo -u gatecandidate` 继承 runner 的 `0002` umask，Cargo 按 `777 & ~0002` 创建 executable，得到 `775`。
- Hypothesis 2（已排除）: Rust/Cargo 或候选 crate 显式请求 `775`；仓库中没有对应权限设置，且失败发生在 producer 的构建边界。

## Fix Acceptance Criteria

- [x] The problem can be reproduced reliably
- [x] The fix removes the primary issue
- [x] Existing correct behavior does not regress
- [x] The minimum necessary tests are added

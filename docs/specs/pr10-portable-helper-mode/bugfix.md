# bugfix.md

> Generated on 2026-08-14 for `pr10-portable-helper-mode`.
> Route: `bugfix`

## Background

- Bug title: Portable producer 继承宽松 umask，可信 helper 被构建为 `775`
- Discovery channel: `code-graph` PR #10，GitHub Actions run `31765400788` attempt 2
- Impact scope: `gate-execution-portable` 无法完成 helper provisioning，受保护的 `main` 无法合并
- Priority: P1（阻断发布，但未影响已部署运行时）

## Current Incorrect Behavior

- Symptom: `helper-proof[bridge] numeric-mode` 报告 `775`，随后以 `group/world writable` 失败。
- Reproduction steps: 使用 producer `303f54e...` 对候选 `06866f6...` 运行 reusable workflow。
- Actual result: producer 虽在 `sudo` 外层设置 `0022`，但 `sudo -u gatecandidate` 为目标身份建立的实际子进程仍使用 `0002`；Cargo 产出 `775` 的 bridge/daemon，安全证明拒绝继续安装与签名。
- Follow-up symptom: producer `4217009...` 已把两个 binary 构建为 `755` 并完成 freeze，但 runner 直接 `stat /etc/codegraph-host-path/client.key` 时因父目录 `root:gatecandidate 750` 返回 `Permission denied`。
- Follow-up root cause: 安装后证明使用了无权遍历受保护目录的 runner 身份；同类未授权访问还存在于 socket ready 检查、preflight mode 证明和清理阶段的 PID 文件读取。

## Expected Correct Behavior

- Expected result: `gatecandidate` 的实际构建子进程在执行 Cargo 前固定 `0022` umask，两个 executable 从生成时即不可被 group/world 写入，并继续通过既有逐项证明。
- Follow-up expected result: root 对受保护 key/socket/PID 路径执行只读证明与清理，runner 不获得额外组身份，`0750`/`0640`/`0660` 权限保持不变。
- User-visible change: PR portable evidence 可以继续运行；不改变 helper 字节、CLI 或运行时协议。

## Invariant Behavior That Must Not Change

- Existing behavior that must remain true 1: 候选源码与生成目录的身份隔离、离线 Cargo、锁定 toolchain 和精确 executable 归因保持不变。
- Existing behavior that must remain true 2: 禁止在证明前用 `chmod` 修补候选产物；mode、owner、ELF、hash 和零参数 probe 仍然 fail-closed。
- Existing behavior that must remain true 3: 不得为方便 runner 检查而放宽 `/etc/codegraph-host-path` 或 `/run/codegraph-host-path` 的访问权限。

## Initial Root-Cause Hypotheses

- Hypothesis 1（已确认）: 外层 `umask 0022` 不会跨越 `sudo` 的目标身份进程边界；该子进程使用 `0002`，Cargo 按 `777 & ~0002` 创建 executable，得到 `775`。
- Hypothesis 2（已排除）: Rust/Cargo 或候选 crate 显式请求 `775`；仓库中没有对应权限设置，且失败发生在 producer 的构建边界。

## Fix Acceptance Criteria

- [x] The problem can be reproduced reliably
- [x] The fix removes the primary issue
- [x] Existing correct behavior does not regress
- [x] The minimum necessary tests are added

## Follow-up Fix Acceptance Criteria

- [x] key/socket 的 mode 证明由 root 身份执行
- [x] socket readiness 与 cleanup PID 读取不依赖 runner 遍历受保护目录
- [x] 受保护目录和材料权限不放宽
- [x] workflow contract 与 controller 全量测试通过

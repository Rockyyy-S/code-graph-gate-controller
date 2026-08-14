# design.md

> Generated on 2026-08-14 for `pr10-portable-helper-mode`.
> Route: `bugfix`

## Overview

- Design objective: 让候选 helper 从创建时就满足不可 group/world 写入的 producer 信任约束。
- Core approach: 在 `Provision signed Linux host-path helper runtime` 的 Cargo 子进程前固定 shell umask 为 `0022`，并用 workflow contract test 锁定顺序与禁止事后 chmod。

## Current State and Constraints

- How the current system works: producer 以私有 build home 和 `gatecandidate` UID 离线构建两个 Rust binary，随后逐项证明权限、身份、ELF、摘要及可执行行为，再冻结、签名和安装。
- Boundaries that must be respected: producer workflow 是外部信任根；不能修改候选源文件、放宽 mode 检查或使用管理员绕过受保护分支。
- Existing logic that must remain compatible: Cargo JSON executable 归因、候选 UID 隔离、runner-owned staging、签名与安装路径均保持原样。

## Proposed Design

### Module Responsibilities and Boundaries

- `.github/workflows/produce-gate-evidence.yml`: 在进入候选 Cargo 构建前建立权限创建策略。
- `tests/workflow-contract.test.mjs`: 验证 `umask 0022` 位于 Cargo 之前，且构建后不存在针对私有产物的 chmod 修补。

### Core Flow / Sequence

1. producer 创建仅候选 UID 可访问的 build home。
2. producer 固定 `umask 0022`，再以 `gatecandidate` 启动离线 Cargo 构建。
3. 既有 `prove_private_binary` 证明产物 mode 不含 `0022` 写位，之后才冻结、签名和安装。

### Incremental Change Points

- Reused modules: 既有 helper provisioning、`prove_private_binary` 和 workflow contract 测试提取器。
- New change points: 一行 umask 策略与一个回归测试。
- Forbidden touch points: 候选 crate、mode 拒绝谓词、签名材料、Controller policy 和 ruleset。

## Data Structures and Interfaces

- Inputs: 固定候选 SHA、固定 Rust toolchain、私有 build home。
- Outputs: mode 通常为 `755` 且不可 group/world 写入的 bridge/daemon。
- State transitions: build home 创建 → restrictive umask → Cargo build → proof → freeze/sign/install。
- Interface contracts: reusable workflow 输入输出与 artifact schema 不变。

## Error Handling

- Failure scenarios: Cargo 失败、产物仍含写位、产物身份或摘要漂移。
- Degradation strategy: 保持现有 fail-closed；不得跳过 proof 或生成部分 evidence。
- Rollback strategy: 单提交回退 producer 变更并恢复旧不可变 SHA；不会触碰候选运行时代码。

## Observability and Test Strategy

- Logs / metrics / traces: 保留 `helper-proof[*] numeric-mode` 诊断。
- Unit tests: workflow contract 锁定 restrictive umask 的存在和顺序。
- Integration tests: controller 全量 `pnpm test`；随后用新 producer 重新运行 `code-graph` PR #10 portable job。
- Regression checks: Win32 producer、可信 tool proof、Cargo JSON 归因和冻结/签名合同继续通过。
- Layered review: `logic / edge handling / rule consistency`

## Risks and Tradeoffs

- Primary risks: umask 设置位置错误导致未传递给候选进程，或误用 chmod 掩盖产物创建策略。
- Alternative approaches: 构建后 `chmod 0755`、放宽 proof、修改 crate；这些方案都会削弱或混淆信任边界。
- Decision rationale: `0022` 在文件创建时消除危险写位，改动最小且保持产物字节与既有证明逻辑不变。

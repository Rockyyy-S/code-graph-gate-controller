# code-graph-gate-controller

`Rockyyy-S/code-graph` 的仓库外架构门禁控制面。候选仓库只能提交待验证的 Gate Registry 和源码，不能修改本仓库固定提交中的 GateHarness、证据规则或最终 check 发布逻辑。

## 信任边界

- `lib/` 与 `bin/`：按不可变提交固定的 GateHarness，解析候选 registry、固定 Git OID、执行 gate 并生成 child evidence。
- `.github/workflows/produce-gate-evidence.yml`：供候选仓库按完整提交 SHA 调用的可信 reusable workflow。
- `trusted/registry.json` 与 `trusted/registry-approval.json`：canonical 单调可信根；canonical producer 只从已验证 approval 读取，候选提交不能修改。
- `trusted/proposed/<head>.json` 与对应 approval：只为精确 provider repository、PR number 和 head OID 授权 proposal-time registry、实现摘要与 producer，不改变 canonical sequence。
- producer 提交必须不可变地固定 GateHarness；当前过渡中 producer `23b8fc5bc221b99d78640ab55a711ae3d42054f4` 固定 Harness `97048ec0c2f6a38716bf3c0b38ac8c6bf31c709f`，Controller 同时把所选 producer 绑定到 GitHub attestation signer digest、证书 URI 与 evidence 校验。
- proposal 成功、Hosted evidence 或 Controller success 都不是 promotion。canonical promotion 必须通过独立批准的单调 registry/approval 迁移完成。
- Controller 与 drift monitor 的密钥只存在于批准的部署环境，不写入仓库。

本仓库不保存 GitHub App private key、webhook secret、管理 token 或候选仓库凭据。

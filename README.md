# code-graph-gate-controller

`Rockyyy-S/code-graph` 的仓库外架构门禁控制面。候选仓库只能提交待验证的 Gate Registry 和源码，不能修改本仓库固定提交中的 GateHarness、证据规则或最终 check 发布逻辑。

## 信任边界

- `lib/` 与 `bin/`：按不可变提交固定的 GateHarness，解析候选 registry、固定 Git OID、执行 gate 并生成 child evidence。
- `.github/workflows/produce-gate-evidence.yml`：供候选仓库按完整提交 SHA 调用的可信 reusable workflow。
- `trusted/registry.json`：外部 owner 批准的单调 Gate Registry 记录；候选提交不能修改。
- Controller 与 drift monitor 的密钥只存在于批准的部署环境，不写入仓库。

本仓库不保存 GitHub App private key、webhook secret、管理 token 或候选仓库凭据。

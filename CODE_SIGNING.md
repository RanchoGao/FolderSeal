# 代码签名与发布验证政策 / Code Signing & Build Verification Policy

> **当前状态 / Current Status**：**尚未启用数字代码签名（Currently Unsigned）**。  
> 在完成免费开源代码签名接入前，Windows UAC 与 SmartScreen 仍可能提示“未知发布者”。请通过本文所述的 **SHA-256 校验文件** 与 **GitHub SLSA 构建溯源证明** 核验发布包真伪。

---

## 中文说明

### 1. 构建来源与可验证性

- 自本政策生效起的公开 Release 均由 GitHub 官方托管环境（`windows-latest` GitHub-hosted runner）执行公开工作流 [`.github/workflows/release.yml`](.github/workflows/release.yml) 从对应 `v*` 源码标签自动编译、通过全量测试（含管理员 NTFS ACL 集成测试）并打包生成。
- 除应急本地验证外，公开分发包不采用个人本机手工编译的二进制文件。
- 每次自动发布都会生成：
  1. `SHA256SUMS.txt` 与 `PORTABLE-SHA256SUMS.txt` 校验文件；
  2. GitHub **SLSA Build Provenance Attestation**（构建溯源证明）。

### 2. 如何验证下载的安装包或便携包

1. **校验 SHA-256 哈希**（PowerShell）：
   ```powershell
   Get-FileHash -Algorithm SHA256 .\FolderSeal-<版本>-Setup.exe
   ```
   将输出结果与同版本 Release 中的 `SHA256SUMS.txt` 比对。
2. **校验 GitHub SLSA 构建溯源证明**（需安装 [GitHub CLI (`gh`)](https://cli.github.com/)）：
   ```powershell
   gh attestation verify .\FolderSeal-<版本>-Setup.exe --repo RanchoGao/FolderSeal
   gh attestation verify .\FolderSeal-<版本>-Portable.zip --repo RanchoGao/FolderSeal
   ```
   验证通过即证明该文件确由 GitHub Actions 从本仓库对应源码提交自动构建且未经篡改。

### 3. 维护者角色与安全治理（单人维护）

本项目由独立开发者单人维护，所有角色均已启用 GitHub 双因素认证（2FA）：

- **作者与提交者（Author / Committer）**：EurekaGao（GitHub: `RanchoGao`）
- **代码审查者（Reviewer）**：EurekaGao（GitHub: `RanchoGao`）
- **发布与签名审批者（Approver）**：EurekaGao（GitHub: `RanchoGao`）

### 4. 代码签名计划（SignPath Foundation 预留）

- 本项目采用 MIT 开源协议、公开仓库且永久免费分发，计划在满足全部前置条件后申请 **SignPath Foundation** 免费开源代码签名计划（需求编号 `R-002`）。
- `.github/workflows/release.yml` 已预留双阶段签名流水线（先签 `FolderSeal.exe`，再打包便携包与安装包，再签 `FolderSeal-Setup.exe` 并重算 `SHA256SUMS.txt`），默认处于关闭状态；待正式获批并启用后，本页将同步更新为已启用状态并公示证书信息。

---

## English Policy

### 1. Build Provenance & Integrity

- Official release binaries are built exclusively on **GitHub-hosted runners** (`windows-latest`) via the public workflow [`.github/workflows/release.yml`](.github/workflows/release.yml) directly from tagged public source code (`v*`), after passing the full automated test suite (including elevated NTFS ACL integration tests).
- Release artifacts are accompanied by `SHA256SUMS.txt` / `PORTABLE-SHA256SUMS.txt` and **GitHub SLSA Build Provenance Attestations**.

### 2. Verifying Release Artifacts

You can verify any downloaded release artifact using GitHub CLI:

```powershell
gh attestation verify .\FolderSeal-<version>-Setup.exe --repo RanchoGao/FolderSeal
gh attestation verify .\FolderSeal-<version>-Portable.zip --repo RanchoGao/FolderSeal
```

### 3. Team Roles (Solo Maintainer)

This project is maintained by a solo developer with Two-Factor Authentication (2FA) enabled on GitHub:

- **Author / Committer**: EurekaGao (GitHub: `RanchoGao`)
- **Reviewer**: EurekaGao (GitHub: `RanchoGao`) — all external pull requests are reviewed before merge
- **Approver**: EurekaGao (GitHub: `RanchoGao`) — manually reviews and approves each release (and future signing requests)

### 4. Planned Code Signing (SignPath Foundation)

- **Current Status**: Release binaries are **not yet Authenticode-signed**.
- **Planned Integration**: This project intends to apply for free open-source code signing through **SignPath Foundation**. Once approved and enabled via `.github/workflows/release.yml`, binaries will be signed exclusively in CI from public tagged sources, and this policy will be updated with the active attribution notice (*"Free code signing provided by SignPath.io, certificate by SignPath Foundation."*).

### 5. Privacy Policy

See [PRIVACY.md](PRIVACY.md) for the complete privacy policy and network disclosure.

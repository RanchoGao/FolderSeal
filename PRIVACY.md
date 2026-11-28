# 隐私声明 / Privacy Policy

> **适用产品**：密封夹（FolderSeal）  
> **维护者**：EurekaGao（GitHub: [`RanchoGao/FolderSeal`](https://github.com/RanchoGao/FolderSeal)）

---

## 中文声明

密封夹（FolderSeal）是一款**纯本地优先（Local-First）**的 Windows 文件夹加密工具。我们遵循最小化数据原则：

1. **零遥测、零追踪、零账号**
   - 本软件**不包含**任何用户账号体系、遥测统计（Telemetry）、行为分析（Analytics）、广告组件或自动崩溃上报机制。
   - 本软件**绝不会**将你的文件内容、文件名、加密文件夹路径、密码、密码提示或本机硬件标识上传至任何服务器。
2. **唯一的联网行为：公开版本升级检测（只读）**
   - 启动软件时会在后台执行一次静默升级检测，或在你主动点击“检测升级”时发起请求。
   - 该请求仅通过 HTTPS 只读访问 GitHub 公开接口 `https://api.github.com/repos/RanchoGao/FolderSeal/releases?per_page=100`（请求头仅包含标准 `User-Agent: FolderSeal/<版本>` 与 GitHub API 版本头）。
   - 仅在你**主动点击确认更新**后，程序才会从 `github.com` 或 `*.githubusercontent.com` 下载对应版本的公开安装包与 `SHA256SUMS.txt` 校验文件。
   - 无网络或无法访问 GitHub 时，升级检测静默失败，不影响任何本地加密、解密与管理功能。
3. **本机持久化数据**
   - 所有数据仅保存在你的本机磁盘中，包括加密保存的位置目录表（`%LOCALAPPDATA%\EurekaGao\FolderSeal\catalog.egcatalog`）与明文保存的轻量偏好设置/可选密码提示（`%LOCALAPPDATA%\EurekaGao\FolderSeal\settings.txt`）。
   - 你可以随时卸载软件并手动清理上述本机目录。

---

## English Policy

**FolderSeal (密封夹)** is a **local-first** Windows folder encryption utility.

1. **No Telemetry, No Analytics, No Accounts**
   - This program has **no user accounts, no telemetry, no analytics, no advertisements, and no automatic crash reporting**.
   - This program **never transfers** your files, filenames, folder paths, passwords, password hints, or machine identifiers to any external server.
2. **The Only Network Activity: Public GitHub Release Update Check**
   - On startup (and when you manually click "Check for Updates"), the program sends a read-only HTTPS `GET` request to the public GitHub Releases API (`https://api.github.com/repos/RanchoGao/FolderSeal/releases?per_page=100`) with only a standard `User-Agent: FolderSeal/<version>` header.
   - Only after you **explicitly confirm** an update will the program download the public installer and `SHA256SUMS.txt` over HTTPS from `github.com` or `*.githubusercontent.com`.
   - If the machine is offline or GitHub is unreachable, the check fails silently without affecting any local functionality.
3. **Local-Only Storage**
   - All application state stays strictly on your local NTFS disk: the encrypted vault catalog (`%LOCALAPPDATA%\EurekaGao\FolderSeal\catalog.egcatalog`) and local preferences / optional plaintext password hint (`%LOCALAPPDATA%\EurekaGao\FolderSeal\settings.txt`).

# AGENTS.md

## 项目

FolderSeal（文件夹加密工具）：C# + Windows Forms + .NET Framework 4.7.2 实现的本地加密文件夹工具，单文件源码，目标 Windows 10/11 本机 NTFS。

## 目录约定

- `src/` 只放程序源码与 manifest，永远只有一份最新版本。
- `tests/` 放验证源码，测试只使用生成的样例，禁止指向个人文件。
- `scripts/` 放构建、打包、安装包验证脚本，一律用仓库相对路径。
- `installer/` 放 NSIS 定义；版本号只在 `!define VERSION` 一处维护。
- `docs/` 放中文文档；过期文档移入 `docs/历史/`。
- `artifacts/`、`tools/`、`releases/`、`_archive/`、`_personal/` 均不入库。

## 硬性规则

1. 文件名不带版本号和日期，版本只写在 CHANGELOG、git tag、`releases/<版本>/` 里。
2. 不新增 `foo_V2.cs` 这类副本；改动直接改原文件，历史交给 git。
3. 构建产物一律进 `artifacts/`，源码目录不出现 exe。
4. 测试、文档、脚本里不出现个人路径、真实姓名和个人资料文件。
5. 对外署名统一 EurekaGao。

## 常用命令

```powershell
.\scripts\build.ps1 -Validate -ValidateEntry     # 编译并跑核心与入口验证
.\scripts\build.ps1 -ValidateAcl                # 管理员 PowerShell：权限验证
.\scripts\package.ps1                           # 编译并生成安装包到 artifacts/dist
.\scripts\verify-installer.ps1                  # 管理员 PowerShell：安装与卸载验证
```

## 发版

1. 更新 `CHANGELOG.md`。
2. 改 `installer/FolderSeal.nsi` 的 `!define VERSION`。
3. 运行 `scripts/package.ps1`，把 `artifacts/dist/` 的安装包与校验文件复制到 `releases/<版本>/`。
4. 提交后打 tag `v<版本>`，附安装包发布到 GitHub Release。

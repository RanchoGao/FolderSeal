# AGENTS.md

## 项目

密封夹（FolderSeal）：C# + Windows Forms + .NET Framework 4.7.2 实现的本地加密文件夹工具，单文件源码，目标 Windows 10/11 本机 NTFS。

中文名为“密封夹”，英文名为“FolderSeal”；对外文档统一使用“密封夹（FolderSeal）”。程序文件名、安装包名与数据路径沿用 FolderSeal。

## 目录约定

- `src/` 只放程序源码与 manifest，永远只有一份最新版本。
- `tests/` 放验证源码，测试只使用生成的样例，禁止指向个人文件。
- `scripts/` 放构建、打包、安装包验证脚本，一律用仓库相对路径。
- `installer/` 放 NSIS 定义；版本号只在 `!define VERSION` 一处维护。
- `docs/` 只放对外中文文档；过期文档移入 `docs/历史/`；图标与命名等品牌资料放 `docs/品牌设计/`。
- `assets/` 放透明品牌原图与多尺寸 ICO；改底图后运行 `scripts/prepare-icon.ps1` 重新生成。
- `_personal/需求/` 放路线图、需求池、决策记录，不入库、不公开。
- `artifacts/`、`tools/`、`releases/`、`_archive/`、`_personal/` 均不入库。

## 硬性规则

1. 文件名不带版本号和日期，版本只写在 CHANGELOG、git tag、`releases/<版本>/` 里；`docs/历史/` 的旧文件名保留版本号，作为历史快照。
2. 不新增 `foo_V2.cs` 这类副本；改动直接改原文件，历史交给 git。
3. 构建产物一律进 `artifacts/`，源码目录不出现 exe。
4. 测试、文档、脚本里不出现个人路径、真实姓名和个人资料文件。
5. 对外署名统一 EurekaGao。
6. 新需求先写进 `_personal/需求/需求池.md` 拿编号，再动代码；不新建第二份需求清单。
7. 未成型的想法、成本判断、商业打算一律不进仓库，仓库只放能公开的成品。

## 需求流程

1. 想法写进 `_personal/需求/需求池.md`，编号 `R-序号`，递增不复用。
2. 要做的需求移到 `_personal/需求/路线图.md` 的对应版本，需求池状态改为“已确认/进行中”。
3. 提交信息引用编号，如 `feat: 批量导入（R-003）`。
4. 发版时在 `CHANGELOG.md` 标注编号。
5. 跨版本、涉及取舍的技术决策，记在 `_personal/需求/决策记录/`。
6. GitHub Issue 只做讨论和缺陷记录，不作为需求清单。

## 常用命令

```powershell
.\scripts\build.ps1 -Validate -ValidateEntry     # 编译并跑核心与入口验证
.\scripts\build.ps1 -ValidateUi -ValidateIcon    # 界面、原生图标及透明边缘验证
.\scripts\build.ps1 -ValidateInstance             # 多进程单实例与请求转交验证
.\scripts\build.ps1 -ValidateLibrary              # 检索、加密位置记录、改密及中断恢复验证
.\scripts\build.ps1 -ValidateDiscovery            # 测试样例/回收站排除及旧缓存清理验证
.\scripts\build.ps1 -ValidateUpdate               # 公开版本解析、安装包筛选与下载地址验证
.\scripts\build.ps1 -ValidateShell                # 资源管理器菜单注册与右键快捷加密验证
.\scripts\build.ps1 -ValidateAcl                # 管理员 PowerShell：权限验证
.\scripts\package.ps1                           # 编译并生成安装包到 artifacts/dist
.\scripts\package-portable.ps1                  # 编译并生成便携包到 artifacts/dist
.\scripts\prepare-icon.ps1                      # 由品牌底图重新生成多尺寸 ICO
.\scripts\verify-installer.ps1                  # 管理员 PowerShell：安装与卸载验证
```

## 发版

1. 更新 `CHANGELOG.md`。
2. 改 `installer/FolderSeal.nsi` 的 `!define VERSION`。
3. 运行 `scripts/package.ps1` 与 `scripts/package-portable.ps1`，把 `artifacts/dist/` 的安装包、便携包与校验文件复制到 `releases/<版本>/`。
4. 提交后打 tag `v<版本>`，附安装包发布到 GitHub Release。

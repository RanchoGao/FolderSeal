# 密封夹（FolderSeal）设计系统

密封夹（FolderSeal）的跨端统一视觉规范与 Token 资产库，覆盖 **Windows 桌面应用（WinForms）**、**Web 交互原型** 与 **产品介绍页（官网）**。

品牌图标理念见 [图标设计理念.md](../图标设计理念.md)。

## 目录结构

| 文件 | 作用 | 是否手工编辑 |
| --- | --- | --- |
| `tokens.json` | 唯一视觉数据源（色彩、排版、圆角、间距、尺寸、阴影与官网宣传变体） | **是** |
| `tokens.css` | 自动生成的 CSS 变量（供组件库、规范手册、原型与介绍页引用） | 否（脚本生成） |
| `components.css` | 基于 `tokens.css` 抽离的共享 Web 组件样式 | 是 |
| `index.html` | 浏览器直接打开的交互式设计规范与组件预览手册 | 是 |
| `README.md` | 本维护说明 | 是 |

## 如何修改视觉规范（改一处、全产品同步）

1. 编辑 `docs/品牌设计/设计系统/tokens.json` 中的对应 Token。
2. 在仓库根目录运行同步脚本：
   ```powershell
   .\scripts\sync-design-tokens.ps1
   ```
   该脚本会自动更新：
   - `docs/品牌设计/设计系统/tokens.css`（Web / 原型 / 规范手册 / 介绍页立即生效）
   - `src/FolderSeal.cs` 中 `UiTheme` 的 `// <design-tokens:start>` 至 `// <design-tokens:end>` 常量区
3. 校验同步状态并跑桌面端回归验证：
   ```powershell
   .\scripts\sync-design-tokens.ps1 -Check
   .\scripts\build.ps1 -Validate -ValidateEntry -ValidateUi
   ```
4. 在浏览器中打开 `docs/品牌设计/设计系统/index.html` 检查视觉效果。

## 跨端 Token 映射规则

| 视觉维度 | `tokens.json` 路径 | Web CSS 变量 | WinForms (`UiTheme`) |
| --- | --- | --- | --- |
| 品牌主绿 | `color.brand.primary` | `--primary` | `UiTheme.Primary` |
| 主绿悬停 / 按下 | `color.brand.primaryHover` / `primaryActive` | `--primary-hover` / `--primary-active` | `UiTheme.PrimaryHover` / `UiTheme.PrimaryActive` |
| 品牌浅底 / 边框 | `color.brand.primaryTint` / `primaryBorder` | `--primary-tint` / `--primary-border` | `UiTheme.PrimaryTint` / `UiTheme.PrimaryBorder` |
| 画布与表面层级 | `color.neutral.canvas` / `surface` / `surface2` | `--canvas` / `--surface` / `--surface-2` | `UiTheme.Canvas` / `UiTheme.Surface` / `UiTheme.Surface2` |
| 文本层级 | `color.neutral.ink` / `muted` / `muted2` | `--ink` / `--muted` / `--muted-2` | `UiTheme.Ink` / `UiTheme.Muted` / `UiTheme.Muted2` |
| 琥珀提醒（已解锁） | `color.semantic.amber.*` | `--amber`, `--amber-bg`, `--amber-border`, `--amber-bar` | `UiTheme.Amber`, `UiTheme.AmberBg`, `UiTheme.AmberBorder`, `UiTheme.AmberBar` |
| 红色警示（错误/危险） | `color.semantic.red.*` | `--red`, `--red-bg`, `--red-border` | `UiTheme.Red`, `UiTheme.RedBg`, `UiTheme.RedBorder` |
| 文件类型色标 | `color.fileType.*` | `--ft-{type}-{bg\|border\|fg}` | `UiTheme.File{Type}{Bg\|Border\|Fg}` |
| 官网深色 Hero 变体 | `color.marketing.*` | `--mkt-*` | 仅 Web 官网使用 |
| 主字体与圆角 | `typography.fontFamily.winForms` / `radius.*` | `--font-ui` / `--r-sm`, `--r-md`, `--r-card` | `UiTheme.FontFamilyName` / `UiTheme.RadiusSm`, `RadiusMd`, `RadiusCard` |

## 设计原则

- **克制、可信赖的深绿基调**：日常工作区保持高对比浅底（`#FFFFFF` / `#F5F7F4`）与单一深绿主操作（`#1F5E45`），官网首屏使用深森林绿（`#102D24`）+ 高对比青柠色（`#DAEF99`）强化品牌记忆。
- **状态语义清晰**：绿色仅表示安全/已锁定与主操作；琥珀色明确提示“当前已解锁，存在临时明文”；红色仅用于保存失败、占锁报错与永久删除等高风险场景。
- **不单靠颜色传递信息**：所有状态徽章、横幅和按钮均搭配文字或图标说明，确保高对比度与可读性。

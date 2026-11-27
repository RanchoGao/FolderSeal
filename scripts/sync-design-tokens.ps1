# Copyright (c) 2026 EurekaGao. MIT License.
[CmdletBinding()]
param([switch]$Check)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$designDir = Join-Path $repoRoot 'docs\品牌设计\设计系统'
$tokensPath = Join-Path $designDir 'tokens.json'
$cssPath = Join-Path $designDir 'tokens.css'
$csPath = Join-Path $repoRoot 'src\FolderSeal.cs'

if (-not (Test-Path -LiteralPath $tokensPath)) {
    throw "未找到设计系统数据源：$tokensPath"
}

$tokens = [IO.File]::ReadAllText($tokensPath, [Text.UTF8Encoding]::new($false)) | ConvertFrom-Json

function ConvertTo-ArgbLiteral {
    param([string]$Hex)
    $clean = $Hex.TrimStart('#')
    if ($clean.Length -ne 6) { throw "不支持的颜色格式：$Hex（需 #RRGGBB）" }
    $r = [Convert]::ToInt32($clean.Substring(0, 2), 16)
    $g = [Convert]::ToInt32($clean.Substring(2, 2), 16)
    $b = [Convert]::ToInt32($clean.Substring(4, 2), 16)
    return "Color.FromArgb($r, $g, $b)"
}

$b = $tokens.color.brand
$n = $tokens.color.neutral
$a = $tokens.color.semantic.amber
$r = $tokens.color.semantic.red
$ft = $tokens.color.fileType
$m = $tokens.color.marketing
$ty = $tokens.typography
$rad = $tokens.radius
$sp = $tokens.spacing
$sz = $tokens.sizing
$sh = $tokens.shadow

$cssLines = @(
    '/*'
    ' * 密封夹（FolderSeal）设计系统 CSS 变量'
    ' * 由 scripts/sync-design-tokens.ps1 根据 tokens.json 自动生成，请勿手工修改。'
    ' */'
    ':root {'
    '  /* Brand */'
    "  --primary: $($b.primary);"
    "  --primary-hover: $($b.primaryHover);"
    "  --primary-active: $($b.primaryActive);"
    "  --primary-tint: $($b.primaryTint);"
    "  --primary-tint-hover: $($b.primaryTintHover);"
    "  --primary-tint-active: $($b.primaryTintActive);"
    "  --primary-border: $($b.primaryBorder);"
    "  --primary-border-hover: $($b.primaryBorderHover);"
    "  --primary-disabled-bg: $($b.primaryDisabledBg);"
    "  --primary-disabled-text: $($b.primaryDisabledText);"
    ''
    '  /* Neutral */'
    "  --canvas: $($n.canvas);"
    "  --surface: $($n.surface);"
    "  --surface-2: $($n.surface2);"
    "  --surface-subtle: $($n.surfaceSubtle);"
    "  --surface-hover: $($n.surfaceHover);"
    "  --row-hover: $($n.rowHover);"
    "  --ink: $($n.ink);"
    "  --muted: $($n.muted);"
    "  --muted-2: $($n.muted2);"
    "  --line: $($n.line);"
    "  --line-hover: $($n.lineHover);"
    "  --line-soft: $($n.lineSoft);"
    "  --dashed-border: $($n.dashedBorder);"
    "  --win-border: $($n.winBorder);"
    ''
    '  /* Semantic: Amber */'
    "  --amber: $($a.text);"
    "  --amber-bg: $($a.bg);"
    "  --amber-border: $($a.border);"
    "  --amber-bar: $($a.bar);"
    "  --amber-strong: $($a.strong);"
    ''
    '  /* Semantic: Red */'
    "  --red: $($r.text);"
    "  --red-bg: $($r.bg);"
    "  --red-bg-active: $($r.bgActive);"
    "  --red-border: $($r.border);"
    "  --red-border-hover: $($r.borderHover);"
    ''
    '  /* File Type Badges */'
    "  --ft-doc-bg: $($ft.doc.bg); --ft-doc-border: $($ft.doc.border); --ft-doc-fg: $($ft.doc.fg);"
    "  --ft-xls-bg: $($ft.xls.bg); --ft-xls-border: $($ft.xls.border); --ft-xls-fg: $($ft.xls.fg);"
    "  --ft-ppt-bg: $($ft.ppt.bg); --ft-ppt-border: $($ft.ppt.border); --ft-ppt-fg: $($ft.ppt.fg);"
    "  --ft-pdf-bg: $($ft.pdf.bg); --ft-pdf-border: $($ft.pdf.border); --ft-pdf-fg: $($ft.pdf.fg);"
    "  --ft-md-bg: $($ft.md.bg); --ft-md-border: $($ft.md.border); --ft-md-fg: $($ft.md.fg);"
    "  --ft-img-bg: $($ft.img.bg); --ft-img-border: $($ft.img.border); --ft-img-fg: $($ft.img.fg);"
    "  --ft-zip-bg: $($ft.zip.bg); --ft-zip-border: $($ft.zip.border); --ft-zip-fg: $($ft.zip.fg);"
    "  --ft-other-bg: $($ft.other.bg); --ft-other-border: $($ft.other.border); --ft-other-fg: $($ft.other.fg);"
    ''
    '  /* Marketing Surface Variant (产品介绍页 / 官网深色 Hero) */'
    "  --mkt-paper: $($m.paper);"
    "  --mkt-ink: $($m.ink);"
    "  --mkt-muted: $($m.muted);"
    "  --mkt-line: $($m.line);"
    "  --mkt-forest: $($m.forest);"
    "  --mkt-forest-glow: $($m.forestGlow);"
    "  --mkt-green: $($m.green);"
    "  --mkt-lime: $($m.lime);"
    "  --mkt-lime-hover: $($m.limeHover);"
    "  --mkt-on-dark: $($m.onDark);"
    "  --mkt-on-dark-title: $($m.onDarkTitle);"
    "  --mkt-on-lime: $($m.onLime);"
    "  --mkt-feature-band: $($m.featureBand);"
    "  --mkt-focus-ring: $($m.focusRing);"
    "  --mkt-focus-ring-dark: $($m.focusRingDark);"
    ''
    '  /* Typography */'
    "  --font-ui: $($ty.fontFamily.ui);"
    "  --font-mono: $($ty.fontFamily.mono);"
    "  --text-caption: $($ty.scale.caption.web);"
    "  --text-body-sm: $($ty.scale.bodySm.web);"
    "  --text-body: $($ty.scale.body.web);"
    "  --text-body-lg: $($ty.scale.bodyLg.web);"
    "  --text-title-sm: $($ty.scale.titleSm.web);"
    "  --text-title: $($ty.scale.title.web);"
    "  --text-brand: $($ty.scale.brand.web);"
    "  --text-headline: $($ty.scale.headline.web);"
    ''
    '  /* Radius */'
    "  --r-sm: $($rad.sm)px;"
    "  --r-md: $($rad.md)px;"
    "  --r-card: $($rad.card)px;"
    "  --r-lg: $($rad.lg)px;"
    "  --r-hero: $($rad.hero)px;"
    "  --r-pill: $($rad.pill)px;"
    ''
    '  /* Spacing */'
    "  --sp-xs: $($sp.xs)px;"
    "  --sp-sm: $($sp.sm)px;"
    "  --sp-md: $($sp.md)px;"
    "  --sp-lg: $($sp.lg)px;"
    "  --sp-xl: $($sp.xl)px;"
    "  --sp-2xl: $($sp.'2xl')px;"
    ''
    '  /* Sizing */'
    "  --h-btn: $($sz.buttonHeight)px;"
    "  --h-btn-sm: $($sz.buttonSmHeight)px;"
    "  --h-btn-side: $($sz.buttonSideHeight)px;"
    "  --h-input: $($sz.inputHeight)px;"
    "  --w-sidebar: $($sz.sidebarWidth)px;"
    "  --h-titlebar: $($sz.titlebarHeight)px;"
    "  --h-statusbar: $($sz.statusbarHeight)px;"
    "  --h-row: $($sz.tableRowHeight)px;"
    "  --h-badge: $($sz.badgeHeight)px;"
    ''
    '  /* Shadows */'
    "  --shadow-win: $($sh.window);"
    "  --shadow-dlg: $($sh.dialog);"
    "  --shadow-menu: $($sh.menu);"
    "  --shadow-card-hover: $($sh.cardHover);"
    "  --shadow-toast: $($sh.toast);"
    '}'
)
$generatedCss = ($cssLines -join "`n") + "`n"

$csTokenLines = @(
    '        // <design-tokens:start> (由 scripts/sync-design-tokens.ps1 自动生成，请勿手工修改)'
    "        internal const string FontFamilyName = ""$($ty.fontFamily.winForms)"";"
    "        internal const int RadiusSm = $($rad.sm);"
    "        internal const int RadiusMd = $($rad.md);"
    "        internal const int RadiusCard = $($rad.card);"
    ''
    "        internal static readonly Color Primary = $(ConvertTo-ArgbLiteral $b.primary);"
    "        internal static readonly Color PrimaryHover = $(ConvertTo-ArgbLiteral $b.primaryHover);"
    "        internal static readonly Color PrimaryActive = $(ConvertTo-ArgbLiteral $b.primaryActive);"
    "        internal static readonly Color PrimaryTint = $(ConvertTo-ArgbLiteral $b.primaryTint);"
    "        internal static readonly Color PrimaryTintHover = $(ConvertTo-ArgbLiteral $b.primaryTintHover);"
    "        internal static readonly Color PrimaryTintActive = $(ConvertTo-ArgbLiteral $b.primaryTintActive);"
    "        internal static readonly Color PrimaryBorder = $(ConvertTo-ArgbLiteral $b.primaryBorder);"
    "        internal static readonly Color PrimaryBorderHover = $(ConvertTo-ArgbLiteral $b.primaryBorderHover);"
    "        internal static readonly Color PrimaryDisabledBg = $(ConvertTo-ArgbLiteral $b.primaryDisabledBg);"
    "        internal static readonly Color PrimaryDisabledText = $(ConvertTo-ArgbLiteral $b.primaryDisabledText);"
    ''
    "        internal static readonly Color Canvas = $(ConvertTo-ArgbLiteral $n.canvas);"
    "        internal static readonly Color Surface = $(ConvertTo-ArgbLiteral $n.surface);"
    "        internal static readonly Color Surface2 = $(ConvertTo-ArgbLiteral $n.surface2);"
    "        internal static readonly Color SurfaceHover = $(ConvertTo-ArgbLiteral $n.surfaceHover);"
    "        internal static readonly Color Ink = $(ConvertTo-ArgbLiteral $n.ink);"
    "        internal static readonly Color Muted = $(ConvertTo-ArgbLiteral $n.muted);"
    "        internal static readonly Color Muted2 = $(ConvertTo-ArgbLiteral $n.muted2);"
    "        internal static readonly Color Line = $(ConvertTo-ArgbLiteral $n.line);"
    "        internal static readonly Color LineHover = $(ConvertTo-ArgbLiteral $n.lineHover);"
    "        internal static readonly Color LineSoft = $(ConvertTo-ArgbLiteral $n.lineSoft);"
    "        internal static readonly Color DashedBorder = $(ConvertTo-ArgbLiteral $n.dashedBorder);"
    ''
    "        internal static readonly Color Amber = $(ConvertTo-ArgbLiteral $a.text);"
    "        internal static readonly Color AmberBg = $(ConvertTo-ArgbLiteral $a.bg);"
    "        internal static readonly Color AmberBorder = $(ConvertTo-ArgbLiteral $a.border);"
    "        internal static readonly Color AmberBar = $(ConvertTo-ArgbLiteral $a.bar);"
    "        internal static readonly Color Red = $(ConvertTo-ArgbLiteral $r.text);"
    "        internal static readonly Color RedBg = $(ConvertTo-ArgbLiteral $r.bg);"
    "        internal static readonly Color RedBgActive = $(ConvertTo-ArgbLiteral $r.bgActive);"
    "        internal static readonly Color RedBorder = $(ConvertTo-ArgbLiteral $r.border);"
    "        internal static readonly Color RedBorderHover = $(ConvertTo-ArgbLiteral $r.borderHover);"
    ''
    "        internal static readonly Color FileDocBg = $(ConvertTo-ArgbLiteral $ft.doc.bg);"
    "        internal static readonly Color FileDocBorder = $(ConvertTo-ArgbLiteral $ft.doc.border);"
    "        internal static readonly Color FileDocFg = $(ConvertTo-ArgbLiteral $ft.doc.fg);"
    "        internal static readonly Color FileXlsBg = $(ConvertTo-ArgbLiteral $ft.xls.bg);"
    "        internal static readonly Color FileXlsBorder = $(ConvertTo-ArgbLiteral $ft.xls.border);"
    "        internal static readonly Color FileXlsFg = $(ConvertTo-ArgbLiteral $ft.xls.fg);"
    "        internal static readonly Color FilePptBg = $(ConvertTo-ArgbLiteral $ft.ppt.bg);"
    "        internal static readonly Color FilePptBorder = $(ConvertTo-ArgbLiteral $ft.ppt.border);"
    "        internal static readonly Color FilePptFg = $(ConvertTo-ArgbLiteral $ft.ppt.fg);"
    "        internal static readonly Color FilePdfBg = $(ConvertTo-ArgbLiteral $ft.pdf.bg);"
    "        internal static readonly Color FilePdfBorder = $(ConvertTo-ArgbLiteral $ft.pdf.border);"
    "        internal static readonly Color FilePdfFg = $(ConvertTo-ArgbLiteral $ft.pdf.fg);"
    "        internal static readonly Color FileMdBg = $(ConvertTo-ArgbLiteral $ft.md.bg);"
    "        internal static readonly Color FileMdBorder = $(ConvertTo-ArgbLiteral $ft.md.border);"
    "        internal static readonly Color FileMdFg = $(ConvertTo-ArgbLiteral $ft.md.fg);"
    "        internal static readonly Color FileImgBg = $(ConvertTo-ArgbLiteral $ft.img.bg);"
    "        internal static readonly Color FileImgBorder = $(ConvertTo-ArgbLiteral $ft.img.border);"
    "        internal static readonly Color FileImgFg = $(ConvertTo-ArgbLiteral $ft.img.fg);"
    "        internal static readonly Color FileZipBg = $(ConvertTo-ArgbLiteral $ft.zip.bg);"
    "        internal static readonly Color FileZipBorder = $(ConvertTo-ArgbLiteral $ft.zip.border);"
    "        internal static readonly Color FileZipFg = $(ConvertTo-ArgbLiteral $ft.zip.fg);"
    "        internal static readonly Color FileOtherBg = $(ConvertTo-ArgbLiteral $ft.other.bg);"
    "        internal static readonly Color FileOtherBorder = $(ConvertTo-ArgbLiteral $ft.other.border);"
    "        internal static readonly Color FileOtherFg = $(ConvertTo-ArgbLiteral $ft.other.fg);"
    '        // <design-tokens:end>'
)

$csContent = [IO.File]::ReadAllText($csPath, [Text.UTF8Encoding]::new($false))
$csNewline = if ($csContent.Contains("`r`n")) { "`r`n" } else { "`n" }
$generatedCsBlock = $csTokenLines -join $csNewline

$pattern = '(?s)        // <design-tokens:start>.*?        // <design-tokens:end>'
if (-not [regex]::IsMatch($csContent, $pattern)) {
    throw "未在 src/FolderSeal.cs 中找到 // <design-tokens:start> ... // <design-tokens:end> 标记区块。"
}
$updatedCsContent = [regex]::Replace($csContent, $pattern, [Text.RegularExpressions.MatchEvaluator]{ param($m) $generatedCsBlock }, 1)

if ($Check) {
    $drifted = @()
    if (-not (Test-Path -LiteralPath $cssPath)) {
        $drifted += 'docs/品牌设计/设计系统/tokens.css（缺失）'
    } else {
        $currentCss = ([IO.File]::ReadAllText($cssPath, [Text.UTF8Encoding]::new($false))) -replace "`r`n", "`n"
        if ($currentCss -ne $generatedCss) { $drifted += 'docs/品牌设计/设计系统/tokens.css' }
    }
    if ($csContent -ne $updatedCsContent) {
        $drifted += 'src/FolderSeal.cs'
    }
    if ($drifted.Count -gt 0) {
        throw "以下文件与 tokens.json 不同步，请运行 .\scripts\sync-design-tokens.ps1：`n - $($drifted -join "`n - ")"
    }
    Write-Output '设计系统 Token 校验通过：tokens.css 与 src/FolderSeal.cs 均与 tokens.json 一致。'
    exit 0
}

[IO.File]::WriteAllText($cssPath, $generatedCss, [Text.UTF8Encoding]::new($false))
$csHasBom = ([IO.File]::ReadAllBytes($csPath) | Select-Object -First 3) -join ',' -eq '239,187,191'
[IO.File]::WriteAllText($csPath, $updatedCsContent, [Text.UTF8Encoding]::new($csHasBom))

Write-Output '已同步设计系统 Token：'
Write-Output ' - docs/品牌设计/设计系统/tokens.css'
Write-Output ' - src/FolderSeal.cs (UiTheme)'

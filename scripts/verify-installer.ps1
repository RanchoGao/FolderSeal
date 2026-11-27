# Copyright (c) 2026 EurekaGao. MIT License.
# 管理员 PowerShell 中运行：验证安装包在干净临时目录中的安装、重复安装与卸载行为。
[CmdletBinding()]
param(
    [string]$SetupPath,
    [ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ExpectedPayloadSha256
)
$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path -Parent $PSScriptRoot
$taskArtifacts = Join-Path $taskRoot 'artifacts'
$taskReport = Join-Path $taskArtifacts 'installer-test.json'
$taskRegistry = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\EurekaGao.FolderSeal'
$taskChecks = [System.Collections.Generic.List[string]]::new()
$taskFixture = Join-Path $taskArtifacts ('.setup-test-' + [guid]::NewGuid().ToString('N'))
$taskInstall = Join-Path $taskFixture '含空格 安装目录'
$taskPrograms = Join-Path ([Environment]::GetFolderPath('CommonPrograms')) 'EurekaGao\密封夹'
$taskLegacyPrograms = Join-Path ([Environment]::GetFolderPath('CommonPrograms')) 'EurekaGao\文件夹加密工具'
$taskDesktop = [Environment]::GetFolderPath('CommonDesktopDirectory')
$taskDesktopLink = Join-Path $taskDesktop '密封夹.lnk'
$taskLegacyDesktopLink = Join-Path $taskDesktop '文件夹加密工具（EurekaGao）.lnk'
$taskMenuEntries = [ordered]@{'密封夹.lnk' = 'FolderSeal.exe'; '使用说明.lnk' = '使用说明.txt'; '卸载.lnk' = 'Uninstall.exe'}
if (-not $SetupPath) {
    $taskSetup = Get-ChildItem -LiteralPath (Join-Path $taskArtifacts 'dist') -Filter 'FolderSeal-*-Setup.exe' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $taskSetup) { throw '未找到安装包，请先运行 scripts\package.ps1。' }
    $SetupPath = $taskSetup.FullName
}
$taskInstaller = [IO.Path]::GetFullPath($SetupPath)
if (-not (Test-Path -LiteralPath $taskInstaller -PathType Leaf)) { throw "安装包不存在：$taskInstaller" }
$taskVersion = [regex]::Match([IO.Path]::GetFileName($taskInstaller), '^FolderSeal-(\d+\.\d+\.\d+)-Setup\.exe$').Groups[1].Value
if (-not $taskVersion) { throw '安装包文件名不符合 FolderSeal-<版本>-Setup.exe 规则。' }
if (-not $ExpectedPayloadSha256) {
    $taskOriginal = Join-Path $taskArtifacts 'bin\FolderSeal.exe'
    if (-not (Test-Path -LiteralPath $taskOriginal -PathType Leaf)) { throw '缺少打包时的程序，请指定 -ExpectedPayloadSha256。' }
    $ExpectedPayloadSha256 = (Get-FileHash -LiteralPath $taskOriginal).Hash
}
function Assert-Test([bool]$condition, [string]$message) {
    if (-not $condition) { throw $message }
    $taskChecks.Add($message)
}
function Invoke-WithTimeout([string]$filePath, [string[]]$arguments, [int]$timeoutMs, [string]$label) {
    $proc = Start-Process -FilePath $filePath -ArgumentList $arguments -WindowStyle Hidden -PassThru
    if (-not $proc.WaitForExit($timeoutMs)) {
        try { $proc.Kill() } catch { }
        throw "$label 超时未退出（超过 ${timeoutMs}ms，可能弹出阻塞窗口）。"
    }
    return $proc.ExitCode
}
$taskShellKeys = @(
    'HKCU:\Software\Classes\Directory\shell\FolderSeal.Seal',
    'HKCU:\Software\Classes\*\shell\FolderSeal.Seal',
    'HKCU:\Software\Classes\Directory\shell\FolderSeal.Open'
)
New-Item -ItemType Directory -Path $taskArtifacts -Force | Out-Null
try {
    if (-not ([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw '安装包验证需要管理员授权。' }
    if (Test-Path -LiteralPath $taskRegistry) { throw '已存在正式安装，停止测试以免影响现有软件。' }
    if ((Test-Path -LiteralPath $taskPrograms) -or (Test-Path -LiteralPath $taskLegacyPrograms)) { throw '开始菜单中已有同名软件，停止测试。' }
    if ((Test-Path -LiteralPath $taskDesktopLink) -or (Test-Path -LiteralPath $taskLegacyDesktopLink)) { throw '公共桌面中已有同名快捷方式，停止测试。' }
    New-Item -ItemType Directory -Path $taskFixture | Out-Null
    $taskBadDir = Join-Path $taskFixture 'non-empty-unrelated'
    New-Item -ItemType Directory -Path $taskBadDir | Out-Null
    [IO.File]::WriteAllText((Join-Path $taskBadDir 'unrelated.txt'), 'unrelated')
    $badCode = Invoke-WithTimeout $taskInstaller @('/S', "/D=$taskBadDir") 15000 '非空无关目录静默安装'
    Assert-Test ($badCode -ne 0 -and -not (Test-Path -LiteralPath (Join-Path $taskBadDir 'FolderSeal.exe'))) '静默安装到非空无关目录快速失败且无弹窗阻塞'
    $installCode = Invoke-WithTimeout $taskInstaller @('/S', "/D=$taskInstall") 60000 '静默安装'
    Assert-Test ($installCode -eq 0) '静默安装成功'
    Assert-Test (Test-Path -LiteralPath (Join-Path $taskInstall 'FolderSeal.exe')) '支持包含中文和空格的安装路径'
    Assert-Test ((Get-FileHash -LiteralPath (Join-Path $taskInstall 'FolderSeal.exe')).Hash -eq $ExpectedPayloadSha256) '安装后程序与指定的打包程序逐字节一致'
    Assert-Test (Test-Path -LiteralPath (Join-Path $taskInstall 'Uninstall.exe')) '卸载程序已生成'
    Assert-Test (Test-Path -LiteralPath (Join-Path $taskInstall '使用说明.txt')) '中文使用说明已安装'
    Assert-Test (Test-Path -LiteralPath (Join-Path $taskInstall 'LICENSE')) 'MIT 许可证文件已安装'
    Assert-Test ((Get-Content -LiteralPath (Join-Path $taskInstall '.folderseal-product') -Raw).Trim() -ceq 'EurekaGao.FolderSeal.v1') '产品标记文件已生成且内容正确'
    foreach ($shellKey in $taskShellKeys) {
        Assert-Test (Test-Path -LiteralPath $shellKey) "已注册资源管理器右键菜单：$shellKey"
    }
    $taskEntry = Get-ItemProperty -LiteralPath $taskRegistry
    Assert-Test ($taskEntry.Publisher -eq 'EurekaGao' -and $taskEntry.DisplayVersion -eq $taskVersion) "应用列表中的发布者和版本正确（$taskVersion）"
    Assert-Test ($taskEntry.UninstallString -eq ('"' + (Join-Path $taskInstall 'Uninstall.exe') + '"')) '卸载入口正确处理带空格路径'
    $taskShell = New-Object -ComObject WScript.Shell
    Assert-Test ($taskEntry.DisplayName -eq '密封夹') '应用列表显示中文产品名'
    foreach ($taskName in $taskMenuEntries.Keys) {
        $taskPath = Join-Path $taskPrograms $taskName
        Assert-Test (Test-Path -LiteralPath $taskPath -PathType Leaf) "已创建开始菜单入口 $taskName"
        $taskLink = $taskShell.CreateShortcut($taskPath)
        Assert-Test ($taskLink.TargetPath -eq (Join-Path $taskInstall $taskMenuEntries[$taskName]) -and $taskLink.Arguments -eq '') "开始菜单入口 $taskName 的目标和参数正确"
    }
    $taskPersonal = Join-Path $taskInstall '模拟用户资料（验证样例）'
    New-Item -ItemType Directory -Path $taskPersonal | Out-Null
    $taskSentinel = Join-Path $taskPersonal '内容.egvault'
    [IO.File]::WriteAllText($taskSentinel, 'Generated installer fixture; not personal data.')
    $taskSentinelHash = (Get-FileHash -LiteralPath $taskSentinel).Hash
    $taskLink = $taskShell.CreateShortcut($taskLegacyDesktopLink)
    $taskLink.TargetPath = Join-Path $taskInstall 'FolderSeal.exe'
    $taskLink.Save()
    $reinstallCode = Invoke-WithTimeout $taskInstaller @('/S', "/D=$taskInstall") 60000 '重复静默安装'
    Assert-Test ($reinstallCode -eq 0 -and (Get-FileHash -LiteralPath $taskSentinel).Hash -eq $taskSentinelHash) '重复安装保留安装目录中的非程序文件'
    Assert-Test ((Test-Path -LiteralPath $taskDesktopLink -PathType Leaf) -and -not (Test-Path -LiteralPath $taskLegacyDesktopLink)) '旧桌面入口已迁移至当前名称'
    Assert-Test ($taskShell.CreateShortcut($taskDesktopLink).TargetPath -eq (Join-Path $taskInstall 'FolderSeal.exe')) '迁移后的桌面入口指向已安装程序'
    $uninstallCode = Invoke-WithTimeout (Join-Path $taskInstall 'Uninstall.exe') @('/S') 60000 '静默卸载'
    Assert-Test ($uninstallCode -eq 0) '静默卸载正常退出'
    for ($taskAttempt = 0; $taskAttempt -lt 40 -and (Test-Path -LiteralPath $taskRegistry); $taskAttempt++) { Start-Sleep -Milliseconds 200 }
    Assert-Test (-not (Test-Path -LiteralPath (Join-Path $taskInstall 'FolderSeal.exe'))) '卸载移除程序'
    Assert-Test (-not (Test-Path -LiteralPath (Join-Path $taskInstall 'LICENSE'))) '卸载移除许可证文件'
    Assert-Test (-not (Test-Path -LiteralPath $taskRegistry)) '卸载清除应用列表入口'
    Assert-Test (-not (Test-Path -LiteralPath $taskDesktopLink)) '卸载清除当前桌面入口'
    foreach ($shellKey in $taskShellKeys) {
        Assert-Test (-not (Test-Path -LiteralPath $shellKey)) "卸载清除资源管理器右键菜单：$shellKey"
    }
    foreach ($taskName in $taskMenuEntries.Keys) {
        Assert-Test (-not (Test-Path -LiteralPath (Join-Path $taskPrograms $taskName))) "卸载清除开始菜单入口 $taskName"
    }
    Assert-Test ((Test-Path -LiteralPath $taskSentinel) -and (Get-FileHash -LiteralPath $taskSentinel).Hash -eq $taskSentinelHash) '卸载保留非程序文件及模拟加密资料'
    [ordered]@{ Passed = $true; Version = $taskVersion; Checks = $taskChecks.ToArray(); CheckCount = $taskChecks.Count; InstallerSHA256 = (Get-FileHash -LiteralPath $taskInstaller).Hash; PayloadSHA256 = $ExpectedPayloadSha256; TestedAt = (Get-Date).ToString('s') } |
        ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $taskReport -Encoding utf8
    $taskResolved = [IO.Path]::GetFullPath($taskFixture)
    if (-not ([IO.Path]::GetDirectoryName($taskResolved)).Equals([IO.Path]::GetFullPath($taskArtifacts), [StringComparison]::OrdinalIgnoreCase) -or ([IO.Path]::GetFileName($taskResolved)) -notmatch '^\.setup-test-[a-f0-9]{32}$') { throw '样例清理路径越界。' }
    $taskLinks = @(Get-ChildItem -LiteralPath $taskResolved -Force -Recurse | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint })
    if ($taskLinks.Count -gt 0) { throw '样例包含链接，停止清理。' }
    Remove-Item -LiteralPath $taskResolved -Recurse -Force
    exit 0
}
catch {
    $cleanupError = $null
    try {
        $uninst = Join-Path $taskInstall 'Uninstall.exe'
        if ((Test-Path -LiteralPath $uninst) -and (Test-Path -LiteralPath $taskRegistry)) {
            $p = Start-Process -FilePath $uninst -ArgumentList '/S' -WindowStyle Hidden -PassThru
            if (-not $p.WaitForExit(30000)) { try { $p.Kill() } catch { } }
            for ($i = 0; $i -lt 25 -and (Test-Path -LiteralPath $taskRegistry); $i++) { Start-Sleep -Milliseconds 200 }
        }
        if (Test-Path -LiteralPath $taskDesktopLink) { Remove-Item -LiteralPath $taskDesktopLink -Force -ErrorAction SilentlyContinue }
        if (Test-Path -LiteralPath $taskLegacyDesktopLink) { Remove-Item -LiteralPath $taskLegacyDesktopLink -Force -ErrorAction SilentlyContinue }
        if (Test-Path -LiteralPath $taskPrograms) { Remove-Item -LiteralPath $taskPrograms -Recurse -Force -ErrorAction SilentlyContinue }
    }
    catch { $cleanupError = $_.Exception.Message }
    [ordered]@{ Passed = $false; Checks = $taskChecks.ToArray(); Error = $_.Exception.Message; CleanupError = $cleanupError; Fixture = $taskFixture } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $taskReport -Encoding utf8
    exit 1
}

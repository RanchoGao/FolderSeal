# Copyright (c) 2026 EurekaGao. MIT License.
[CmdletBinding()]
param([string]$NsisCompiler, [switch]$ValidateAll, [switch]$SkipBuild)
$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path -Parent $PSScriptRoot
if (-not $NsisCompiler) {
    $taskPortable = Join-Path $taskRoot 'tools\nsis-3.13\makensis.exe'
    if (Test-Path -LiteralPath $taskPortable) {
        $NsisCompiler = $taskPortable
    } else {
        $taskCommand = Get-Command makensis.exe -ErrorAction SilentlyContinue
        if ($taskCommand) { $NsisCompiler = $taskCommand.Source }
    }
}
if (-not $NsisCompiler -or -not (Test-Path -LiteralPath $NsisCompiler -PathType Leaf)) {
    throw '请安装 NSIS（已验证版本 3.13），放入 tools\nsis-3.13\，或通过 -NsisCompiler 指定 makensis.exe 的完整路径。'
}
$NsisCompiler = (Resolve-Path -LiteralPath $NsisCompiler).Path
$taskInstallerScript = Join-Path $taskRoot 'installer\FolderSeal.nsi'
$taskVersion = [regex]::Match((Get-Content -LiteralPath $taskInstallerScript -Raw), '!define VERSION "([^"]+)"').Groups[1].Value
if (-not $taskVersion) { throw '无法从 installer/FolderSeal.nsi 读取 VERSION。' }
if ($SkipBuild) {
    $taskBinary = Join-Path $taskRoot 'artifacts\bin\FolderSeal.exe'
    if (-not (Test-Path -LiteralPath $taskBinary -PathType Leaf)) {
        throw '使用 -SkipBuild 时未找到 artifacts\bin\FolderSeal.exe，请先运行 scripts/build.ps1。'
    }
} else {
    # Always compile from this checkout before packaging; do not package a stale EXE.
    if ($ValidateAll) {
        & (Join-Path $PSScriptRoot 'build.ps1') -ValidateAll
    } else {
        & (Join-Path $PSScriptRoot 'build.ps1')
    }
}
$taskDist = Join-Path $taskRoot 'artifacts\dist'
New-Item -ItemType Directory -Path $taskDist -Force | Out-Null
& $NsisCompiler /INPUTCHARSET UTF8 /V2 /WX "/DPROJECT_ROOT=$taskRoot" $taskInstallerScript
if ($LASTEXITCODE -ne 0) { throw '安装包编译失败。' }
$taskInstaller = Join-Path $taskDist "FolderSeal-$taskVersion-Setup.exe"
$taskHash = Get-FileHash -LiteralPath $taskInstaller -Algorithm SHA256
"$($taskHash.Hash)  $([IO.Path]::GetFileName($taskInstaller))" | Set-Content -LiteralPath (Join-Path $taskDist 'SHA256SUMS.txt') -Encoding ascii
Get-Item -LiteralPath $taskInstaller | Select-Object FullName, Length
Write-Output "发布时把安装包和 SHA256SUMS.txt 复制到 releases\$taskVersion\。"

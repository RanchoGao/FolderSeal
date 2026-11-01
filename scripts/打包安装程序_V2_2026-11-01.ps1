# Copyright (c) 2026 EurekaGao. MIT License.
[CmdletBinding()]
param([string]$NsisCompiler)
$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path -Parent $PSScriptRoot
if (-not $NsisCompiler) {
    $taskCommand = Get-Command makensis.exe -ErrorAction SilentlyContinue
    if ($taskCommand) { $NsisCompiler = $taskCommand.Source }
}
if (-not $NsisCompiler -or -not (Test-Path -LiteralPath $NsisCompiler -PathType Leaf)) {
    throw '请安装 NSIS（已验证版本 3.13），通过 -NsisCompiler 指定 makensis.exe 的完整路径，或将其加入 PATH。'
}
$NsisCompiler = (Resolve-Path -LiteralPath $NsisCompiler).Path
# Always compile from this checkout before packaging; do not package a stale EXE.
& (Join-Path $PSScriptRoot '构建_V2_2026-11-01.ps1')
$taskDist = Join-Path $taskRoot 'dist'
New-Item -ItemType Directory -Path $taskDist -Force | Out-Null
& $NsisCompiler /INPUTCHARSET UTF8 /V2 "/DPROJECT_ROOT=$taskRoot" (Join-Path $taskRoot 'installer\安装脚本_V1_2026-11-01.nsi')
if ($LASTEXITCODE -ne 0) { throw '安装包编译失败。' }
$taskInstaller = Join-Path $taskDist 'FolderSeal-2.1.0-Setup.exe'
$taskHash = Get-FileHash -LiteralPath $taskInstaller -Algorithm SHA256
"$($taskHash.Hash)  $([IO.Path]::GetFileName($taskInstaller))" | Set-Content -LiteralPath "$taskInstaller.sha256" -Encoding ascii
Get-Item -LiteralPath $taskInstaller | Select-Object Name, Length
# Copyright (c) 2026 EurekaGao. MIT License.
[CmdletBinding()]
param([switch]$Validate, [switch]$ValidateEntry, [switch]$ValidateAcl)
$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path -Parent $PSScriptRoot
$taskCompiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path -LiteralPath $taskCompiler)) {
    $taskCompiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe'
}
if (-not (Test-Path -LiteralPath $taskCompiler)) { throw '未找到 .NET Framework C# 编译器；需要 Windows 和 .NET Framework 4.7.2 或更新版本。' }
if ($ValidateAcl -and -not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw '权限验证需要管理员 PowerShell。请在管理员终端中重新运行 -ValidateAcl。'
}
$taskOutput = Join-Path $taskRoot 'artifacts\bin'
$taskTestParent = Join-Path $taskRoot 'artifacts\test-work'
New-Item -ItemType Directory -Path $taskOutput, $taskTestParent -Force | Out-Null
$taskSource = Join-Path $taskRoot 'src\文件夹加密工具_V1_2026-11-01.cs'
$taskManifest = Join-Path $taskRoot 'src\程序清单_V1_2026-11-01.manifest'
$taskReferences = @('/r:System.dll','/r:System.Core.dll','/r:System.Drawing.dll','/r:System.Windows.Forms.dll','/r:System.Security.dll','/r:System.IO.Compression.dll','/r:System.IO.Compression.FileSystem.dll')
& $taskCompiler /nologo /optimize+ /target:winexe /platform:anycpu "/win32manifest:$taskManifest" "/out:$taskOutput\FolderSeal.exe" @taskReferences $taskSource
if ($LASTEXITCODE -ne 0) { throw '程序编译失败。' }
& $taskCompiler /nologo /optimize+ /target:exe /main:FolderSeal.Tests "/out:$taskOutput\FolderSeal.Tests.exe" @taskReferences $taskSource (Join-Path $taskRoot 'tests\核心验证_V2_2026-11-01.cs')
if ($LASTEXITCODE -ne 0) { throw '核心验证程序编译失败。' }
& $taskCompiler /nologo /optimize+ /target:exe /main:EntryTests "/out:$taskOutput\FolderSeal.EntryTests.exe" @taskReferences $taskSource (Join-Path $taskRoot 'tests\入口验证_V1_2026-11-01.cs')
if ($LASTEXITCODE -ne 0) { throw '入口验证程序编译失败。' }
if ($Validate) {
    & "$taskOutput\FolderSeal.Tests.exe" $taskTestParent
    if ($LASTEXITCODE -ne 0) { throw '核心验证失败；生成的样例保留在 artifacts/test-work 中。' }
}
if ($ValidateEntry) {
    & "$taskOutput\FolderSeal.EntryTests.exe" $taskTestParent
    if ($LASTEXITCODE -ne 0) { throw '入口验证失败；生成的样例保留在 artifacts/test-work 中。' }
}
if ($ValidateAcl) {
    & "$taskOutput\FolderSeal.Tests.exe" $taskTestParent --acl
    if ($LASTEXITCODE -ne 0) { throw '权限验证失败；请检查 artifacts/test-work 中的报告与样例。' }
}
Write-Output "已生成：$taskOutput\FolderSeal.exe"
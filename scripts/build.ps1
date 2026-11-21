# Copyright (c) 2026 EurekaGao. MIT License.
[CmdletBinding()]
param([switch]$Validate, [switch]$ValidateEntry, [switch]$ValidateAcl, [switch]$ValidateUi, [switch]$ValidateIcon, [switch]$ValidateInstance, [switch]$ValidateLibrary, [switch]$ValidateDiscovery, [switch]$ValidateUpdate, [switch]$ValidateShell)
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
$taskSource = Join-Path $taskRoot 'src\FolderSeal.cs'
$taskManifest = Join-Path $taskRoot 'src\FolderSeal.manifest'
$taskVersion = [regex]::Match([IO.File]::ReadAllText((Join-Path $taskRoot 'installer\FolderSeal.nsi')), '!define VERSION "([^\"]+)"').Groups[1].Value
if (-not $taskVersion) { throw 'Missing VERSION in installer definition.' }
$taskVersionSource = Join-Path $taskOutput 'VersionInfo.cs'
$taskVersionText = @"
using System.Reflection;
[assembly: AssemblyVersion("$taskVersion.0")]
[assembly: AssemblyFileVersion("$taskVersion.0")]
[assembly: AssemblyProduct("密封夹")]
[assembly: AssemblyTitle("密封夹")]
[assembly: AssemblyDescription("密封夹 · 本地文件夹加密工具")]
[assembly: AssemblyCompany("EurekaGao")]
[assembly: AssemblyCopyright("Copyright (c) EurekaGao")]
"@
[IO.File]::WriteAllText($taskVersionSource, $taskVersionText, [Text.UTF8Encoding]::new($true))
$taskIcon = Join-Path $taskRoot 'assets\FolderSeal.ico'
$taskBranding = @("/win32icon:$taskIcon", "/resource:$taskIcon,FolderSeal.AppIcon", $taskVersionSource)
$taskReferences = @('/r:System.dll','/r:System.Core.dll','/r:System.Drawing.dll','/r:System.Windows.Forms.dll','/r:System.Security.dll','/r:System.IO.Compression.dll','/r:System.IO.Compression.FileSystem.dll','/r:System.Runtime.Serialization.dll')
& $taskCompiler /nologo /optimize+ /target:winexe /platform:anycpu "/win32manifest:$taskManifest" "/out:$taskOutput\FolderSeal.exe" @taskReferences @taskBranding $taskSource
if ($LASTEXITCODE -ne 0) { throw '程序编译失败。' }
& $taskCompiler /nologo /optimize+ /target:exe /main:FolderSeal.Tests "/out:$taskOutput\FolderSeal.Tests.exe" @taskReferences @taskBranding $taskSource (Join-Path $taskRoot 'tests\CoreTests.cs')
if ($LASTEXITCODE -ne 0) { throw '核心验证程序编译失败。' }
& $taskCompiler /nologo /optimize+ /target:exe /main:EntryTests "/out:$taskOutput\FolderSeal.EntryTests.exe" @taskReferences @taskBranding $taskSource (Join-Path $taskRoot 'tests\EntryTests.cs')
if ($LASTEXITCODE -ne 0) { throw '入口验证程序编译失败。' }
if ($Validate) {
    & "$taskOutput\FolderSeal.Tests.exe" $taskTestParent
    if ($LASTEXITCODE -ne 0) { throw '核心验证失败；生成的样例保留在 artifacts/test-work 中。' }
}
if ($ValidateEntry) {
    & "$taskOutput\FolderSeal.EntryTests.exe" $taskTestParent
    if ($LASTEXITCODE -ne 0) { throw '入口验证失败；生成的样例保留在 artifacts/test-work 中。' }
}
if ($ValidateUi) {
    & $taskCompiler /nologo /optimize+ /target:exe /main:UiTests "/out:$taskOutput\FolderSeal.UiTests.exe" @taskReferences @taskBranding $taskSource (Join-Path $taskRoot 'tests\UiTests.cs')
    if ($LASTEXITCODE -ne 0) { throw '界面验证程序编译失败。' }
    & "$taskOutput\FolderSeal.UiTests.exe" $taskTestParent
    if ($LASTEXITCODE -ne 0) { throw '界面验证失败；生成的样例保留在 artifacts/test-work 中。' }
}
if ($ValidateIcon) {
    & $taskCompiler /nologo /optimize+ /target:exe "/out:$taskOutput\FolderSeal.IconTests.exe" /r:System.Drawing.dll /r:System.Core.dll (Join-Path $taskRoot 'tests\IconTests.cs')
    if ($LASTEXITCODE -ne 0) { throw 'Icon verification compile failed.' }
    & "$taskOutput\FolderSeal.IconTests.exe" $taskIcon "$taskOutput\FolderSeal.exe" (Join-Path $taskTestParent 'icon-preview')
    if ($LASTEXITCODE -ne 0) { throw 'Icon verification failed.' }
}
if ($ValidateInstance) {
    & $taskCompiler /nologo /optimize+ /target:exe /main:SingleInstanceTests "/out:$taskOutput\FolderSeal.SingleInstanceTests.exe" @taskReferences @taskBranding $taskSource (Join-Path $taskRoot 'tests\SingleInstanceTests.cs')
    if ($LASTEXITCODE -ne 0) { throw 'Single-instance verification compile failed.' }
    & "$taskOutput\FolderSeal.SingleInstanceTests.exe" $taskTestParent
    if ($LASTEXITCODE -ne 0) { throw 'Single-instance verification failed.' }
}
if ($ValidateDiscovery) {
    & $taskCompiler /nologo /optimize+ /target:exe /main:DiscoveryTests "/out:$taskOutput\FolderSeal.DiscoveryTests.exe" @taskReferences @taskBranding $taskSource (Join-Path $taskRoot 'tests\DiscoveryTests.cs')
    if ($LASTEXITCODE -ne 0) { throw '扫描过滤验证编译失败。' }
    & "$taskOutput\FolderSeal.DiscoveryTests.exe" $taskTestParent
    if ($LASTEXITCODE -ne 0) { throw '扫描过滤验证失败；样例保留在 artifacts/test-work。' }
}
if ($ValidateLibrary) {
    & $taskCompiler /nologo /optimize+ /target:exe /main:LibraryTests "/out:$taskOutput\FolderSeal.LibraryTests.exe" @taskReferences @taskBranding $taskSource (Join-Path $taskRoot 'tests\LibraryTests.cs')
    if ($LASTEXITCODE -ne 0) { throw '文件夹管理验证程序编译失败。' }
    & "$taskOutput\FolderSeal.LibraryTests.exe" $taskTestParent
    if ($LASTEXITCODE -ne 0) { throw '文件夹管理验证失败；样例保留在 artifacts/test-work 中。' }
}
if ($ValidateUpdate) {
    & $taskCompiler /nologo /optimize+ /target:exe /main:UpdateTests "/out:$taskOutput\FolderSeal.UpdateTests.exe" @taskReferences @taskBranding $taskSource (Join-Path $taskRoot 'tests\UpdateTests.cs')
    if ($LASTEXITCODE -ne 0) { throw '升级检测验证编译失败。' }
    & "$taskOutput\FolderSeal.UpdateTests.exe"
    if ($LASTEXITCODE -ne 0) { throw '升级检测验证失败。' }
}
if ($ValidateAcl) {
    & "$taskOutput\FolderSeal.Tests.exe" $taskTestParent --acl
    if ($LASTEXITCODE -ne 0) { throw '权限验证失败；请检查 artifacts/test-work 中的报告与样例。' }
}
if ($ValidateShell) {
    & $taskCompiler /nologo /optimize+ /target:exe /main:ShellTests "/out:$taskOutput\FolderSeal.ShellTests.exe" @taskReferences @taskBranding $taskSource (Join-Path $taskRoot 'tests\ShellTests.cs')
    if ($LASTEXITCODE -ne 0) { throw '右键菜单验证程序编译失败。' }
    & "$taskOutput\FolderSeal.ShellTests.exe" $taskTestParent
    if ($LASTEXITCODE -ne 0) { throw '右键菜单验证失败；样例保留在 artifacts/test-work 中。' }
}

Write-Output "已生成：$taskOutput\FolderSeal.exe"

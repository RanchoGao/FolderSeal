# Copyright (c) 2026 EurekaGao. Build a portable package from this checkout.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path -Parent $PSScriptRoot
$taskDefinition = Join-Path $taskRoot 'installer\FolderSeal.nsi'
$taskVersion = [regex]::Match((Get-Content -LiteralPath $taskDefinition -Raw -Encoding UTF8), '!define VERSION "([^"]+)"').Groups[1].Value
if (-not $taskVersion) { throw '无法读取版本号。' }
& (Join-Path $PSScriptRoot 'build.ps1')
$taskDist = Join-Path $taskRoot 'artifacts\dist'
$taskStageParent = Join-Path $taskRoot ('artifacts\portable-' + [guid]::NewGuid().ToString('N'))
$taskStage = Join-Path $taskStageParent 'FolderSeal'
New-Item -ItemType Directory -Path $taskDist, $taskStage -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $taskRoot 'artifacts\bin\FolderSeal.exe') -Destination $taskStage
foreach ($taskDocument in @('便携版说明.txt', '使用说明.md', '安全边界.md', '安装说明.md')) {
    Copy-Item -LiteralPath (Join-Path $taskRoot ('docs\' + $taskDocument)) -Destination $taskStage
}
Copy-Item -LiteralPath (Join-Path $taskRoot 'LICENSE') -Destination $taskStage
$taskArchive = Join-Path $taskDist "FolderSeal-$taskVersion-Portable.zip"
Compress-Archive -LiteralPath $taskStage -DestinationPath $taskArchive -Force
Add-Type -AssemblyName System.IO.Compression.FileSystem
$taskZip = [IO.Compression.ZipFile]::OpenRead($taskArchive)
try {
    $taskExpected = @('FolderSeal.exe', '便携版说明.txt', '使用说明.md', '安全边界.md', '安装说明.md', 'LICENSE')
    $taskEntries = @($taskZip.Entries | Where-Object { $_.Name })
    if ($taskEntries.Count -ne $taskExpected.Count) { throw '便携包文件数量不符。' }
    foreach ($taskName in $taskExpected) {
        $taskEntry = $taskEntries | Where-Object { $_.FullName.Replace('\', '/') -eq ('FolderSeal/' + $taskName) }
        if (-not $taskEntry -or $taskEntry.Length -eq 0) { throw "便携包缺失或空文件：$taskName" }
    }
    $taskPayload = $taskEntries | Where-Object { $_.Name -eq 'FolderSeal.exe' }
    $taskHashAlgorithm = [Security.Cryptography.SHA256]::Create()
    $taskStream = $taskPayload.Open()
    try { $taskPayloadHash = [BitConverter]::ToString($taskHashAlgorithm.ComputeHash($taskStream)).Replace('-', '') }
    finally { $taskStream.Dispose(); $taskHashAlgorithm.Dispose() }
    if ($taskPayloadHash -ne (Get-FileHash -LiteralPath (Join-Path $taskStage 'FolderSeal.exe') -Algorithm SHA256).Hash) { throw '压缩包内程序与当前构建不一致。' }
} finally { $taskZip.Dispose() }
$taskHash = Get-FileHash -LiteralPath $taskArchive -Algorithm SHA256
"$($taskHash.Hash)  $([IO.Path]::GetFileName($taskArchive))" | Set-Content -LiteralPath (Join-Path $taskDist 'PORTABLE-SHA256SUMS.txt') -Encoding ascii
Get-Item -LiteralPath $taskArchive | Select-Object FullName, Length
Write-Output '便携包文件清单与程序 SHA-256 校验通过。'

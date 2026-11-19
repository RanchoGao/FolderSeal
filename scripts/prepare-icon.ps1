# Copyright (c) 2026 EurekaGao. Convert the supplied artwork to a Windows icon.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path -Parent $PSScriptRoot
Add-Type -AssemblyName System.Drawing
Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class FolderSealIconNative {
    [DllImport("user32.dll")] public static extern bool DestroyIcon(IntPtr icon);
}
'@
$taskSource = [Drawing.Image]::FromFile((Join-Path $taskRoot 'assets\FolderSeal.png'))
$taskFrames = @()
try {
    foreach ($taskSize in @(16, 24, 32, 48, 64, 128, 256)) {
        $taskBitmap = [Drawing.Bitmap]::new($taskSize, $taskSize)
        $taskGraphics = [Drawing.Graphics]::FromImage($taskBitmap)
        $taskMemory = [IO.MemoryStream]::new()
        $taskHandle = [IntPtr]::Zero
        $taskIcon = $null
        try {
            $taskGraphics.InterpolationMode = [Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
            $taskGraphics.DrawImage($taskSource, 0, 0, $taskSize, $taskSize)
            $taskHandle = $taskBitmap.GetHicon()
            $taskIcon = [Drawing.Icon]::FromHandle($taskHandle)
            $taskIcon.Save($taskMemory)
            $taskBytes = $taskMemory.ToArray()
            $taskOffset = [BitConverter]::ToUInt32($taskBytes, 18)
            $taskLength = [BitConverter]::ToUInt32($taskBytes, 14)
            $taskFrames += ,@{ Size = $taskSize; Bytes = $taskBytes[$taskOffset..($taskOffset + $taskLength - 1)] }
        } finally {
            if ($taskIcon) { $taskIcon.Dispose() }
            if ($taskHandle -ne [IntPtr]::Zero) { [FolderSealIconNative]::DestroyIcon($taskHandle) | Out-Null }
            $taskMemory.Dispose(); $taskGraphics.Dispose(); $taskBitmap.Dispose()
        }
    }
    $taskFile = [IO.File]::Create((Join-Path $taskRoot 'assets\FolderSeal.ico'))
    $taskWriter = [IO.BinaryWriter]::new($taskFile)
    try {
        $taskWriter.Write([uint16]0); $taskWriter.Write([uint16]1); $taskWriter.Write([uint16]$taskFrames.Count)
        $taskOffset = 6 + 16 * $taskFrames.Count
        foreach ($taskFrame in $taskFrames) {
            $taskDimension = $taskFrame.Size % 256
            $taskWriter.Write([byte]$taskDimension); $taskWriter.Write([byte]$taskDimension)
            $taskWriter.Write([uint16]0); $taskWriter.Write([uint16]1); $taskWriter.Write([uint16]32)
            $taskWriter.Write([uint32]$taskFrame.Bytes.Length); $taskWriter.Write([uint32]$taskOffset)
            $taskOffset += $taskFrame.Bytes.Length
        }
        foreach ($taskFrame in $taskFrames) { $taskWriter.Write([byte[]]$taskFrame.Bytes) }
    } finally { $taskWriter.Dispose() }
} finally { $taskSource.Dispose() }
Write-Output 'Icon generated: 16, 24, 32, 48, 64, 128, 256 pixels.'

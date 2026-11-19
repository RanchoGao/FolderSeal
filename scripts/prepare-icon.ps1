# Copyright (c) 2026 EurekaGao. Convert the supplied artwork to a Windows icon.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path -Parent $PSScriptRoot
Add-Type -AssemblyName System.Drawing
$taskSource = [Drawing.Image]::FromFile((Join-Path $taskRoot 'assets\FolderSeal.png'))
$taskFrames = @()
try {
    foreach ($taskSize in @(16, 24, 32, 48, 64, 128, 256)) {
        $taskBitmap = [Drawing.Bitmap]::new($taskSize, $taskSize, [Drawing.Imaging.PixelFormat]::Format32bppArgb)
        $taskGraphics = [Drawing.Graphics]::FromImage($taskBitmap)
        $taskMemory = [IO.MemoryStream]::new()
        try {
            $taskGraphics.InterpolationMode = [Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
            $taskGraphics.DrawImage($taskSource, 0, 0, $taskSize, $taskSize)
            # Icon.FromHandle().Save() can quantize to a 4-bit palette. Write the
            # 32-bit DIB directly, including the separate Windows AND mask.
            $taskBitmap.Save($taskMemory, [Drawing.Imaging.ImageFormat]::Bmp)
            $taskBytes = $taskMemory.ToArray()
            if ([BitConverter]::ToUInt32($taskBytes, 14) -ne 40 -or
                [BitConverter]::ToUInt16($taskBytes, 28) -ne 32 -or
                [BitConverter]::ToUInt32($taskBytes, 30) -ne 0) { throw 'Expected an uncompressed 32-bit bitmap.' }
            $taskOffset = [BitConverter]::ToUInt32($taskBytes, 10)
            $taskPixelLength = $taskSize * $taskSize * 4
            $taskMaskLength = [int]([Math]::Ceiling($taskSize / 32.0) * 4 * $taskSize)
            $taskDib = [byte[]]::new(40 + $taskPixelLength + $taskMaskLength)
            [Array]::Copy($taskBytes, 14, $taskDib, 0, 40)
            [Array]::Copy([BitConverter]::GetBytes([int]($taskSize * 2)), 0, $taskDib, 8, 4)
            [Array]::Copy([BitConverter]::GetBytes([int]($taskPixelLength + $taskMaskLength)), 0, $taskDib, 20, 4)
            [Array]::Copy($taskBytes, $taskOffset, $taskDib, 40, $taskPixelLength)
            $taskFrames += ,@{ Size = $taskSize; Bytes = $taskDib }
        } finally {
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

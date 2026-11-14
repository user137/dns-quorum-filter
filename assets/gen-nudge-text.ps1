#Requires -Version 7
<#
.SYNOPSIS
Renders the browser-nudge popup's text (T-151, Batch 5.7) for every tray locale as a raw 8-bit
alpha mask. Called by gen-icon.py, which then RLE-encodes each mask into
crates/dnsqb-tray/icons/nudge-text/<locale>.bin; not meant to be run on its own.

.DESCRIPTION
GDI+ (System.Drawing) shapes every script the tray ships - Arabic and Urdu joining, Hebrew
right-to-left, Devanagari reordering, Thai, CJK - which Pillow cannot without libraqm. The
font is chosen per script so the output does not depend on GDI+ font fallback, and each
locale's text is shrunk until it fits the box whole: a sentence that does not fit at
-MinSize is an error, never a silently clipped mask. Anti-aliasing is greyscale (never
ClearType), so one channel is the coverage.

pwsh 7 only: Windows PowerShell 5.1 reads this BOM-less UTF-8 file as the ANSI codepage.
#>
param(
    [Parameter(Mandatory)] [string]$I18nDir,
    [Parameter(Mandatory)] [string]$OutDir,
    [Parameter(Mandatory)] [int]$Width,
    [Parameter(Mandatory)] [int]$Height,
    [double]$StartSize = 15,
    [double]$MinSize = 10,
    [string]$Key = 'nudge.popupText'
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing

$FontByLocale = @{
    ja = 'Yu Gothic UI'
    zh = 'Microsoft YaHei UI'
    ko = 'Malgun Gothic'
    th = 'Leelawadee UI'
    hi = 'Nirmala UI'
}
$RightToLeft = @('ar', 'he', 'ur')

$installed = (New-Object System.Drawing.Text.InstalledFontCollection).Families
function Get-Family([string]$Name) {
    $family = $installed | Where-Object Name -EQ $Name
    if (-not $family) { throw "font family '$Name' is not installed" }
    if (-not $family.IsStyleAvailable([System.Drawing.FontStyle]::Bold)) { throw "font family '$Name' has no bold face" }
    $family
}

New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
foreach ($file in Get-ChildItem -LiteralPath $I18nDir -Filter *.json | Sort-Object Name) {
    $locale = $file.BaseName
    $text = (Get-Content -LiteralPath $file.FullName -Raw -Encoding utf8 | ConvertFrom-Json -AsHashtable)[$Key]
    if (-not $text) { throw "$locale.json has no '$Key'" }
    $family = Get-Family ($FontByLocale[$locale] ?? 'Segoe UI')

    $format = [System.Drawing.StringFormat]::new([System.Drawing.StringFormat]::GenericTypographic)
    $format.FormatFlags = $format.FormatFlags -band (-bnot [System.Drawing.StringFormatFlags]::NoWrap)
    if ($RightToLeft -contains $locale) {
        $format.FormatFlags = $format.FormatFlags -bor [System.Drawing.StringFormatFlags]::DirectionRightToLeft
    }
    $format.Trimming = [System.Drawing.StringTrimming]::None

    $bitmap = [System.Drawing.Bitmap]::new($Width, $Height, [System.Drawing.Imaging.PixelFormat]::Format24bppRgb)
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    try {
        $graphics.Clear([System.Drawing.Color]::Black)
        $graphics.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
        $box = [System.Drawing.SizeF]::new($Width, $Height)
        $size = $StartSize
        $font = $null
        $measured = $null
        while ($true) {
            $font = [System.Drawing.Font]::new($family, [single]$size, [System.Drawing.FontStyle]::Bold, [System.Drawing.GraphicsUnit]::Pixel)
            $chars = 0; $lines = 0
            $measured = $graphics.MeasureString($text, $font, $box, $format, [ref]$chars, [ref]$lines)
            if ($chars -eq $text.Length -and $measured.Height -le $Height) { break }
            $font.Dispose()
            $size -= 0.5
            if ($size -lt $MinSize) { throw "$locale`: text does not fit ${Width}x${Height} even at ${MinSize}px" }
        }
        $top = [Math]::Floor(($Height - $measured.Height) / 2)
        # The draw rect runs to the bottom of the box, not to the measured height: with
        # LineLimit a rect a rounding error shorter than the last line drops that line.
        $graphics.DrawString($text, $font, [System.Drawing.Brushes]::White, [System.Drawing.RectangleF]::new(0, $top, $Width, $Height - $top), $format)
        $font.Dispose()

        $alpha = [byte[]]::new($Width * $Height)
        for ($y = 0; $y -lt $Height; $y++) {
            for ($x = 0; $x -lt $Width; $x++) {
                $alpha[$y * $Width + $x] = $bitmap.GetPixel($x, $y).G
            }
        }
        [System.IO.File]::WriteAllBytes((Join-Path $OutDir "$locale.alpha"), $alpha)
        Write-Host ("{0,-8} {1,-20} {2,4}px {3} line(s)" -f $locale, $family.Name, $size, $lines)
    } finally {
        $graphics.Dispose()
        $bitmap.Dispose()
        $format.Dispose()
    }
}

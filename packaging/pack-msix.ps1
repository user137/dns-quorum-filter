#Requires -Version 5.1
<#
.SYNOPSIS
  T-156 (Батч 3.8): stages the three signed binaries + assets + a substituted
  AppxManifest.xml, packs an .msix with makeappx, then signs it.

.DESCRIPTION
  Signing model mirrors T-102's binary signing: -PfxPath/-PfxPassword (or the
  CODESIGN_PFX/CODESIGN_PASSWORD env vars release.yml already uses) sign
  strictly with a supplied certificate; otherwise an ephemeral self-signed
  certificate is generated in this process (never written to disk except as
  a temp .pfx deleted before this script returns) and the package is
  test-signed. The certificate's Subject is always exactly -Publisher — the
  .msix signature and <Identity Publisher> must match character for
  character, or signing fails with "publisher name does not match" — so both
  come from this one parameter, never two literals that happen to agree
  today.
#>
[CmdletBinding()]
param(
    [string]$Version,
    [string]$Publisher = "CN=dns-quorum-filter",
    [Parameter(Mandatory)]
    [string]$BinDir,
    [Parameter(Mandatory)]
    [string]$OutFile,
    [string]$PfxPath,
    [string]$PfxPassword
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $false

function Resolve-SdkTool {
    param([Parameter(Mandatory)][string]$Name)
    $tool = Get-ChildItem "C:\Program Files (x86)\Windows Kits\10\bin\10.*\x64\$Name" -ErrorAction SilentlyContinue |
        Sort-Object FullName -Descending | Select-Object -First 1
    if (-not $tool) {
        throw "$Name not found under Windows Kits\10\bin\10.*\x64 — is the Windows SDK installed?"
    }
    return $tool.FullName
}

$makeappx = Resolve-SdkTool "makeappx.exe"
$signtool = Resolve-SdkTool "signtool.exe"
Write-Host "makeappx: $makeappx"
Write-Host "signtool: $signtool"

# --- Version: git tag is authoritative when present, cross-checked against
# the crate version so a .msix is never versioned differently from the
# binaries packed inside it; a plain local run without a tag falls back to
# the crate version alone. MSIX Version is 4-part Major.Minor.Build.Revision
# with Revision always 0.
if (-not $Version) {
    $repoRoot = Split-Path -Parent $PSScriptRoot
    $metaJson = & cargo metadata --no-deps --format-version 1 --manifest-path (Join-Path $repoRoot "Cargo.toml")
    if ($LASTEXITCODE -ne 0) { throw "cargo metadata failed" }
    $meta = $metaJson | ConvertFrom-Json
    $crateVersion = ($meta.packages | Where-Object { $_.name -eq "dnsqb-service" }).version
    if (-not $crateVersion) { throw "could not read dnsqb-service's version from cargo metadata" }

    $tagRef = $env:GITHUB_REF_NAME
    if ($tagRef -and $tagRef -match '^v(\d+\.\d+\.\d+)$') {
        $tagVersion = $Matches[1]
        if ($tagVersion -ne $crateVersion) {
            throw "tag v$tagVersion does not match dnsqb-service's Cargo.toml version $crateVersion — bump one to match before tagging"
        }
        $Version = $tagVersion
    } else {
        $Version = $crateVersion
    }
}
$msixVersion = "$Version.0"
Write-Host "MSIX version: $msixVersion"

# --- Stage: manifest + assets + the three binaries, nothing else.
$staging = Join-Path ([System.IO.Path]::GetTempPath()) ("dqf-msix-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $staging | Out-Null
try {
    $repoRoot = Split-Path -Parent $PSScriptRoot
    $manifestTemplate = Get-Content (Join-Path $repoRoot "packaging\AppxManifest.template.xml") -Raw
    $manifest = $manifestTemplate.Replace("{{VERSION}}", $msixVersion).Replace("{{PUBLISHER}}", $Publisher)
    Set-Content -Path (Join-Path $staging "AppxManifest.xml") -Value $manifest -Encoding utf8NoBOM

    # assets/icon/ is the single source for the app's icon everywhere (README,
    # a future Store listing, a future Linux desktop icon) - it also holds
    # sizes this package doesn't need, so only the three MSIX names are
    # copied here, not the whole directory.
    New-Item -ItemType Directory -Path (Join-Path $staging "Assets") | Out-Null
    foreach ($logo in "Square44x44Logo.png", "Square150x150Logo.png", "StoreLogo.png") {
        Copy-Item (Join-Path $repoRoot "assets\icon\$logo") (Join-Path $staging "Assets\$logo")
    }

    foreach ($exe in "dnsqb-service.exe", "dnsqb-watcher.exe", "dnsqb-tray.exe") {
        $src = Join-Path $BinDir $exe
        if (-not (Test-Path $src)) { throw "missing binary: $src" }
        Copy-Item $src (Join-Path $staging $exe)
    }

    # --- Pack.
    $outDir = Split-Path -Parent $OutFile
    if ($outDir -and -not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir | Out-Null }
    if (Test-Path $OutFile) { Remove-Item $OutFile -Force }
    & $makeappx pack /d $staging /p $OutFile /o
    if ($LASTEXITCODE -ne 0) { throw "makeappx pack failed (exit $LASTEXITCODE)" }
} finally {
    Remove-Item $staging -Recurse -Force -ErrorAction SilentlyContinue
}

# --- Sign: real cert if supplied, else an ephemeral ad-hoc one whose Subject
# is exactly $Publisher.
$cerPath = [System.IO.Path]::ChangeExtension($OutFile, ".cer")
$pfx = Join-Path ([System.IO.Path]::GetTempPath()) ("dqf-msix-" + [guid]::NewGuid() + ".pfx")
try {
    if ($PfxPath) {
        Copy-Item $PfxPath $pfx
        $pw = $PfxPassword
        $mode = "signed"
    } else {
        $pw = -join ((1..32) | ForEach-Object { '{0:x}' -f (Get-Random -Maximum 16) })
        Write-Host "::add-mask::$pw"
        $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject $Publisher `
            -CertStoreLocation Cert:\CurrentUser\My -KeyExportPolicy Exportable `
            -KeyUsage DigitalSignature -HashAlgorithm SHA256
        Export-PfxCertificate -Cert $cert -FilePath $pfx `
            -Password (ConvertTo-SecureString $pw -AsPlainText -Force) | Out-Null
        Export-Certificate -Cert $cert -FilePath $cerPath | Out-Null
        Remove-Item ("Cert:\CurrentUser\My\" + $cert.Thumbprint) -Force
        $mode = "test-signed"
        Write-Host "No -PfxPath — ephemeral self-signed cert; package is $mode. Exported $cerPath."
    }

    & $signtool sign /fd SHA256 /f $pfx /p $pw /tr http://timestamp.digicert.com /td SHA256 $OutFile
    if ($LASTEXITCODE -ne 0) { throw "signtool sign failed (exit $LASTEXITCODE) — check the .msix <Identity Publisher> matches -Publisher's Subject exactly" }
} finally {
    Remove-Item $pfx -Force -ErrorAction SilentlyContinue
}

Write-Host "mode=$mode"
Write-Host "Packed and signed: $OutFile"

#Requires -Version 5.1
<#
.SYNOPSIS
    Trust (or untrust) the ephemeral test-signing certificate that ships next to
    dns-quorum-filter.msix, so Add-AppxPackage will sideload it.

.DESCRIPTION
    Test-signed releases carry dns-quorum-filter.cer alongside the .msix. Windows
    will not install the package until that certificate is trusted, and
    Add-AppxPackage specifically checks Cert:\LocalMachine\TrustedPeople for the
    signer -- Cert:\CurrentUser\... is not enough (0x800B0109), and an absent
    certificate gives 0x800B010A. Writing to LocalMachine needs elevation, so
    this script relaunches itself as Administrator (forwarding its parameters)
    and adds the certificate via the X509Store API, mirroring what pakko's
    scripts/Setup-DevCert.ps1 does for the same class of package.

    This certificate is unrelated to the one dns-quorum-service installs for
    127.0.0.1 DoH traffic (T-49) -- trusting one does not trust the other.

.PARAMETER CerPath
    Path to the .cer. Defaults to dns-quorum-filter.cer next to this script
    (its layout in every release). A repo checkout has no .cer beside it -- pass
    this pointing at a downloaded release asset.

.PARAMETER Install
    After trusting the certificate, also run Add-AppxPackage on
    dns-quorum-filter.msix next to the .cer. Passes
    -ForceTargetApplicationShutdown (T-223), so re-running this on an
    already-installed, running app upgrades in place instead of failing
    with 0x80073D02 ("needs to be closed") -- no manual "Exit" from the
    tray needed first.

.PARAMETER Remove
    Undo: delete the certificate from Cert:\LocalMachine\TrustedPeople instead of
    adding it. Ignores -Install.

.EXAMPLE
    .\Trust-TestCert.ps1
    Trust the certificate (prompts for elevation).

.EXAMPLE
    .\Trust-TestCert.ps1 -Install
    Trust it, then sideload the .msix in one step.

.EXAMPLE
    .\Trust-TestCert.ps1 -Remove
    Remove the trust again (run before removing the app -- MSIX has no
    uninstall-time hook, T-70).
#>
[CmdletBinding()]
param(
    [string] $CerPath,
    [switch] $Install,
    [switch] $Remove,
    # Internal: set on the elevated relaunch so the child window pauses before
    # closing and the user can read the result.
    [Parameter(DontShow)]
    [switch] $Elevated
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# On the elevated relaunch the window closes the instant the script ends, so a
# failure would flash past. Pause on every error path (including a later `throw`
# from Add-AppxPackage), then re-raise so the exit code stays non-zero.
trap {
    if ($Elevated) { Read-Host "`nError -- press Enter to close" | Out-Null }
    break
}

$CODE_SIGNING_EKU = '1.3.6.1.5.5.7.3.3'
$EXPECTED_SUBJECT = 'CN=dns-quorum-filter'
$STORE_NAME       = 'TrustedPeople'

# --- Resolve paths (working directory is C:\WINDOWS\system32 after elevation,
# so everything forwarded to the child must already be absolute).
$here = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $PSCommandPath }
if (-not $here) {
    throw "Cannot resolve the script directory. Run this as a file: .\Trust-TestCert.ps1"
}
if (-not $CerPath) { $CerPath = Join-Path $here 'dns-quorum-filter.cer' }
$CerPath = [System.IO.Path]::GetFullPath($CerPath)
if (-not (Test-Path -LiteralPath $CerPath)) {
    throw "Certificate not found: $CerPath`n" +
          "Expected 'dns-quorum-filter.cer' next to this script -- it ships in every release " +
          "alongside the .msix. Pass -CerPath to point at a downloaded copy."
}

# --- Load and sanity-check the certificate before trusting anything.
$cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($CerPath)

if ($cert.Subject -ne $EXPECTED_SUBJECT) {
    throw "Refusing to trust '$($cert.Subject)' -- expected '$EXPECTED_SUBJECT'. " +
          "This script only trusts the dns-quorum-filter test-signing certificate."
}

$ekuExt = $cert.Extensions |
    Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension] } |
    Select-Object -First 1
$hasCodeSigning = $false
if ($ekuExt) {
    foreach ($oid in $ekuExt.EnhancedKeyUsages) {
        if ($oid.Value -eq $CODE_SIGNING_EKU) { $hasCodeSigning = $true }
    }
}
if (-not $hasCodeSigning) {
    throw "Refusing to trust: certificate has no Code Signing EKU ($CODE_SIGNING_EKU)."
}

$thumb = $cert.Thumbprint

# --- Elevate if needed, forwarding the (now absolute) parameters.
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)
if (-not $isAdmin) {
    $psHost = if ($PSVersionTable.PSEdition -eq 'Core') { 'pwsh' } else { 'powershell' }
    $fwd = @('-CerPath', $CerPath, '-Elevated')
    if ($Install) { $fwd += '-Install' }
    if ($Remove)  { $fwd += '-Remove' }
    Write-Host "Elevation required -- relaunching as Administrator..." -ForegroundColor Yellow
    $psArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath) + $fwd
    Start-Process $psHost -Verb RunAs -Wait -ArgumentList $psArgs
    # The child did the write under LocalMachine; reading the store back needs no
    # elevation, so report the final state from here too.
    $stillThere = @(Get-ChildItem "Cert:\LocalMachine\$STORE_NAME" |
        Where-Object { $_.Thumbprint -eq $thumb }).Count -gt 0
    if ($Remove) {
        if ($stillThere) { Write-Warning "Certificate still present -- the elevated step may have been cancelled." }
        else { Write-Host "Certificate $thumb is no longer trusted." -ForegroundColor Green }
    } else {
        if ($stillThere) { Write-Host "Certificate $thumb is now trusted (LocalMachine\$STORE_NAME)." -ForegroundColor Green }
        else { Write-Warning "Certificate not found afterwards -- the elevated step may have been cancelled." }
    }
    return
}

# --- Elevated from here: do the store write.
$store = [System.Security.Cryptography.X509Certificates.X509Store]::new($STORE_NAME, 'LocalMachine')
$store.Open('ReadWrite')
try {
    if ($Remove) {
        $store.Remove($cert)
        Write-Host "Removed $thumb from LocalMachine\$STORE_NAME." -ForegroundColor Green
    } else {
        $store.Add($cert)
        Write-Host "Added $thumb to LocalMachine\$STORE_NAME." -ForegroundColor Green
    }
} finally {
    $store.Close()
}

$present = @(Get-ChildItem "Cert:\LocalMachine\$STORE_NAME" |
    Where-Object { $_.Thumbprint -eq $thumb }).Count -gt 0
if ($Remove) {
    if ($present) { throw "Removal reported success but the certificate is still in the store." }
    Write-Host "Verified: not trusted." -ForegroundColor Green
} else {
    if (-not $present) { throw "Add reported success but the certificate is not in the store." }
    $leaf = Split-Path -Leaf $PSCommandPath
    Write-Host "Verified: trusted. Undo later with:  .\$leaf -Remove" -ForegroundColor Green
}

if ($Install -and -not $Remove) {
    $msix = Join-Path (Split-Path -Parent $CerPath) 'dns-quorum-filter.msix'
    if (-not (Test-Path -LiteralPath $msix)) {
        throw "Cannot -Install: '$msix' not found next to the certificate."
    }
    Write-Host "Installing $msix ..."
    try {
        # -ForceTargetApplicationShutdown (T-223): the manifest declares no
        # <PackageDependency>, so this (rather than -ForceApplicationShutdown,
        # which also tears down dependency packages) is the documented,
        # narrowest option -- closes dnsqb-service/-tray/-watcher itself if
        # an older version is already running, so an update never hits
        # 0x80073D02 and never needs a manual tray "Exit" first.
        Add-AppxPackage -Path $msix -ForceTargetApplicationShutdown -ErrorAction Stop
        Write-Host "Installed. Look for 'DNS Quorum Filter' in the Start menu." -ForegroundColor Green
    } catch {
        throw "Add-AppxPackage failed: $_"
    }
}

if ($Elevated) { Read-Host "`nDone. Press Enter to close" | Out-Null }

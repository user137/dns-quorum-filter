#Requires -Version 7
<#
.SYNOPSIS
Tray idle cost: CPU seconds and Win32_Process I/O operation counts over 60 s (ARCH-19, T-278).

.DESCRIPTION
Without -ExeDir: measures the running installed dnsqb-tray as-is.
With -ExeDir: starts that directory's dnsqb-tray.exe under a throwaway LOCALAPPDATA, so the
tray spawns its own watcher+service from the same directory. The copied resolver_config.toml
gets port 18453 BEFORE anything starts (a scratch instance on the default port talks to the
installed service), and the three one-shot markers are copied from the installed app-data so
the scratch tray is in the same settled state. Afterwards every scratch process is killed by
PID (never by image name - that would kill the installed app) and the scratch TLS-key entry
is removed from Credential Manager.
#>
param([string]$ExeDir, [int]$WarmupSeconds = 15, [int]$Seconds = 60)

$ErrorActionPreference = 'Stop'

function Measure-Tray([System.Diagnostics.Process]$Proc) {
    $Proc.Refresh(); $c0 = $Proc.TotalProcessorTime.TotalSeconds
    $w0 = Get-CimInstance Win32_Process -Filter "ProcessId=$($Proc.Id)"
    Start-Sleep $Seconds
    $Proc.Refresh(); $w1 = Get-CimInstance Win32_Process -Filter "ProcessId=$($Proc.Id)"
    '{0}s idle: CPU={1:N2}s Read={2} Other={3} Write={4}' -f $Seconds,
        ($Proc.TotalProcessorTime.TotalSeconds - $c0),
        ($w1.ReadOperationCount - $w0.ReadOperationCount),
        ($w1.OtherOperationCount - $w0.OtherOperationCount),
        ($w1.WriteOperationCount - $w0.WriteOperationCount)
}

if (-not $ExeDir) {
    Measure-Tray (Get-Process dnsqb-tray | Where-Object Path -like '*\WindowsApps\*' | Select-Object -First 1)
    return
}

$ExeDir = (Resolve-Path $ExeDir).Path
$installed = (Get-ChildItem "$env:LOCALAPPDATA\Packages" -Filter 'dns-quorum-filter*' |
    Select-Object -First 1).FullName + '\LocalCache\Local\dns-quorum-filter'
$lad = Join-Path ([IO.Path]::GetTempPath()) "dnsqb-measure-$PID"
$appData = Join-Path $lad 'dns-quorum-filter'
New-Item -ItemType Directory -Force $appData | Out-Null
$config = if (Test-Path "$installed\resolver_config.toml") {
    (Get-Content "$installed\resolver_config.toml") -replace '^port\s*=.*', 'port = 18453'
} else { 'port = 18453' }
Set-Content "$appData\resolver_config.toml" $config
foreach ($f in 'onboarding.seen', 'browser-nudge.seen', 'first-seen.stamp') {
    if (Test-Path "$installed\$f") { Copy-Item "$installed\$f" "$appData\$f" }
}

$realLad = $env:LOCALAPPDATA
try {
    $env:LOCALAPPDATA = $lad
    $tray = Start-Process (Join-Path $ExeDir 'dnsqb-tray.exe') -PassThru
} finally { $env:LOCALAPPDATA = $realLad }
try {
    Start-Sleep $WarmupSeconds
    Measure-Tray $tray
} finally {
    Get-Process dnsqb-* -ErrorAction SilentlyContinue | Where-Object Path -like "$ExeDir\*" |
        ForEach-Object { Stop-Process -Id $_.Id -Force }
    $sha = [Security.Cryptography.SHA1]::Create()
    $hash = -join ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($appData.ToLower()))[0..7] |
        ForEach-Object { $_.ToString('x2') })
    cmdkey /delete:"doh-tls-private-key:$hash.dns-quorum-filter" | Out-Null
    Start-Sleep 2
    Remove-Item $lad -Recurse -Force -ErrorAction SilentlyContinue
}

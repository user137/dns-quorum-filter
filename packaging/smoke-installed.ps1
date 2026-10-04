#Requires -Version 7
<#
.SYNOPSIS
Post-install live smoke test of the installed dns-quorum-filter MSIX (QA pass, Phase 3b).

.DESCRIPTION
Run against the installed package before every release; CI never sees an installed MSIX.
Read-only apart from one rolled-back mutation (POST /admin/config with the current values,
then resolver_config.toml must be byte-identical). Never calls /admin/shutdown,
/admin/install-cert or /admin/uninstall-local-state, and never prints a /admin/log body.
Exit code: 0 when every check passes, 1 otherwise.

.PARAMETER InjectFailure
Adds one check that must fail, to prove the non-zero exit code path.
#>
param([switch]$InjectFailure)

$ErrorActionPreference = 'Stop'
$script:Failures = 0

function Check([string]$Name, [bool]$Ok, [string]$Detail = '') {
    if ($Ok) { Write-Host "PASS $Name $Detail" }
    else { Write-Host "FAIL $Name $Detail"; $script:Failures++ }
}

$PackageName = 'dns-quorum-filter'
$Locales = @('ar', 'bg', 'cs', 'da', 'de', 'el', 'en', 'es', 'et', 'fi', 'fr', 'he', 'hi', 'hr',
    'hu', 'id', 'it', 'ja', 'ko', 'lt', 'lv', 'nb', 'nl', 'pl', 'pt', 'ro', 'sk', 'sl', 'sr-Latn',
    'sv', 'sw', 'th', 'tr', 'uk', 'ur', 'vi', 'zh')
# Every GET route in dispatch::ROUTES that answers JSON (/dns-query is checked separately).
$JsonRoutes = @('/health', '/admin/status', '/admin/overrides', '/admin/cache-config',
    '/admin/geoip', '/admin/geoip/maxmind', '/admin/providers', '/admin/log', '/admin/cert-status')
$StaticRoutes = @{
    '/admin/ui'           = 'text/html'
    '/admin/ui/main.js'   = 'text/javascript'
    '/admin/ui/style.css' = 'text/css'
}

$pkg = Get-AppxPackage -Name $PackageName
if (-not $pkg) { Write-Host "FAIL package $PackageName is not installed"; exit 1 }
Check 'package' $true "$($pkg.Version)"
$appData = Join-Path $env:LOCALAPPDATA "Packages\$($pkg.PackageFamilyName)\LocalCache\Local\dns-quorum-filter"
$configPath = Join-Path $appData 'resolver_config.toml'
$port = 8443
# A fresh install runs on built-in defaults until the first settings write creates the file.
$configExisted = Test-Path $configPath
if ($configExisted -and (Get-Content $configPath -Raw) -match '(?m)^port\s*=\s*(\d+)') { $port = [int]$Matches[1] }

# --- processes -----------------------------------------------------------------------------
foreach ($name in 'dnsqb-service', 'dnsqb-tray', 'dnsqb-watcher') {
    $procs = @(Get-Process -Name $name -ErrorAction SilentlyContinue |
        Where-Object { $_.Path -and $_.Path.StartsWith($pkg.InstallLocation, [StringComparison]::OrdinalIgnoreCase) })
    Check "process $name" ($procs.Count -eq 1) "count=$($procs.Count)"
}

# --- startup task (T-243): state lives under the package's SystemAppData key ---------------
$taskKey = "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\$($pkg.PackageFamilyName)\DnsqbWatcherStartup"
$taskState = (Get-ItemProperty -Path $taskKey -Name State -ErrorAction SilentlyContinue).State
# StartupTaskState: 2 = Enabled, 4 = EnabledByPolicy.
Check 'startupTask DnsqbWatcherStartup enabled' ($taskState -in 2, 4) "State=$taskState"

# --- pinned TLS client ---------------------------------------------------------------------
Add-Type -TypeDefinition @'
using System;
using System.Linq;
using System.Net.Http;
public static class DqfSmokeHttp {
    public static HttpClient Create(byte[] pinned) {
        var handler = new HttpClientHandler();
        handler.ServerCertificateCustomValidationCallback =
            (message, cert, chain, errors) => cert != null && cert.RawData.SequenceEqual(pinned);
        return new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(15) };
    }
}
'@
$pem = Get-Content (Join-Path $appData 'cert.pem') -Raw
$der = [Convert]::FromBase64String(($pem -replace '-----[^-]+-----', '' -replace '\s', ''))
$client = [DqfSmokeHttp]::Create($der)
$base = "https://127.0.0.1:$port"

function Invoke-Route([string]$Method, [string]$Path, [byte[]]$Body = $null, [string]$ContentType = $null) {
    $msg = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::new($Method), "$base$Path")
    if ($null -ne $Body) {
        $msg.Content = [System.Net.Http.ByteArrayContent]::new($Body)
        $msg.Content.Headers.ContentType = [System.Net.Http.Headers.MediaTypeHeaderValue]::Parse($ContentType)
    }
    if ($ContentType -eq 'application/dns-message') { $msg.Headers.Accept.ParseAdd($ContentType) }
    try {
        $resp = $client.SendAsync($msg).GetAwaiter().GetResult()
        $bytes = $resp.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult()
        $ct = if ($resp.Content.Headers.ContentType) { $resp.Content.Headers.ContentType.MediaType } else { '' }
        [pscustomobject]@{ Status = [int]$resp.StatusCode; Type = $ct; Bytes = $bytes }
    } catch {
        [pscustomobject]@{ Status = 0; Type = ''; Bytes = [byte[]]@(); Error = $_.Exception.GetBaseException().Message }
    }
}

function Read-Json($Response) {
    try { [System.Text.Encoding]::UTF8.GetString($Response.Bytes) | ConvertFrom-Json -AsHashtable } catch { $null }
}

# --- JSON GET routes -----------------------------------------------------------------------
foreach ($path in $JsonRoutes) {
    $r = Invoke-Route GET $path
    $json = Read-Json $r
    $ok = $r.Status -eq 200 -and $r.Type -eq 'application/json' -and $null -ne $json
    # Body content is deliberately never printed: /admin/log holds the user's own domains.
    Check "GET $path" $ok "status=$($r.Status) type=$($r.Type) $($r.Error)"
    if ($path -eq '/admin/status' -and $json) {
        Check 'status schema_version' ($json.schema_version -is [long] -and $json.schema_version -gt 0) "schema_version=$($json.schema_version)"
        Check 'status app_version matches package' ("$($pkg.Version)".StartsWith("$($json.app_version)")) "app_version=$($json.app_version)"
    }
}

# --- static site + every i18n dictionary ---------------------------------------------------
foreach ($path in $StaticRoutes.Keys) {
    $r = Invoke-Route GET $path
    Check "GET $path" ($r.Status -eq 200 -and $r.Type -eq $StaticRoutes[$path] -and $r.Bytes.Length -gt 0) "status=$($r.Status) type=$($r.Type) bytes=$($r.Bytes.Length)"
}
$dictOk = 0
foreach ($loc in $Locales) {
    $r = Invoke-Route GET "/admin/ui/i18n/$loc.json"
    $json = Read-Json $r
    if ($r.Status -eq 200 -and $r.Type -eq 'application/json' -and $json -and $json.Count -gt 0) { $dictOk++ }
    else { Check "GET /admin/ui/i18n/$loc.json" $false "status=$($r.Status) type=$($r.Type)" }
}
Check 'i18n dictionaries' ($dictOk -eq $Locales.Count) "$dictOk/$($Locales.Count)"

# --- one DoH query (RFC 8484 POST, A example.com) ------------------------------------------
$query = [byte[]](0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7) + [Text.Encoding]::ASCII.GetBytes('example') +
    [byte[]](3) + [Text.Encoding]::ASCII.GetBytes('com') + [byte[]](0, 0, 1, 0, 1)
$r = Invoke-Route POST '/dns-query' $query 'application/dns-message'
$rcode = if ($r.Bytes.Length -ge 4) { $r.Bytes[3] -band 0x0F } else { -1 }
Check 'POST /dns-query' ($r.Status -eq 200 -and $r.Type -eq 'application/dns-message' -and $rcode -eq 0) "status=$($r.Status) rcode=$rcode"

# --- unknown route stays closed ------------------------------------------------------------
$r = Invoke-Route GET '/admin/does-not-exist'
Check 'GET unknown route' ($r.Status -eq 404) "status=$($r.Status)"
if ($InjectFailure) {
    Check 'injected failure (unknown route must be 200)' ($r.Status -eq 200) "status=$($r.Status)"
}

# --- mutation round trip: POST /admin/config with the current values -----------------------
$before = if ($configExisted) { [IO.File]::ReadAllBytes($configPath) } else { $null }
$status = Read-Json (Invoke-Route GET '/admin/status')
if ($status) {
    $body = @{
        timeout_mode                            = $status.timeout_mode
        serve_baseline_when_filters_unreachable = $status.serve_baseline_when_filters_unreachable
    } | ConvertTo-Json -Compress
    $r = Invoke-Route POST '/admin/config' ([Text.Encoding]::UTF8.GetBytes($body)) 'application/json'
    $resp = Read-Json $r
    Check 'POST /admin/config (same values)' ($r.Status -eq 200 -and $resp -and $resp.persisted -eq $true) "status=$($r.Status) persisted=$($resp.persisted)"
    if ($configExisted) {
        $after = [IO.File]::ReadAllBytes($configPath)
        $same = [Linq.Enumerable]::SequenceEqual($before, $after)
        if (-not $same) { [IO.File]::WriteAllBytes($configPath, $before) }
        Check 'resolver_config.toml byte-identical after round trip' $same "bytes=$($before.Length)->$($after.Length)"
    } else {
        # The write created the file; remove it so the install goes back to running on defaults.
        $created = Test-Path $configPath
        if ($created) { Remove-Item -LiteralPath $configPath }
        Check 'resolver_config.toml absent again after round trip' (-not (Test-Path $configPath)) "created=$created"
    }
} else {
    Check 'POST /admin/config (same values)' $false 'status unreadable'
}

# --- --help of all three binaries, run inside the package identity -------------------------
# A direct launch from WindowsApps is denied for service/tray (T-246), so go through the
# package. --help is checked before anything else in each main, so nothing else starts.
$cmd = Join-Path $env:SystemRoot 'System32\cmd.exe'
foreach ($name in 'dnsqb-service', 'dnsqb-tray', 'dnsqb-watcher') {
    $exe = Join-Path $pkg.InstallLocation "$name.exe"
    $out = Join-Path $env:TEMP "dqf-smoke-$name-help.txt"
    Remove-Item $out, "$out.rc" -ErrorAction SilentlyContinue
    Invoke-CommandInDesktopPackage -PackageFamilyName $pkg.PackageFamilyName -AppId App -Command $cmd `
        -Args "/c `"`"$exe`" --help > `"$out`" 2>&1 & echo %errorlevel% > `"$out.rc`"`""
    for ($i = 0; $i -lt 40 -and -not (Test-Path "$out.rc"); $i++) { Start-Sleep -Milliseconds 250 }
    $text = if (Test-Path $out) { Get-Content $out -Raw } else { '' }
    $rc = if (Test-Path "$out.rc") { (Get-Content "$out.rc" -Raw).Trim() } else { 'timeout' }
    Check "$name --help" ($rc -eq '0' -and $text -match [regex]::Escape("$name ") -and $text -match '\d+\.\d+\.\d+') "rc=$rc chars=$($text.Length)"
    Remove-Item $out, "$out.rc" -ErrorAction SilentlyContinue
}

$client.Dispose()
if ($script:Failures -gt 0) { Write-Host "smoke-installed: $script:Failures failure(s)"; exit 1 }
Write-Host 'smoke-installed: all checks passed'
exit 0

# Privileged route-isolation test for the Leshy Windows port.
#
# Proves that each zone installs host routes through *its own* tunnel, that no
# address leaks onto another tunnel, and that a missing device file does not
# silently move traffic to a different tunnel.
#
# Runs against the installed service (the production path), temporarily swapping
# in a three-zone config and restoring the previous one afterwards.
#
#   .\route-isolation.ps1 -DeviceDir C:\ProgramData\Kikimora\leshy\vpn
param(
    [string]$DeviceDir = 'C:\ProgramData\Kikimora\leshy\vpn',
    [string]$ConfigPath = 'C:\ProgramData\leshy\config.toml',
    [string]$ServiceName = 'leshy'
)

$ErrorActionPreference = 'Stop'
$failures = New-Object System.Collections.ArrayList
$tracked = New-Object System.Collections.ArrayList

function Assert-True([bool]$condition, [string]$label) {
    if ($condition) { Write-Host "  PASS $label" } else { Write-Host "  FAIL $label" -ForegroundColor Red; [void]$failures.Add($label) }
}

function Wait-Listener([int]$attempts = 20) {
    for ($i = 0; $i -lt $attempts; $i++) {
        if (netstat -ano | Select-String -Pattern '127\.0\.0\.1:53\s') { return $true }
        Start-Sleep -Milliseconds 500
    }
    return $false
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { throw 'run this from an elevated PowerShell' }

$matrix = @(
    @{ Zone = 'awg'; Dev = 'awg.dev'; Domain = 'chatgpt.com'; Interface = 'kk-awg0' },
    @{ Zone = 'oc'; Dev = 'oc.dev'; Domain = 'gitlab.sca.ad-tech.ru'; Interface = 'kk-oc0' },
    @{ Zone = 'xray'; Dev = 'xray.dev'; Domain = 'telegram.org'; Interface = 'kk-xray-win0' }
)
foreach ($entry in $matrix) {
    $path = Join-Path $DeviceDir $entry.Dev
    if (-not (Test-Path $path)) { throw "device file missing: $path" }
    $alias = (Get-Content $path -Raw).Trim()
    if (-not $alias) { throw "device file is empty: $path" }
    $entry.Alias = $alias
    Write-Host "device $($entry.Dev) -> $alias (expected $($entry.Interface))"
}

$backup = "$ConfigPath.route-isolation.bak"
Copy-Item $ConfigPath $backup -Force
$zones = foreach ($entry in $matrix) {
    $extra = if ($entry.Zone -eq 'awg') { "static_routes = [""1.1.1.1/32"", ""8.8.8.8/32""]`r`n" } else { '' }
    "[[zones]]`r`nname = ""$($entry.Zone)""`r`nmode = ""inclusive""`r`ndns_servers = []`r`nroute_type = ""dev""`r`nroute_target = '$((Join-Path $DeviceDir $entry.Dev))'`r`ndomains = [""$($entry.Domain)""]`r`n$extra`r`n"
}
"[server]`r`nlisten_address = ""127.0.0.1:53""`r`ndefault_upstream = [""1.1.1.1:53"", ""8.8.8.8:53""]`r`nroute_failure_mode = ""fallback""`r`n`r`n$($zones -join '')" |
    Set-Content -Path $ConfigPath -Encoding UTF8

try {
    Restart-Service -Name $ServiceName -Force
    if (-not (Wait-Listener)) { throw 'leshy did not start listening on 127.0.0.1:53' }
    Start-Sleep -Seconds 2
    Clear-DnsClientCache

    Write-Host "`n=== zone -> tunnel matrix ==="
    foreach ($entry in $matrix) {
        $answers = @(Resolve-DnsName $entry.Domain -Server 127.0.0.1 -Type A -ErrorAction SilentlyContinue |
            Where-Object { $_.IPAddress } | Select-Object -ExpandProperty IPAddress)
        Assert-True ($answers.Count -gt 0) "$($entry.Domain) resolves through leshy"
        foreach ($ip in ($answers | Select-Object -First 2)) {
            [void]$tracked.Add($ip)
            $row = Get-NetRoute -DestinationPrefix "$ip/32" -ErrorAction SilentlyContinue | Select-Object -First 1
            $chosen = (Find-NetRoute -RemoteIPAddress $ip -ErrorAction SilentlyContinue | Select-Object -First 1).InterfaceAlias
            Assert-True ([bool]$row -and $row.InterfaceAlias -eq $entry.Alias) "$ip routed via $($entry.Alias)"
            Assert-True ($chosen -eq $entry.Alias) "$ip selects $($entry.Alias)"
            foreach ($other in $matrix) {
                if ($other.Interface -eq $entry.Interface) { continue }
                $leak = Get-NetRoute -DestinationPrefix "$ip/32" -ErrorAction SilentlyContinue |
                    Where-Object { $_.InterfaceAlias -eq $other.Alias }
                Assert-True (-not $leak) "$ip isolated from $($other.Alias)"
            }
        }
    }

    Write-Host "`n=== fail-closed: device file removed must not move traffic ==="
    $entry = $matrix[2]
    $devPath = Join-Path $DeviceDir $entry.Dev
    Rename-Item $devPath "$devPath.off" -Force
    try {
        foreach ($ip in $tracked) { Remove-NetRoute -DestinationPrefix "$ip/32" -Confirm:$false -ErrorAction SilentlyContinue }
        Clear-DnsClientCache
        $answers = @(Resolve-DnsName $entry.Domain -Server 127.0.0.1 -Type A -ErrorAction SilentlyContinue |
            Where-Object { $_.IPAddress } | Select-Object -ExpandProperty IPAddress)
        foreach ($ip in ($answers | Select-Object -First 2)) {
            $leak = Get-NetRoute -DestinationPrefix "$ip/32" -ErrorAction SilentlyContinue |
                Where-Object { $_.InterfaceAlias -ne $entry.Alias }
            Assert-True (-not $leak) "$ip did not fall back to another tunnel"
        }
    } finally {
        Rename-Item "$devPath.off" $devPath -Force
    }
} finally {
    Copy-Item $backup $ConfigPath -Force
    Remove-Item $backup -Force -ErrorAction SilentlyContinue
    foreach ($ip in $tracked) { Remove-NetRoute -DestinationPrefix "$ip/32" -Confirm:$false -ErrorAction SilentlyContinue }
    Restart-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    Clear-DnsClientCache
}

Write-Host ''
if ($failures.Count -gt 0) {
    Write-Host "$($failures.Count) assertion(s) failed" -ForegroundColor Red
    exit 1
}
Write-Host 'route isolation verified'
exit 0

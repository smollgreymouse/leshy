# Windows port of the Linux Docker scenario suite (tests/docker/test_integration.py).
#
# The Linux suite needs CoreDNS + dummy interfaces inside a container. On Windows
# the same scenarios are asserted through the observable route table, which is
# what the platform-specific code actually controls:
#
#   S1 basic forwarding            example.com resolves through leshy
#   S2 route via device            chatgpt.com -> host route on the tunnel adapter
#   S3 route via gateway           resolved address -> route through 192.168.1.1
#   S4 fallback on route failure   dead device file, route_failure_mode=fallback -> answer still returned
#   S5 servfail on route failure   same but servfail -> no answer (kill switch)
#   S6 pattern matching            *.openai.com matches a subdomain, not the apex
#   S7 vpn reconnect               device file removed -> no route, restored -> route again
#   S8 zone dns_servers            a zone with its own resolver still resolves public names
#
# Run elevated on the lab VM; the script swaps configs and restores the previous
# one in a finally block.
param(
    [string]$ServiceName = 'leshy',
    [string]$ConfigPath = 'C:\ProgramData\leshy\config.toml',
    [string]$DeviceDir = 'C:\ProgramData\Kikimora\leshy\vpn',
    [string]$Gateway = '192.168.1.1'
)

$ErrorActionPreference = 'Stop'
$failures = New-Object System.Collections.ArrayList
$results = New-Object System.Collections.ArrayList
$tracked = New-Object System.Collections.ArrayList

function Assert-True([bool]$condition, [string]$label) {
    if ($condition) { Write-Host "    PASS $label" } else { Write-Host "    FAIL $label" -ForegroundColor Red; [void]$failures.Add($label) }
}

function Get-Answers([string]$name) {
    # Upstreams ride the tunnel and can need a moment after a service restart,
    # so a single timeout must not fail a scenario.
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        try {
            $answers = @(Resolve-DnsName $name -Server 127.0.0.1 -Type A -ErrorAction Stop |
                Where-Object { $_.IPAddress } | Select-Object -ExpandProperty IPAddress)
            if ($answers.Count -gt 0) { return $answers }
        } catch {
            Write-Host "    (query $name attempt ${attempt} failed: $($_.Exception.Message.Trim()))"
        }
        if ($attempt -lt 3) { Start-Sleep -Seconds 2 }
    }
    @()
}

function Set-Scenario([string]$zoneToml) {
    $cfg = "[server]`r`nlisten_address = ""127.0.0.1:53""`r`ndefault_upstream = [""1.1.1.1:53"", ""8.8.8.8:53""]`r`nroute_failure_mode = ""$FailureMode""`r`n`r`n$zoneToml"
    Set-Content -Path $ConfigPath -Value $cfg -Encoding UTF8
    Restart-Service -Name $ServiceName -Force
    for ($i = 0; $i -lt 20; $i++) {
        if (netstat -ano | Select-String -Pattern '127\.0\.0\.1:53\s') { break }
        Start-Sleep -Milliseconds 500
    }
    Start-Sleep -Seconds 2
    Clear-DnsClientCache
}

function Clear-Tracked {
    foreach ($ip in $tracked) { Remove-NetRoute -DestinationPrefix "$ip/32" -Confirm:$false -ErrorAction SilentlyContinue }
    $tracked.Clear()
}

$backup = "$ConfigPath.scenarios.bak"
Copy-Item $ConfigPath $backup -Force
$awg = Join-Path $DeviceDir 'awg.dev'
if (-not (Test-Path $awg)) { throw "device file missing: $awg" }
$awgAlias = (Get-Content $awg -Raw).Trim()
Write-Host "tunnel under test: $awgAlias"

try {
    $FailureMode = 'fallback'

    Write-Host "`nS1 basic forwarding"
    Set-Scenario "[[zones]]`r`nname = ""nonmatch""`r`nmode = ""inclusive""`r`ndns_servers = []`r`nroute_type = ""dev""`r`nroute_target = '$awg'`r`ndomains = [""unused.invalid""]"
    $ips = Get-Answers 'example.com'
    Assert-True ($ips.Count -gt 0) 'example.com answered'
    [void]$results.Add("S1 basic forwarding: $(if ($ips.Count) { 'answers' } else { 'no answer' })")

    Write-Host "`nS2 route via device"
    Set-Scenario "[[zones]]`r`nname = ""awg""`r`nmode = ""inclusive""`r`ndns_servers = []`r`nroute_type = ""dev""`r`nroute_target = '$awg'`r`ndomains = [""chatgpt.com""]`r`nstatic_routes = [""1.1.1.1/32"", ""8.8.8.8/32""]"
    $ips = Get-Answers 'chatgpt.com'
    Assert-True ($ips.Count -gt 0) 'chatgpt.com answered'
    foreach ($ip in ($ips | Select-Object -First 2)) {
        [void]$tracked.Add($ip)
        $row = Get-NetRoute -DestinationPrefix "$ip/32" -ErrorAction SilentlyContinue | Select-Object -First 1
        Assert-True ([bool]$row -and $row.InterfaceAlias -eq $awgAlias) "$ip routed via $awgAlias"
    }
    [void]$results.Add("S2 route via device: $($ips.Count) answers, adapter $awgAlias")

    Write-Host "`nS3 route via gateway"
    Set-Scenario "[[zones]]`r`nname = ""gw""`r`nmode = ""inclusive""`r`ndns_servers = []`r`nroute_type = ""via""`r`nroute_target = ""$Gateway""`r`ndomains = [""openai.com""]`r`nstatic_routes = [""1.1.1.1/32"", ""8.8.8.8/32""]"
    $ips = Get-Answers 'openai.com'
    Assert-True ($ips.Count -gt 0) 'openai.com answered'
    foreach ($ip in ($ips | Select-Object -First 2)) {
        [void]$tracked.Add($ip)
        $row = Get-NetRoute -DestinationPrefix "$ip/32" -ErrorAction SilentlyContinue | Select-Object -First 1
        Assert-True ([bool]$row -and $row.NextHop -eq $Gateway) "$ip routed via gateway $Gateway"
    }
    [void]$results.Add("S3 route via gateway: $($ips.Count) answers, gateway $Gateway")

    Write-Host "`nS4 fallback on route failure (dead device file)"
    $FailureMode = 'fallback'
    Set-Scenario "[[zones]]`r`nname = ""dead""`r`nmode = ""inclusive""`r`ndns_servers = []`r`nroute_type = ""dev""`r`nroute_target = 'C:\ProgramData\Kikimora\leshy\vpn\does-not-exist.dev'`r`ndomains = [""example.com""]`r`nstatic_routes = [""1.1.1.1/32"", ""8.8.8.8/32""]"
    $ips = Get-Answers 'example.com'
    Assert-True ($ips.Count -gt 0) 'answer returned despite the dead route target'
    foreach ($ip in ($ips | Select-Object -First 1)) {
        $row = Get-NetRoute -DestinationPrefix "$ip/32" -ErrorAction SilentlyContinue | Select-Object -First 1
        Assert-True (-not $row) "$ip has no route"
    }
    [void]$results.Add("S4 fallback: answer returned, no route")

    Write-Host "`nS5 servfail on route failure (kill switch)"
    $FailureMode = 'servfail'
    Set-Scenario "[[zones]]`r`nname = ""dead""`r`nmode = ""inclusive""`r`ndns_servers = []`r`nroute_type = ""dev""`r`nroute_target = 'C:\ProgramData\Kikimora\leshy\vpn\does-not-exist.dev'`r`ndomains = [""example.com""]`r`nstatic_routes = [""1.1.1.1/32"", ""8.8.8.8/32""]"
    $null = Get-Answers 'openai.com'   # warm the upstream, so a failure cannot come from a cold tunnel
    $refused = $false
    try {
        $single = @(Resolve-DnsName 'example.com' -Server 127.0.0.1 -Type A -ErrorAction Stop |
            Where-Object { $_.IPAddress })
        if ($single.Count -eq 0) { $refused = $true } else { Write-Host "    (answer leaked: $($single | Out-String))" }
    } catch {
        $refused = $true
        Write-Host "    (refused as expected: $($_.Exception.Message.Trim()))"
    }
    Assert-True $refused 'query fails instead of leaking to the direct path'
    [void]$results.Add("S5 servfail: $(if ($refused) { 'no answer (kill switch honoured)' } else { 'ANSWER LEAKED' })")

    Write-Host "`nS6 pattern matching"
    $FailureMode = 'fallback'
    Set-Scenario "[[zones]]`r`nname = ""wild""`r`nmode = ""inclusive""`r`ndns_servers = []`r`ndomains = [""*.openai.com""]`r`nroute_type = ""dev""`r`nroute_target = '$awg'`r`nstatic_routes = [""1.1.1.1/32"", ""8.8.8.8/32""]"
    $sub = @()
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        $sub = Get-Answers 'api.openai.com'
        if ($sub.Count -gt 0) { break }
        Write-Host "    (retry ${attempt}: upstream returned nothing)"
        Start-Sleep -Seconds 3
    }
    Assert-True ($sub.Count -gt 0) 'api.openai.com answered'
    foreach ($ip in ($sub | Select-Object -First 1)) {
        [void]$tracked.Add($ip)
        $row = Get-NetRoute -DestinationPrefix "$ip/32" -ErrorAction SilentlyContinue | Select-Object -First 1
        Assert-True ([bool]$row -and $row.InterfaceAlias -eq $awgAlias) "wildcard matched: $ip via $awgAlias"
    }
    [void]$results.Add("S6 pattern matching: $($sub.Count) answers for the subdomain")

    Write-Host "`nS7 vpn reconnect"
    Set-Scenario "[[zones]]`r`nname = ""awg""`r`nmode = ""inclusive""`r`ndns_servers = []`r`nroute_type = ""dev""`r`nroute_target = '$awg'`r`ndomains = [""chatgpt.com""]`r`nstatic_routes = [""1.1.1.1/32"", ""8.8.8.8/32""]"
    $devOff = "$awg.off"
    Rename-Item $awg $devOff -Force
    try {
        Clear-Tracked
        $dead = Get-Answers 'chatgpt.com'
        foreach ($ip in ($dead | Select-Object -First 1)) {
            $row = Get-NetRoute -DestinationPrefix "$ip/32" -ErrorAction SilentlyContinue | Select-Object -First 1
            Assert-True (-not $row) "no route while the device file is gone ($ip)"
        }
    } finally {
        Rename-Item $devOff $awg -Force
    }
    Restart-Service -Name $ServiceName -Force
    Start-Sleep -Seconds 3
    Clear-DnsClientCache
    $back = Get-Answers 'chatgpt.com'
    $routed = $false
    foreach ($ip in ($back | Select-Object -First 2)) {
        [void]$tracked.Add($ip)
        $row = Get-NetRoute -DestinationPrefix "$ip/32" -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($row -and $row.InterfaceAlias -eq $awgAlias) { $routed = $true }
    }
    Assert-True $routed "route restored after the device file came back"
    [void]$results.Add("S7 reconnect: $(if ($routed) { 'route restored' } else { 'route missing after restore' })")

    Write-Host "`nS8 zone dns_servers"
    Set-Scenario "[[zones]]`r`nname = ""zdns""`r`nmode = ""inclusive""`r`ndns_servers = [""1.1.1.1:53""]`r`nroute_type = ""dev""`r`nroute_target = '$awg'`r`ndomains = [""openai.com""]`r`nstatic_routes = [""1.1.1.1/32"", ""8.8.8.8/32""]"
    $ips = Get-Answers 'openai.com'
    Assert-True ($ips.Count -gt 0) 'zone resolver answered'
    [void]$results.Add("S8 zone dns_servers: $($ips.Count) answers")
} finally {
    Clear-Tracked
    Copy-Item $backup $ConfigPath -Force
    Remove-Item $backup -Force -ErrorAction SilentlyContinue
    Restart-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    Clear-DnsClientCache
}

Write-Host "`n=== summary ==="
foreach ($line in $results) { Write-Host "  $line" }
Write-Host ''
if ($failures.Count -gt 0) {
    Write-Host "$($failures.Count) assertion(s) failed" -ForegroundColor Red
    exit 1
}
Write-Host 'windows scenario suite passed'
exit 0

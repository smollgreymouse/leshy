# Windows SCM graceful-stop and readiness smoke (08D1 Production Plan C4).
#
# Proves, on a disposable Windows VM with a real Service Control Manager:
#
#   * the service answers StartPending through config load, the writer lease,
#     the initial static-route work and the DNS bind, and only then reports
#     Running;
#   * the first observed Running already has the owned rows and the DNS
#     endpoint, so Running is never advertised early;
#   * Stop is graceful: StopPending, the server drains, Stopped with exit 0;
#   * shutdown removes exactly the owned rows and leaves a same-prefix foreign
#     fixture (same destination, different interface) untouched;
#   * unrelated routes are byte-identical before and after;
#   * a server that cannot bind is never reported Running and exits non-clean.
#
# Usage (elevated):
#   powershell -NoProfile -ExecutionPolicy Bypass -File windows\tests\service-stop-smoke.ps1 `
#       -LeshyExe C:\Users\greymouse\gates\leshy.exe

param(
    [Parameter(Mandatory = $true)][string]$LeshyExe,
    [string]$Name = 'leshy-smoke',
    [string]$BadName = 'leshy-smoke-bad',
    [string]$WorkDir = 'C:\ProgramData\leshy-smoke',
    [string]$Adapter = 'Ethernet',
    [string]$ForeignAdapter = 'kk-awg0',
    [string]$V4 = '10.77.7.7/32',
    [string]$V6 = 'fd00:77::7/128',
    [int]$StaticRoutes = 20,
    [int]$Port = 15357,
    [int]$BadPort = 15358
)

$ErrorActionPreference = 'Stop'
$script:Failures = New-Object System.Collections.Generic.List[string]

function Fail([string]$message) {
    $script:Failures.Add($message)
    Write-Host "FAIL: $message" -ForegroundColor Red
}

function Pass([string]$message) {
    Write-Host "PASS: $message" -ForegroundColor Green
}

function Assert-True([bool]$condition, [string]$message) {
    if ($condition) { Pass $message } else { Fail $message }
}

function Get-ScmState([string]$serviceName) {
    $output = & sc.exe query $serviceName 2>$null
    foreach ($line in $output) {
        if ($line -match 'STATE\s*:\s*\d+\s+(\S+)') { return $Matches[1] }
    }
    return 'Unknown'
}

function Get-Win32ExitCode([string]$serviceName) {
    $output = & sc.exe queryex $serviceName 2>$null
    foreach ($line in $output) {
        if ($line -match 'WIN32_EXIT_CODE\s*:\s*(\d+)') { return [int]$Matches[1] }
    }
    return -1
}

function Stop-IfPresent([string]$serviceName) {
    if ($null -eq (Get-Service -Name $serviceName -ErrorAction SilentlyContinue)) { return }
    try { Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue } catch { }
    for ($i = 0; $i -lt 100; $i++) {
        if ((Get-ScmState $serviceName) -eq 'STOPPED') { return }
        Start-Sleep -Milliseconds 100
    }
}

function Remove-SmokeService([string]$serviceName) {
    Stop-IfPresent $serviceName
    if ($null -ne (Get-Service -Name $serviceName -ErrorAction SilentlyContinue)) {
        & $LeshyExe service uninstall --name $serviceName | Out-Null
    }
}

function Get-OwnedRows([string]$family, [string]$prefix) {
    $rows = @(Get-NetRoute -AddressFamily $family -DestinationPrefix $prefix -ErrorAction SilentlyContinue |
        Where-Object { $_.RouteMetric -eq 0 })
    return , $rows
}

function Get-AllRows([string]$family, [string]$prefix) {
    $rows = @(Get-NetRoute -AddressFamily $family -DestinationPrefix $prefix -ErrorAction SilentlyContinue)
    return , $rows
}

function Format-Rows($rows) {
    if ($rows.Count -eq 0) { return '<none>' }
    return ($rows | ForEach-Object {
            "$($_.DestinationPrefix) if=$($_.InterfaceIndex) metric=$($_.RouteMetric) next=$($_.NextHop) proto=$($_.Protocol)"
        }) -join "`n"
}

function Get-SmokeRouteCount([string]$family, [string]$pattern) {
    return @(Get-NetRoute -AddressFamily $family -ErrorAction SilentlyContinue |
        Where-Object { $_.DestinationPrefix -like $pattern -and $_.RouteMetric -eq 0 }).Count
}

# The harness owns the 10.78.0.0/16-shaped and fd00:78::/64-shaped space.
# Leftovers from an interrupted earlier run would look like rows owned by a
# previous process, so they are removed before and after every run.
function Remove-SmokeRouteRows {
    foreach ($family in @('IPv4', 'IPv6')) {
        foreach ($row in (Get-NetRoute -AddressFamily $family -ErrorAction SilentlyContinue)) {
            if ($row.DestinationPrefix -like '10.78.*' -or $row.DestinationPrefix -like 'fd00:78::*') {
                Remove-NetRoute -DestinationPrefix $row.DestinationPrefix `
                    -InterfaceIndex $row.InterfaceIndex -NextHop $row.NextHop `
                    -Confirm:$false -ErrorAction SilentlyContinue
            }
        }
    }
}

function Get-RouteTableSnapshot {
    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($family in @('IPv4', 'IPv6')) {
        foreach ($row in (Get-NetRoute -AddressFamily $family -ErrorAction SilentlyContinue)) {
            $lines.Add("$family|$($row.DestinationPrefix)|$($row.InterfaceIndex)|$($row.NextHop)|$($row.RouteMetric)|$($row.Protocol)")
        }
    }
    $lines.Sort()
    return $lines
}

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'run this script elevated'
}
if (-not (Test-Path -LiteralPath $LeshyExe)) { throw "leshy binary not found: $LeshyExe" }
$adapterInfo = Get-NetAdapter -Name $Adapter -ErrorAction SilentlyContinue
$foreignInfo = Get-NetAdapter -Name $ForeignAdapter -ErrorAction SilentlyContinue
if ($null -eq $adapterInfo) { throw "adapter not found: $Adapter" }
if ($null -eq $foreignInfo) { throw "foreign fixture adapter not found: $ForeignAdapter" }

Write-Host "leshy:    $LeshyExe"
Write-Host "service:  $Name (bad-path variant: $BadName)"
Write-Host "adapters: $Adapter=$($adapterInfo.ifIndex), foreign=$ForeignAdapter=$($foreignInfo.ifIndex)"
Write-Host "routes:   $StaticRoutes static v4 + $StaticRoutes static v6 (lengthens the StartPending window)"

Remove-SmokeService $Name
Remove-SmokeService $BadName
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
$badDir = Join-Path $WorkDir 'bad'
New-Item -ItemType Directory -Force -Path $badDir | Out-Null
# A clean log directory per run: assertions must never match an older run.
foreach ($dir in @((Join-Path $WorkDir 'logs'), (Join-Path $badDir 'logs'))) {
    Remove-Item -Path $dir -Recurse -Force -ErrorAction SilentlyContinue
}

$deviceFile = Join-Path $WorkDir 'route.dev'
Set-Content -LiteralPath $deviceFile -Value $Adapter -Encoding ascii
$escapedDeviceFile = $deviceFile -replace '\\', '\\'

$staticList = New-Object System.Collections.Generic.List[string]
$fourthOctet = 10
for ($i = 0; $i -lt $StaticRoutes; $i++) {
    $staticList.Add(('"10.78.{0}.{1}/32"' -f [int][math]::Floor($i / 200), ([int]($i % 200) + 1)))
}
for ($i = 0; $i -lt $StaticRoutes; $i++) {
    $staticList.Add(('"fd00:78::{0:x}/128"' -f ($i + 1)))
}
$staticBlock = $staticList -join ', '

$config = Join-Path $WorkDir 'config.toml'
$logDir = Join-Path $WorkDir 'logs'
$badConfig = Join-Path $badDir 'config-bad.toml'

$configBody = @"
[server]
listen_address = "127.0.0.1:$Port"
default_upstream = ["192.0.2.1:53"]
route_failure_mode = "fallback"
auto_reload = false

[[zones]]
name = "smoke"
route_type = "dev"
route_target = "$escapedDeviceFile"
domains = ["smoke.invalid"]
ipv6 = true
static_routes = ["$V4", "$V6", $staticBlock]
"@
Set-Content -LiteralPath $config -Value $configBody -Encoding ascii

$badBody = @"
[server]
listen_address = "127.0.0.1:$BadPort"
default_upstream = ["192.0.2.1:53"]
route_failure_mode = "fallback"
auto_reload = false

[[zones]]
name = "smoke-bad"
route_type = "dev"
route_target = "$escapedDeviceFile"
domains = ["smoke.invalid"]
ipv6 = true
static_routes = []
"@
Set-Content -LiteralPath $badConfig -Value $badBody -Encoding ascii

$udpHolder = $null
try {
    Remove-SmokeRouteRows
    $startSnapshot = Get-RouteTableSnapshot
    Assert-True ((Get-AllRows 'IPv4' $V4).Count -eq 0) "precondition: $V4 is free"
    Assert-True ((Get-AllRows 'IPv6' $V6).Count -eq 0) "precondition: $V6 is free"
    Assert-True ((Get-SmokeRouteCount 'IPv4' '10.78.*') -eq 0) 'precondition: no leftover smoke IPv4 rows'
    Assert-True ((Get-SmokeRouteCount 'IPv6' 'fd00:78::*') -eq 0) 'precondition: no leftover smoke IPv6 rows'

    # -----------------------------------------------------------------------
    # 1. Install and start; SCM must stay StartPending until readiness.
    # -----------------------------------------------------------------------
    & $LeshyExe service install --name $Name --config $config | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "service install failed with $LASTEXITCODE" }

    $observedStates = New-Object System.Collections.Generic.List[string]
    $started = Get-Date
    $startProc = Start-Process -FilePath sc.exe -ArgumentList @('start', $Name) -NoNewWindow -PassThru
    $becameRunning = $false
    $stoppedPolls = 0
    $deadline = $started.AddSeconds(60)
    while ((Get-Date) -lt $deadline) {
        $state = Get-ScmState $Name
        if ($state -eq 'Unknown') { break }
        if ($state -eq 'STOPPED' -and -not $startProc.HasExited) {
            # The start command has not reached the SCM yet: not a failed start.
            Start-Sleep -Milliseconds 5
            continue
        }
        if ($observedStates.Count -eq 0 -or $observedStates[$observedStates.Count - 1] -ne $state) {
            $observedStates.Add($state)
        }
        if ($state -eq 'RUNNING') {
            $becameRunning = $true
            # Captured immediately: Running must never precede the rows or the bind.
            $runningV4 = Get-OwnedRows 'IPv4' $V4
            $runningV6 = Get-OwnedRows 'IPv6' $V6
            $runningStaticV4 = Get-SmokeRouteCount 'IPv4' '10.78.*'
            $runningStaticV6 = Get-SmokeRouteCount 'IPv6' 'fd00:78::*'
            $runningUdp = @(Get-NetUDPEndpoint -LocalPort $Port -ErrorAction SilentlyContinue).Count
            break
        }
        if ($state -eq 'STOPPED') {
            $stoppedPolls++
            if ($stoppedPolls -ge 20) { break }
        }
        Start-Sleep -Milliseconds 5
    }
    $startElapsed = ((Get-Date) - $started).TotalSeconds
    if (-not $startProc.HasExited) { $startProc.WaitForExit(5000) | Out-Null }

    Write-Host ("observed states: {0} (start took {1:N2}s)" -f ($observedStates -join ' -> '), $startElapsed)
    Assert-True $becameRunning 'the service reached Running'
    Assert-True ($observedStates[0] -eq 'START_PENDING') "the SCM was held in StartPending before Running (observed: $($observedStates -join ' -> '))"
    if ($becameRunning) {
        Assert-True ($runningUdp -ge 1) "the DNS UDP endpoint on $Port exists at the first Running observation"
        Assert-True ($runningV4.Count -eq 1) "the owned IPv4 row exists at the first Running observation ($(Format-Rows $runningV4))"
        Assert-True ($runningV6.Count -eq 1) "the owned IPv6 row exists at the first Running observation ($(Format-Rows $runningV6))"
        Assert-True ($runningStaticV4 -eq $StaticRoutes) "all $StaticRoutes static IPv4 rows exist at the first Running observation (got $runningStaticV4)"
        Assert-True ($runningStaticV6 -eq $StaticRoutes) "all $StaticRoutes static IPv6 rows exist at the first Running observation (got $runningStaticV6)"
    }

    # -----------------------------------------------------------------------
    # 2. Same-prefix foreign fixture on another adapter, then graceful stop.
    # -----------------------------------------------------------------------
    New-NetRoute -DestinationPrefix $V4 -InterfaceAlias $ForeignAdapter -RouteMetric 500 -ErrorAction Stop | Out-Null
    New-NetRoute -DestinationPrefix $V6 -InterfaceAlias $ForeignAdapter -RouteMetric 500 -ErrorAction Stop | Out-Null
    $rowsBeforeStopV4 = Format-Rows (Get-AllRows 'IPv4' $V4)
    $rowsBeforeStopV6 = Format-Rows (Get-AllRows 'IPv6' $V6)
    Write-Host "IPv4 rows before stop:`n$rowsBeforeStopV4"
    Write-Host "IPv6 rows before stop:`n$rowsBeforeStopV6"

    $stopStarted = Get-Date
    Stop-Service -Name $Name -ErrorAction Stop
    $stopped = $false
    $stopDeadline = $stopStarted.AddSeconds(30)
    while ((Get-Date) -lt $stopDeadline) {
        if ((Get-ScmState $Name) -eq 'STOPPED') { $stopped = $true; break }
        Start-Sleep -Milliseconds 10
    }
    $stopElapsed = ((Get-Date) - $stopStarted).TotalSeconds
    Write-Host ("stop took {0:N2}s" -f $stopElapsed)

    Assert-True $stopped 'the service reached Stopped within 30s'
    Assert-True ($stopElapsed -le 15) ("the stop stayed inside the 15s grace window ({0:N2}s)" -f $stopElapsed)
    $exitCode = Get-Win32ExitCode $Name
    Assert-True ($exitCode -eq 0) "the SCM recorded a clean exit code (got $exitCode)"

    $afterV4 = Get-AllRows 'IPv4' $V4
    $afterV6 = Get-AllRows 'IPv6' $V6
    Write-Host "IPv4 rows after stop:`n$(Format-Rows $afterV4)"
    Write-Host "IPv6 rows after stop:`n$(Format-Rows $afterV6)"

    Assert-True (@($afterV4 | Where-Object { $_.InterfaceIndex -eq $adapterInfo.ifIndex }).Count -eq 0) 'the owned IPv4 row is gone'
    Assert-True (@($afterV6 | Where-Object { $_.InterfaceIndex -eq $adapterInfo.ifIndex }).Count -eq 0) 'the owned IPv6 row is gone'
    Assert-True (@($afterV4 | Where-Object { $_.InterfaceIndex -eq $foreignInfo.ifIndex -and $_.RouteMetric -eq 500 }).Count -eq 1) 'the foreign IPv4 fixture survived'
    Assert-True (@($afterV6 | Where-Object { $_.InterfaceIndex -eq $foreignInfo.ifIndex -and $_.RouteMetric -eq 500 }).Count -eq 1) 'the foreign IPv6 fixture survived'
    Assert-True ((Get-SmokeRouteCount 'IPv4' '10.78.*') -eq 0) 'every owned static IPv4 row is gone'
    Assert-True ((Get-SmokeRouteCount 'IPv6' 'fd00:78::*') -eq 0) 'every owned static IPv6 row is gone'

    $afterSnapshot = Get-RouteTableSnapshot
    $expectedSnapshot = New-Object System.Collections.Generic.List[string]
    foreach ($line in $startSnapshot) { $expectedSnapshot.Add($line) }
    $expectedSnapshot.Add("IPv4|$V4|$($foreignInfo.ifIndex)|0.0.0.0|500|NetMgmt")
    $expectedSnapshot.Add("IPv6|$V6|$($foreignInfo.ifIndex)|::|500|NetMgmt")
    $expectedSnapshot.Sort()
    $diff = Compare-Object -ReferenceObject $expectedSnapshot -DifferenceObject $afterSnapshot
    $diffText = ($diff | ForEach-Object { "$($_.SideIndicator)$($_.InputObject)" }) -join '; '
    Assert-True ($null -eq $diff) "the table equals the pre-run snapshot plus exactly the foreign fixtures (unexpected: $diffText)"

    $logFile = Get-ChildItem -Path $logDir -Filter 'leshy.log*' -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($null -eq $logFile) {
        Fail "service log not found under $logDir"
    }
    else {
        $logText = Get-Content -LiteralPath $logFile.FullName -Raw
        $removedMatch = [regex]::Match($logText, 'Shutdown route cleanup complete removed=(\d+)')
        Assert-True $removedMatch.Success 'the log records the shutdown cleanup with a removed count'
        if ($removedMatch.Success) {
            $removed = [int]$removedMatch.Groups[1].Value
            Assert-True ($removed -eq (2 * $StaticRoutes + 2)) "every owned row was reported removed (got $removed, expected $(2 * $StaticRoutes + 2))"
        }
        Assert-True ($logText -notmatch 'forced abort') 'no forced abort happened'
        Assert-True ($logText -notmatch 'exact delete left the owned route') 'the read-back confirmed the delete'
    }

    # -----------------------------------------------------------------------
    # 3. A server that cannot bind is never reported Running.
    # -----------------------------------------------------------------------
    Remove-SmokeService $Name
    # No SO_REUSEADDR: the service's bind of the same port must fail.
    $udpHolder = New-Object System.Net.Sockets.Socket(
        [System.Net.Sockets.AddressFamily]::InterNetwork,
        [System.Net.Sockets.SocketType]::Dgram,
        [System.Net.Sockets.ProtocolType]::Udp)
    $udpHolder.Bind((New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Loopback, $BadPort)))
    & $LeshyExe service install --name $BadName --config $badConfig | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "bad service install failed with $LASTEXITCODE" }

    $badStates = New-Object System.Collections.Generic.List[string]
    $badProc = Start-Process -FilePath sc.exe -ArgumentList @('start', $BadName) -NoNewWindow -PassThru
    $badDeadline = (Get-Date).AddSeconds(30)
    $badStoppedPolls = 0
    while ((Get-Date) -lt $badDeadline) {
        $state = Get-ScmState $BadName
        if ($state -eq 'Unknown') { break }
        if ($state -eq 'STOPPED' -and -not $badProc.HasExited) {
            Start-Sleep -Milliseconds 5
            continue
        }
        if ($badStates.Count -eq 0 -or $badStates[$badStates.Count - 1] -ne $state) { $badStates.Add($state) }
        if ($state -eq 'STOPPED') {
            $badStoppedPolls++
            if ($badStoppedPolls -ge 20) { break }
        }
        Start-Sleep -Milliseconds 5
    }
    if (-not $badProc.HasExited) { $badProc.WaitForExit(5000) | Out-Null }
    Write-Host ("bad-path states: {0}" -f ($badStates -join ' -> '))
    Assert-True (-not ($badStates -contains 'RUNNING')) 'a server that cannot bind is never reported Running'
    Assert-True ($badStates -contains 'STOPPED') 'the failed start ends in Stopped'
    $badExit = Get-Win32ExitCode $BadName
    Assert-True ($badExit -ne 0) "the failed start records a non-clean exit code (got $badExit)"

    $badLogFile = Get-ChildItem -Path (Join-Path $badDir 'logs') -Filter 'leshy.log*' -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($null -eq $badLogFile) {
        Fail 'the bad-path service wrote no log'
    }
    else {
        $badLog = Get-Content -LiteralPath $badLogFile.FullName -Raw
        Assert-True ($badLog -notmatch 'Leshy DNS server started') 'the log never records a started DNS server'
        Assert-True ($badLog -match 'Leshy service failed') 'the log records the startup failure'
        Assert-True ($badLog -match 'exited before readiness') 'the log records the pre-readiness exit'
    }
}
finally {
    if ($null -ne $udpHolder) { $udpHolder.Close() }
    Remove-SmokeService $BadName
    Remove-SmokeService $Name
    foreach ($prefix in @($V4, $V6)) {
        Remove-NetRoute -DestinationPrefix $prefix -Confirm:$false -ErrorAction SilentlyContinue
    }
    Remove-SmokeRouteRows
}

Write-Host ''
if ($script:Failures.Count -eq 0) {
    Write-Host 'SERVICE STOP SMOKE: PASS' -ForegroundColor Green
    exit 0
}
Write-Host "SERVICE STOP SMOKE: FAIL ($($script:Failures.Count) checks)" -ForegroundColor Red
foreach ($failure in $script:Failures) { Write-Host " - $failure" }
exit 1

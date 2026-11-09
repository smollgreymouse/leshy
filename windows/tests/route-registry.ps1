#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Native Windows route-registry acceptance (08D1 §41.3 / rescue R5).

.DESCRIPTION
    Runs the prebuilt `windows_route_registry` test binary elevated against a
    disposable adapter and disposable TEST-NET prefixes, and fails if any
    unrelated route changed.

    The binary must be built from the exact SHA under test:
        cargo test --test windows_route_registry --no-run
        windows/tests/route-registry.ps1 -TestBin <target/debug/deps/...exe> `
            -Adapter kk-awg0 -OtherAdapter Ethernet -Sha <40-char SHA>

    No cargo/rustup is required here: like the Linux netns harness, the build
    happens as the normal user and only the already-built binary runs elevated.
#>
param(
    [Parameter(Mandatory = $true)][string]$TestBin,
    [Parameter(Mandatory = $true)][string]$Adapter,
    [Parameter(Mandatory = $true)][string]$OtherAdapter,
    [string]$Sha = $env:LESHY_WIN_TEST_SHA
)

$ErrorActionPreference = "Stop"

function Fail([string]$message) {
    Write-Host "FAIL: $message" -ForegroundColor Red
    exit 1
}

function Snapshot-Routes {
    Get-NetRoute -ErrorAction SilentlyContinue |
        ForEach-Object { "$($_.AddressFamily)|$($_.DestinationPrefix)|$($_.ifIndex)|$($_.NextHop)|$($_.RouteMetric)" } |
        Where-Object { $_ -notmatch "198\.18\.77\.1/32" -and $_ -notmatch "fd00:77::1/128" } |
        Sort-Object
}

if (-not (Test-Path -LiteralPath $TestBin)) {
    Fail "test binary not found: $TestBin"
}
if (-not $env:LESHY_WIN_TEST_SHA -and $Sha) {
    $env:LESHY_WIN_TEST_SHA = $Sha
}

$primary = Get-NetAdapter -Name $Adapter -ErrorAction SilentlyContinue
if (-not $primary) { Fail "disposable adapter '$Adapter' does not exist" }
$secondary = Get-NetAdapter -Name $OtherAdapter -ErrorAction SilentlyContinue
if (-not $secondary) { Fail "second adapter '$OtherAdapter' does not exist" }
if ($primary.ifIndex -eq $secondary.ifIndex) { Fail "'$Adapter' and '$OtherAdapter' must be different adapters" }
if ($primary.Status -ne "Up") { Fail "adapter '$Adapter' is not Up (status: $($primary.Status))" }

# Never improvise against a production path: the disposable adapter must not
# carry a default route.
$defaultRoutes = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue
if ($defaultRoutes -and ($defaultRoutes.ifIndex -contains $primary.ifIndex)) {
    Fail "refusing: '$Adapter' carries the IPv4 default route"
}

Write-Host "Windows native route-registry acceptance"
Write-Host "  SHA:        $($env:LESHY_WIN_TEST_SHA)"
Write-Host "  adapter:    $Adapter (ifIndex $($primary.ifIndex))"
Write-Host "  foreign on: $OtherAdapter (ifIndex $($secondary.ifIndex))"
Write-Host "  binary:     $TestBin"

$before = Snapshot-Routes

$env:LESHY_WIN_ROUTE_TEST = "1"
$env:LESHY_WIN_TEST_ADAPTER = $Adapter
$env:LESHY_WIN_TEST_OTHER_ADAPTER = $OtherAdapter

& $TestBin --ignored --test-threads=1 --nocapture
$code = $LASTEXITCODE

$after = Snapshot-Routes
if ($code -ne 0) {
    Fail "acceptance binary failed with exit code $code"
}

$diff = Compare-Object -ReferenceObject $before -DifferenceObject $after
if ($diff) {
    $diff | Format-Table -AutoSize | Out-String | Write-Host
    Fail "unrelated routes changed during the acceptance"
}

Write-Host "PASS: native Windows route-registry acceptance ($($env:LESHY_WIN_TEST_SHA))" -ForegroundColor Green
exit 0

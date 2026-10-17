# Registers the leshy Windows service from a portable (unzipped) package.
# Run from an ELEVATED PowerShell, from the directory containing leshy.exe.
$ErrorActionPreference = "Stop"

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { throw "Run this script from an elevated (Administrator) PowerShell." }

$here = $PSScriptRoot
$exe = Join-Path $here "leshy.exe"
if (-not (Test-Path $exe)) { throw "leshy.exe not found next to this script." }

# Machine-wide data layout: C:\ProgramData\leshy
$dataDir = Join-Path $env:ProgramData "leshy"
New-Item (Join-Path $dataDir "run"), (Join-Path $dataDir "logs") -ItemType Directory -Force | Out-Null

$config = Join-Path $dataDir "config.toml"
if (Test-Path $config) {
    Write-Host "Keeping existing config: $config"
} else {
    Copy-Item (Join-Path $here "default-config.toml") $config
    Write-Host "Wrote default config: $config"
}

& $exe service install --name leshy --config $config
if ($LASTEXITCODE -ne 0) { throw "service install failed with exit code $LASTEXITCODE" }

Write-Host ""
Write-Host "Start the service with:  sc.exe start leshy"
Write-Host "Logs:                    $(Join-Path $dataDir 'logs')\leshy.log"

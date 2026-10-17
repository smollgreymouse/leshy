# Stops and removes the leshy Windows service.
# Run from an ELEVATED PowerShell. C:\ProgramData\leshy (config, device files,
# logs) is intentionally kept.
$ErrorActionPreference = "Stop"

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { throw "Run this script from an elevated (Administrator) PowerShell." }

$here = $PSScriptRoot
$exe = Join-Path $here "leshy.exe"
if (-not (Test-Path $exe)) { $exe = Join-Path (Join-Path $env:ProgramFiles "leshy") "leshy.exe" }
if (-not (Test-Path $exe)) { throw "leshy.exe not found (portable dir or C:\Program Files\leshy)." }

& $exe service uninstall --name leshy
if ($LASTEXITCODE -ne 0) { throw "service uninstall failed with exit code $LASTEXITCODE" }

Write-Host ""
Write-Host "Config, device files and logs under C:\ProgramData\leshy are kept."

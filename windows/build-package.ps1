# Builds the Windows installable package:
#   windows/dist/leshy-<version>-x64-setup.exe            (NSIS installer)
#   windows/dist/leshy-<version>-windows-x64-portable.zip (portable bundle)
#
# Requires: Rust (cargo) on PATH. For the installer step, makensis.exe is
# looked up in this order: $MakensisPath parameter, PATH, standard NSIS
# install locations. See windows/README.md for a portable NSIS setup.
[CmdletBinding()]
param(
    [string]$MakensisPath = ""
)

$ErrorActionPreference = "Stop"
$windowsDir = $PSScriptRoot
$repoRoot = Split-Path -Parent $windowsDir

# 1. Version from Cargo.toml (first `version = "..."` under [package]).
$cargoToml = Get-Content (Join-Path $repoRoot "Cargo.toml") -Raw
$version = [regex]::Match($cargoToml, '(?m)^version = "([^"]+)"').Groups[1].Value
if (-not $version) { throw "Could not read version from Cargo.toml" }
Write-Host "Packaging Leshy $version"

# 2. Release build.
Push-Location $repoRoot
try {
    cargo build --release
    if ($LASTEXITCODE -ne 0) { throw "cargo build --release failed" }
} finally {
    Pop-Location
}

# 3. Stage the payload.
$stage = Join-Path $windowsDir "stage"
$dist = Join-Path $windowsDir "dist"
Remove-Item $stage, $dist -Recurse -Force -ErrorAction SilentlyContinue
New-Item $stage, $dist -ItemType Directory -Force | Out-Null

$payload = @(
    "target\release\leshy.exe",
    "config.example.toml",
    "LICENSE",
    "windows\default-config.toml",
    "windows\install-service.ps1",
    "windows\uninstall-service.ps1"
)
foreach ($item in $payload) {
    Copy-Item (Join-Path $repoRoot $item) $stage
}

# 4. Installer via NSIS. Optional: without makensis only the portable bundle is
# built, which is the documented fallback for machines that cannot install NSIS.
$candidates = @()
if ($MakensisPath) { $candidates += $MakensisPath }
$cmd = Get-Command makensis.exe -ErrorAction SilentlyContinue
if ($cmd) { $candidates += $cmd.Source }
$bases = @($env:ProgramFiles, ${env:ProgramFiles(x86)})
if ($env:LOCALAPPDATA) { $bases += (Join-Path $env:LOCALAPPDATA "Programs") }
foreach ($base in $bases) {
    if ($base) { $candidates += (Join-Path $base "NSIS\makensis.exe") }
}
$makensis = $candidates | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
if ($makensis) {
    Push-Location $windowsDir
    try {
        & $makensis /DVERSION=$version ".\leshy.nsi"
        if ($LASTEXITCODE -ne 0) { throw "makensis failed with exit code $LASTEXITCODE" }
    } finally {
        Pop-Location
    }
} elseif ($MakensisPath) {
    throw "makensis.exe not found at the given -MakensisPath"
} else {
    Write-Warning "makensis.exe not found: skipping the installer, building the portable bundle only."
}

# 5. Portable zip (same payload, service scripts instead of an installer).
Compress-Archive -Path (Join-Path $stage "*") `
    -DestinationPath (Join-Path $dist "leshy-$version-windows-x64-portable.zip") -Force

Write-Host "`nArtifacts:"
Get-ChildItem $dist | ForEach-Object { Write-Host ("  " + $_.FullName) }

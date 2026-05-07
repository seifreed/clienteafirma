#requires -Version 5
<#
.SYNOPSIS
    Repack a fresh certutil.windows.zip for Autofirma's configurator using the
    Mozilla NSS toolkit shipped inside a Mozilla Firefox installation.

.DESCRIPTION
    Mozilla does not publish standalone NSS binaries for Windows. Firefox
    installs include certutil.exe and the NSS DLLs under its program directory
    (or under Firefox/NSS in some builds). This script extracts a known-good
    copy from a local Firefox installation and packs it with the same structure
    as the legacy bundle expected by ConfiguratorFirefoxWindows.java.

.PARAMETER FirefoxRoot
    Path to a local Mozilla Firefox installation. Defaults to
    "C:\Program Files\Mozilla Firefox".

.PARAMETER Output
    Output zip path. Defaults to ".\certutil.windows.zip".

.NOTES
    Prerequisite: Firefox installed locally (or any other directory containing
    a recent NSS toolkit binary).

    M3.4 — Autofirma modernization, 2026-05-07. Replaces the 2010-era binaries.

.EXAMPLE
    .\scripts\repack-nss-windows.ps1
#>
[CmdletBinding()]
param(
    [string]$FirefoxRoot = "C:\Program Files\Mozilla Firefox",
    [string]$Output      = ".\certutil.windows.zip"
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path $FirefoxRoot)) {
    Write-Error "Firefox not found at $FirefoxRoot. Pass -FirefoxRoot <path> or install Firefox."
    exit 1
}

$Required = @(
    'certutil.exe',
    'nss3.dll',
    'nssutil3.dll',
    'nspr4.dll',
    'plc4.dll',
    'plds4.dll',
    'smime3.dll',
    'ssl3.dll',
    'softokn3.dll',
    'freebl3.dll',
    'nssckbi.dll',
    'nssdbm3.dll',
    'sqlite3.dll'
)

$WorkDir = New-Item -ItemType Directory -Path (Join-Path $env:TEMP "nss-win-$([Guid]::NewGuid().ToString('N').Substring(0,8))")
$Stage   = New-Item -ItemType Directory -Path (Join-Path $WorkDir 'certutil')

Write-Host ">>> Firefox root: $FirefoxRoot"
Write-Host ">>> Working dir:  $WorkDir"
Write-Host ">>> Output:       $Output"

$Missing = @()
foreach ($name in $Required) {
    $found = $null
    foreach ($candidate in @(
            (Join-Path $FirefoxRoot $name),
            (Join-Path $FirefoxRoot "NSS\$name"),
            (Join-Path $FirefoxRoot "bin\$name")
        )) {
        if (Test-Path $candidate) {
            $found = $candidate
            break
        }
    }
    if ($null -ne $found) {
        Copy-Item -Path $found -Destination (Join-Path $Stage $name)
    } else {
        $Missing += $name
    }
}

if ($Missing.Count -gt 0) {
    Write-Warning "The following NSS components were not found in $FirefoxRoot and will not be in the bundle:"
    $Missing | ForEach-Object { Write-Warning "  - $_" }
    Write-Warning "Some certutil features may fail at runtime."
}

Write-Host ">>> Bundle contents:"
Get-ChildItem $Stage | Format-Table Name, Length, LastWriteTime

Compress-Archive -Path (Join-Path $WorkDir 'certutil') -DestinationPath $Output -Force
Write-Host ">>> Wrote: $Output"

Remove-Item -Recurse -Force $WorkDir

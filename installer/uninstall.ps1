# Local Chrome Extension Auditor - Uninstaller (134)
# Removes ONLY this product's artifacts. Chrome itself, unrelated policies and
# unrelated registry entries are never touched.

param(
    [string]$PackageDir = (Split-Path -Parent $PSScriptRoot),
    [switch]$KeepData
)

$ErrorActionPreference = "Continue"
$HostName = "com.local.extensionauditor.scanner"
$DataDir = Join-Path $env:LOCALAPPDATA "LocalExtensionAuditor"

Write-Host "Removing native messaging host registration..."
$regKey = "HKCU:\Software\Google\Chrome\NativeMessagingHosts\$HostName"
if (Test-Path $regKey) {
    Remove-Item -Path $regKey -Recurse -Force
    Write-Host "  removed: $regKey" -ForegroundColor Green
} else {
    Write-Host "  not registered (nothing to remove)"
}

# remove generated host manifest (inside the package)
$hostManifest = Join-Path $PackageDir "native\$HostName.json"
if (Test-Path $hostManifest) {
    Remove-Item $hostManifest -Force
    Write-Host "  removed: $hostManifest" -ForegroundColor Green
}

# local database / reports / logs (64: users may delete all audit history)
if (-not $KeepData) {
    $answer = Read-Host "Delete local audit data (scans, snapshots, reports) at $DataDir ? (y/N)"
    if ($answer -eq "y" -or $answer -eq "Y") {
        if (Test-Path $DataDir) {
            Remove-Item $DataDir -Recurse -Force
            Write-Host "  removed: $DataDir" -ForegroundColor Green
        }
    } else {
        Write-Host "  kept: $DataDir"
    }
}

# Start Menu shortcut
$lnk = Join-Path ([Environment]::GetFolderPath("Programs")) "Local Extension Auditor.lnk"
if (Test-Path $lnk) { Remove-Item $lnk -Force; Write-Host "  removed: $lnk" -ForegroundColor Green }

Write-Host ""
Write-Host "Uninstall completed." -ForegroundColor Green
Write-Host "Remaining manual steps (Chrome does not allow programs to remove extensions):"
Write-Host "  1. Open chrome://extensions"
Write-Host "  2. Find 'Local Chrome Extension Auditor' and click Remove"
Write-Host "  3. Delete this extracted package folder when you no longer need it"
Write-Host ""
Write-Host "This uninstaller never modifies Chrome itself, unrelated policies or other extensions."

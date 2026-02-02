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

:: 3. CRASH-PROOF LOADER
set "PS_CMD=$f=[System.IO.Path]::GetFullPath('%~f0'); iex ((Get-Content -LiteralPath $f) | Where-Object {$found -or $_ -match '^#PS_START'} | ForEach-Object {$found=$true; $_} | Out-String)"

:: Inject shortcut status
powershell -NoProfile -ExecutionPolicy Bypass -Command "%PS_CMD%"
exit /b
#>

#PS_START
$ProgressPreference = 'SilentlyContinue'

# --- SECURITY PROTOCOL (Fix for GitHub Downloads) ---
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13

# --- Filename Restoration (Fix GAMELA~2.BAT Bug) ---
if ($f -match "GAMELA~") {
    $correctName = Join-Path (Split-Path $f) "game launcher.bat"
    if (-not (Test-Path $correctName)) {
        try {
            Rename-Item $f "game launcher.bat" -ErrorAction SilentlyContinue
            $f = $correctName
        } catch {}
    }
}

# --- Admin Detection ---
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

# --- UI Enhancement ---
try {
    # Set modern window size
    $width = 120; $height = 35
    $size = New-Object System.Management.Automation.Host.Size($width, $height)
    $Host.UI.RawUI.WindowSize = $size
    $Host.UI.RawUI.BufferSize = $size
    
    # Add Antivirus Exclusions (Admin only)
    if ($isAdmin) {
        Write-Host "      [AV] Adding Windows Defender exclusions..." -ForegroundColor Gray
        Add-MpPreference -ExclusionPath $localAppData -ErrorAction SilentlyContinue
        Add-MpPreference -ExclusionProcess $gameExe -ErrorAction SilentlyContinue
    }
} catch {}

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
$API_HOST = "https://hytaleapi.online"
$AUTH_URL_SESSIONS = "https://auth.sanasol.ws"
$global:AUTH_URL_CURRENT = $AUTH_URL_SESSIONS

# Patching Defaults
$ORIGINAL_DOMAIN = "hytale.com"
$DEFAULT_NEW_DOMAIN = "auth.sanasol.ws"

$OFFICIAL_BASE = "https://game-patches.hytale.com/patches"
$ZIP_FILENAME = "latest.zip"

$localAppData = "$env:LOCALAPPDATA\HytaleF2P"
$PublicConfig = "C:\Users\Public\HytaleF2P"
$pathConfigFile = Join-Path $localAppData "path_config.json"

function Invoke-PathDialog {
    # Show folder browser dialog to select Hytale installation
    Add-Type -AssemblyName System.Windows.Forms
    
    $dialog = New-Object System.Windows.Forms.FolderBrowserDialog
    $dialog.Description = "Select your 'Hytale F2P Launcher' installation folder (or the 'Client' folder)"
    $dialog.ShowNewFolderButton = $true  # Allow creating new folders
    
    # Try to bring to front
    $owner = New-Object System.Windows.Forms.NativeWindow
    $owner.AssignHandle([System.Diagnostics.Process]::GetCurrentProcess().MainWindowHandle)
    
    $result = $dialog.ShowDialog($owner)
    
    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        $userInput = $dialog.SelectedPath
        
        # Special case: If user selected drive root (e.g., C:\), create HytaleF2P folder
        if ($userInput -match "^[A-Z]:\\$") {
            $userInput = Join-Path $userInput "HytaleF2P"
            Write-Host "`n      [INFO] Drive root selected. Using: $userInput" -ForegroundColor Cyan
        }
        
        # Smart Check: Direct selection OR Root selection
        $pRoot = Join-Path $userInput "release\package\game\latest\Client\HytaleClient.exe"
        $pDirect = Join-Path $userInput "HytaleClient.exe"
        
        $potential = if (Test-Path $pRoot) { 
            $pRoot 
        } elseif (Test-Path $pDirect) { 
            $pDirect 
        } else { 
            # Game doesn't exist - assume user wants to install here
            Write-Host "`n      [INFO] Game not found at selected location." -ForegroundColor Cyan
            Write-Host "              Will use this folder for fresh installation." -ForegroundColor Gray
            
            # Determine if they selected a root folder or client folder
            # If path ends with "Client", assume it's the Client folder
            if ($userInput -match "\\Client$") {
                $clientPath = Join-Path $userInput "HytaleClient.exe"
            } else {
                # Use standard structure
                $clientPath = Join-Path $userInput "release\package\game\latest\Client\HytaleClient.exe"
            }
            
            # Create directory structure if it doesn't exist
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
            # Save for next time
            if (-not (Test-Path $localAppData)) { New-Item -ItemType Directory $localAppData -Force | Out-Null }
            $obj = @{ gamePath = $potential }
            $obj | ConvertTo-Json | Out-File $pathConfigFile
            return $potential
        } else {
            Write-Host "`n      [ERROR] Could not determine valid installation path." -ForegroundColor Red
            Start-Sleep -Seconds 3
            return $null
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
    
    $dialog = New-Object System.Windows.Forms.FolderBrowserDialog
    $dialog.Description = "Select installation folder (can be empty for fresh install)"
    $dialog.ShowNewFolderButton = $true
    
    # Try to bring to front
    $owner = New-Object System.Windows.Forms.NativeWindow
    $owner.AssignHandle([System.Diagnostics.Process]::GetCurrentProcess().MainWindowHandle)
    
    $result = $dialog.ShowDialog($owner)
    
    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        $userInput = $dialog.SelectedPath
        
        # Special case: If user selected drive root (e.g., C:\), create HytaleF2P folder
        if ($userInput -match "^[A-Z]:\\$") {
            $userInput = Join-Path $userInput "HytaleF2P"
            Write-Host "[INFO] Drive root selected. Using: $userInput" -ForegroundColor Cyan
        }
        
        # Smart Check: Direct selection OR Root selection
        $pRoot = Join-Path $userInput "release\package\game\latest\Client\HytaleClient.exe"
        $pDirect = Join-Path $userInput "HytaleClient.exe"
        
        $potential = if (Test-Path $pRoot) { 
            $pRoot 
        } elseif (Test-Path $pDirect) { 
            $pDirect 
        } else { 
            # Game doesn't exist - assume user wants to install here
            Write-Host "[INFO] Game not found at selected location." -ForegroundColor Cyan
            Write-Host "       Will use this folder for fresh installation." -ForegroundColor Gray
            
            # Determine if they selected a root folder or client folder
            if ($userInput -match "\\Client$") {
                $clientPath = Join-Path $userInput "HytaleClient.exe"
            } else {
                # Use standard structure
                $clientPath = Join-Path $userInput "release\package\game\latest\Client\HytaleClient.exe"
            }
            
            # Create directory structure if it doesn't exist
            $clientDir = Split-Path $clientPath
            if (-not (Test-Path $clientDir)) {
                try {
                    New-Item -ItemType Directory -Path $clientDir -Force | Out-Null
                    Write-Host "       Created directory structure." -ForegroundColor Green
                } catch {
                    Write-Host "[ERROR] Failed to create directory: $($_.Exception.Message)" -ForegroundColor Red
                    Start-Sleep -Seconds 3
                    return $null
                }
            }
            
            $clientPath
        }
        
        if ($potential) {
            # Save for next time
            if (-not (Test-Path $localAppData)) { New-Item -ItemType Directory $localAppData -Force | Out-Null }
            $obj = @{ gamePath = $potential }
            $obj | ConvertTo-Json | Out-File $pathConfigFile
            return $potential
        } else {
            Write-Host "[ERROR] Could not determine valid installation path." -ForegroundColor Red
            Start-Sleep -Seconds 3
        }
    }
    return $null
}

$gameExe = Resolve-GamePath
if (-not $gameExe) {
    Write-Host "[INFO] Game not found or selection skipped." -ForegroundColor Yellow
    Write-Host "       Defaulting to standard path for fresh installation." -ForegroundColor Gray
    $gameExe = Join-Path $localAppData "release\package\game\latest\Client\HytaleClient.exe"
    $forceShowMenu = $true
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

# --- Player Stats & ISP Check ---
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

# -- NODE.JS PORTED LOGIC: Player Manager & Paths --
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
    # Replicates logic from backend/core/paths.js
    $candidates = @()
    
    # Priority order from Node.js
    $candidates += Join-Path $gameLatest "Client\UserData"
    $candidates += Join-Path $gameLatest "Client\Hytale.app\Contents\UserData"
    $candidates += Join-Path $gameLatest "Hytale.app\Contents\UserData"
    $candidates += Join-Path $gameLatest "UserData"
    
    # Explicit Windows fallback
    $candidates += Join-Path $gameLatest "Client\UserData"
    
    foreach ($cand in $candidates) {
        if (Test-Path $cand) { return $cand }
    }
    
    # Default fallback: create Client\UserData
    $defaultPath = Join-Path $gameLatest "Client\UserData"
    if (-not (Test-Path $defaultPath)) {
        New-Item -ItemType Directory $defaultPath -Force | Out-Null
    }
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
    if (-not (Test-Path (Split-Path $serverJarPath))) { 
        New-Item -ItemType Directory (Split-Path $serverJarPath) -Force | Out-Null 
    }
    
    $patchFlag = "$serverJarPath.dualauth_patched"
    $targetDomain = "auth.sanasol.ws"
    $minValidSize = 1024 * 1024  # Minimum 1MB for valid JAR
    
    # Define URLs
    $releaseUrl = 'https://patcher.authbp.xyz/download/patched_release'
    $preReleaseUrl = 'https://patcher.authbp.xyz/download/patched_prerelease'
    
    # Only trust flag if JAR exists AND is valid size
    if (-not $force -and (Test-Path $patchFlag) -and (Test-Path $serverJarPath)) {
        $jarSize = (Get-Item $serverJarPath).Length
        if ($jarSize -ge $minValidSize) {
            Write-Host "      [SKIP] Server JAR already patched ($([math]::Round($jarSize/1MB, 2)) MB)" -ForegroundColor Green
            return $true
        } else {
            Write-Host "      [WARN] Flag exists but JAR is invalid/missing. Re-downloading..." -ForegroundColor Yellow
            Remove-Item $patchFlag -Force -ErrorAction SilentlyContinue
        }
    } elseif (Test-Path $patchFlag) {
        Write-Host "      [WARN] Flag exists but JAR is missing. Re-downloading..." -ForegroundColor Yellow
        Remove-Item $patchFlag -Force -ErrorAction SilentlyContinue
    }

    Write-Host "      [SERVER] Downloading Patched Server JAR ($branch)..." -ForegroundColor Cyan
    
    # Create backup of original if exists
    if (Test-Path $serverJarPath) {
        Move-Item $serverJarPath "$serverJarPath.original" -Force -ErrorAction SilentlyContinue
    }
    
    # Determine initial URL
    $url = if ($branch -eq 'pre-release') { $preReleaseUrl } else { $releaseUrl }
    $downloaded = $false
    
    # Attempt 1: Selected Branch
    if (Download-WithProgress $url $serverJarPath $false) {
        if ((Test-Path $serverJarPath) -and ((Get-Item $serverJarPath).Length -ge $minValidSize)) {
            $downloaded = $true
        } else {
             Write-Host "      [WARN] Download incomplete or corrupted." -ForegroundColor Yellow
             if (Test-Path $serverJarPath) { Remove-Item $serverJarPath -Force -ErrorAction SilentlyContinue }
        }
    }
    
    # Attempt 2: Fallback (Only if we started with Release and it failed)
    if (-not $downloaded -and $branch -eq 'release') {
        Write-Host "      [FALLBACK] Release patch failed. Attempting Pre-release version..." -ForegroundColor Yellow
        $url = $preReleaseUrl
        $branch = "pre-release" # Update branch for the flag
        
        if (Download-WithProgress $url $serverJarPath $false) {
            if ((Test-Path $serverJarPath) -and ((Get-Item $serverJarPath).Length -ge $minValidSize)) {
                $downloaded = $true
            } else {
                if (Test-Path $serverJarPath) { Remove-Item $serverJarPath -Force -ErrorAction SilentlyContinue }
            }
        }
    }
    
    # Final Success Check
    if ($downloaded) {
        $flagObj = @{ domain = $targetDomain; patchedAt = (Get-Date).ToString(); source = "PatcherHost"; branch = $branch }
        $flagObj | ConvertTo-Json | Out-File $patchFlag
        Write-Host "      [SUCCESS] Patched Server JAR installed ($branch)." -ForegroundColor Green
        return $true
    }
    
    # Final Failure: Restore backup if available
    Write-Host "      [ERROR] Server patch download failed." -ForegroundColor Red
    if (Test-Path "$serverJarPath.original") {
        Move-Item "$serverJarPath.original" $serverJarPath -Force
        Write-Host "      [INFO] Original server JAR restored." -ForegroundColor Gray
    }
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

function Get-LocalSha256($filePath) {
    if (-not (Test-Path $filePath)) { return "MISSING" }
    try { return (Get-FileHash $filePath -Algorithm SHA256).Hash } catch { return "ERROR" }
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
    if (-not (Test-Path $filePath)) { return "MISSING" }
    $hashCacheFile = $filePath + ".hashcache"
    try {
        $lastModified = (Get-Item $filePath).LastWriteTime.Ticks
        if (Test-Path $hashCacheFile) {
            $cache = Get-Content $hashCacheFile -Raw | ConvertFrom-Json
            if ($cache.lastModified -eq $lastModified) { return $cache.hash }
        }
        $actualHash = (Get-FileHash $filePath -Algorithm SHA1).Hash
        $cacheObj = @{ hash = $actualHash; lastModified = $lastModified }
        $cacheObj | ConvertTo-Json | Out-File $hashCacheFile
        return $actualHash
    } catch { return "ERROR" }
}

function Get-RemoteHash($fileName) {
    try {
        $hashUrl = "$API_HOST/api/hash/$fileName"
        $response = Invoke-RestMethod -Uri $hashUrl -Headers $global:HEADERS -Method Get -TimeoutSec 10
        return $response.hash
    } catch {
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

function Download-WithProgress($url, $destination, $useHeaders=$true) {
    # --- PHASE 1: CHECK FOR EXISTING wget.exe ---
    # Check for REAL wget.exe (not PowerShell's alias to Invoke-WebRequest)
    $wgetExe = Get-Command wget.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    
    # Also check Chocolatey bin folder directly (in case PATH isn't refreshed)
    if (-not $wgetExe) {
        $chocoWget = "C:\ProgramData\chocolatey\bin\wget.exe"
        if (Test-Path $chocoWget) {
            $wgetExe = [PSCustomObject]@{ Source = $chocoWget }
            Write-Host "      [FOUND] wget.exe in Chocolatey bin folder" -ForegroundColor Gray
        }
    }
    
    # Only try to install wget if running as admin (choco requires admin)
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    
    if (-not $wgetExe -and $isAdmin) {
        Write-Host "[SETUP] wget.exe not found. Installing via Chocolatey (Admin Mode)..." -ForegroundColor Yellow
        
        $chocoExe = "C:\ProgramData\chocolatey\bin\choco.exe"
        if (-not (Test-Path $chocoExe)) {
            # Check if choco is on PATH
            $chocoCmd = Get-Command choco -ErrorAction SilentlyContinue
            if ($chocoCmd) { $chocoExe = $chocoCmd.Source }
        }
        
        if (Test-Path $chocoExe) {
            # Run choco with timeout
            $stdoutFile = Join-Path $env:TEMP "choco_stdout_$(Get-Random).log"
            $stderrFile = Join-Path $env:TEMP "choco_stderr_$(Get-Random).log"
            try {
                $proc = Start-Process $chocoExe -ArgumentList "install wget -y --no-progress" -NoNewWindow -PassThru -RedirectStandardOutput $stdoutFile -RedirectStandardError $stderrFile
                $completed = $proc.WaitForExit(60000)  # 60s timeout
                
                if (-not $completed) {
                    Write-Host "      [TIMEOUT] Choco hung. Using HTTP fallback..." -ForegroundColor Yellow
                    try { $proc.Kill() } catch {}
                } else {
                    if (Test-Path $stdoutFile) {
                        $stdout = Get-Content $stdoutFile -Raw -ErrorAction SilentlyContinue
                        if ($stdout -and $stdout.Length -lt 2000) { Write-Host "      [CHOCO] $stdout" -ForegroundColor Gray }
                    }
                    Write-Host "      [CHOCO] Exit Code: $($proc.ExitCode)" -ForegroundColor $(if ($proc.ExitCode -eq 0) { "Green" } else { "Yellow" })
                }
            } catch {
                Write-Host "      [CHOCO ERROR] $($_.Exception.Message)" -ForegroundColor Yellow
            } finally {
                if (Test-Path $stdoutFile) { Remove-Item $stdoutFile -Force -ErrorAction SilentlyContinue }
                if (Test-Path $stderrFile) { Remove-Item $stderrFile -Force -ErrorAction SilentlyContinue }
            }
            
            # Refresh path and re-check
            $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
            $chocoWget = "C:\ProgramData\chocolatey\bin\wget.exe"
            if (Test-Path $chocoWget) {
                $wgetExe = [PSCustomObject]@{ Source = $chocoWget }
            }
        } else {
            Write-Host "      [SKIP] Chocolatey not installed. Using HTTP fallback..." -ForegroundColor Gray
        }
    } elseif (-not $wgetExe) {
        Write-Host "      [SKIP] wget not found, not admin. Using HTTP fallback..." -ForegroundColor Gray
    }

    # --- PHASE 2: TURBO ATTEMPT (wget.exe) ---
    if ($wgetExe) {
        Write-Host "`n[TURBO] Initializing wget high-speed transfer..." -ForegroundColor Cyan
        
        $dir = Split-Path $destination
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory $dir -Force | Out-Null }

        $wgetArgs = @(
            "--continue", 
            "--tries=5",          # Increased retries
            "--timeout=30", 
            "--show-progress", 
            "--no-check-certificate", 
            "--user-agent='Mozilla/5.0'",
            "--inet4-only"        # [FIX] Force IPv4 to avoid IPv6 routing issues
        )
        
        # Add auth header for API Host downloads
        if ($useHeaders -and $global:HEADERS) {
            foreach ($key in $global:HEADERS.Keys) {
                $wgetArgs += "--header=`"${key}: $($global:HEADERS[$key])`""
            }
        }
        
        $wgetArgs += @("-O", "`"$destination`"", "`"$url`"")

        try {
            # Don't redirect stderr - let progress bar show
            $proc = Start-Process $wgetExe.Source -ArgumentList $wgetArgs -Wait -NoNewWindow -PassThru
            
            if ($proc.ExitCode -eq 0) {
                Write-Host "      [SUCCESS] Turbo download complete.`n" -ForegroundColor Green
                return $true
            }
            
            Write-Host "      [WARN] Turbo transfer interrupted (Code: $($proc.ExitCode)).`n" -ForegroundColor Yellow
        } catch {
            Write-Host "      [WARN] wget failed to start: $($_.Exception.Message)`n" -ForegroundColor Yellow
        }
    }

    # --- PHASE 3: STANDARD FALLBACK (Fixed for Exceptions) [cite: 109, 110, 112] ---
    Write-Host "`n[FALLBACK] Starting memory-efficient streaming download..." -ForegroundColor Gray
    
    # Ensure modern security protocols for R2/CDN [cite: 1]
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    # Retry Loop for Fallback Stream
    $maxFallbackRetries = 3
    $currentFallbackRetry = 0
    $success = $false

    while (-not $success -and $currentFallbackRetry -lt $maxFallbackRetries) {
        $currentFallbackRetry++
        if ($currentFallbackRetry -gt 1) { 
            Write-Host "      [RETRY] Attempt $currentFallbackRetry of $maxFallbackRetries..." -ForegroundColor Yellow
            Start-Sleep -Seconds 2
        }

        $client = New-Object System.Net.Http.HttpClient
        $client.Timeout = [System.TimeSpan]::FromMinutes(120)
        
        # Add headers BEFORE URL check (required for API Host auth)
        if ($useHeaders -and $global:HEADERS) { 
            foreach ($key in $global:HEADERS.Keys) { $client.DefaultRequestHeaders.TryAddWithoutValidation($key, $global:HEADERS[$key]) } 
        }
        
        # Verify URL Access [cite: 111, 126] (Only on first try to save time)
        if ($currentFallbackRetry -eq 1) {
            try {
                $headRequest = New-Object System.Net.Http.HttpRequestMessage([System.Net.Http.HttpMethod]::Head, $url)
                $check = $client.SendAsync($headRequest).GetAwaiter().GetResult()
                if (-not $check.IsSuccessStatusCode) {
                    Write-Host "      [ERROR] URL unreachable: $($check.StatusCode)" -ForegroundColor Red
                    $client.Dispose()
                    return $false
                }
            } catch {
                Write-Host "      [ERROR] Could not connect to storage node." -ForegroundColor Red
                $client.Dispose()
                return $false
            }
        }

        $existingOffset = 0
        if (Test-Path $destination) { $existingOffset = (Get-Item $destination).Length }
        
        if ($existingOffset -gt 0) {
            try {
                $client.DefaultRequestHeaders.Range = New-Object System.Net.Http.Headers.RangeHeaderValue($existingOffset, $null)
            } catch {}
        }

        try {
            # ResponseHeadersRead prevents the memory buffering exception 
            $response = $client.GetAsync($url, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
            
            if ($response.StatusCode -eq [System.Net.HttpStatusCode]::RequestedRangeNotSatisfiable) {
                 $client.Dispose()
                 # File might be fully downloaded or corrupted, reset and retry
                 Write-Host "      [INFO] Range not satisfiable. Resetting for fresh download..." -ForegroundColor Gray
                 Remove-Item $destination -Force
                 continue # Next retry iteration will start from 0
            }
            
            if (-not $response.IsSuccessStatusCode) { 
                # Don't break immediately, might be transient? NO, status code usually definitive.
                # But let's log and retry if it's a 5xx error
                if ([int]$response.StatusCode -ge 500) { throw "Server Error" }
                $client.Dispose(); return $false 
            }
            
            $isPartial = $response.StatusCode -eq [System.Net.HttpStatusCode]::PartialContent
            $contentLength = $response.Content.Headers.ContentLength
            $totalSize = if ($isPartial) { $contentLength + $existingOffset } else { $contentLength }
            
            $stream = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
            $fileStream = if ($isPartial) { [System.IO.File]::Open($destination, [System.IO.FileMode]::Append) } 
                          else { [System.IO.File]::Create($destination) }
            
            $buffer = New-Object byte[] 4MB 
            $downloaded = if ($isPartial) { $existingOffset } else { 0 }
            $lastUpdate = $downloaded
            $startTime = [DateTime]::Now
            
            while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                $fileStream.Write($buffer, 0, $read)
                $downloaded += $read
                if ($downloaded -ge ($lastUpdate + 10MB) -or $downloaded -eq $totalSize) {
                    $lastUpdate = $downloaded
                    $percent = [math]::Floor(($downloaded / $totalSize) * 100)
                    $elapsed = ([DateTime]::Now - $startTime).TotalSeconds
                    $speed = if ($elapsed -gt 0) { [math]::Round(($downloaded - $existingOffset) / 1MB / $elapsed, 2) } else { 0 }
                    $bar = ("#" * [math]::Floor($percent/5)) + ("." * (20 - [math]::Floor($percent/5)))
                    Write-Host "`r      Progress: [$bar] $percent% ($([math]::Round($downloaded/1MB,2)) MB) @ $speed MB/s   " -NoNewline -ForegroundColor Yellow
                }
            }
            
            $success = $true
            Write-Host ""; 
        } catch { 
            Write-Host "`n      [DOWNLOAD EXCEPTION] $($_.Exception.Message)" -ForegroundColor Red
            # Loop will retry
            $success = $false
        } finally { 
            if ($fileStream) { $fileStream.Close(); $fileStream.Dispose() }
            if ($stream) { $stream.Close(); $stream.Dispose() }
            if ($client) { $client.Dispose() }
        }
    }

    return $success
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
    $api_url = "https://files.hytalef2p.com/api/version_client"
    
    # --- Try API First (Instant) ---
    # --- Try API First (Instant) ---
    try {
        Write-Host "      [API] Fetching latest client version..." -ForegroundColor Gray
        $api_res = Invoke-RestMethod -Uri $api_url -Headers @{ 'User-Agent' = 'Hytale-F2P-Launcher' } -TimeoutSec 5
        
        if ($api_res -and $api_res.client_version) {
            # Log Branch (Debug/Visibility)
            if ($api_res.branch) { Write-Host "      [BRANCH] Detected Branch: $($api_res.branch)" -ForegroundColor DarkGray }
            
            # Extract number from "7.pwr"
            if ($api_res.client_version -match "(\d+)") {
                $ver = [int]$matches[1]
                
                # [VERIFY] Check if this version actually exists on CDN before trusting API
                # This prevents loops if API is updated before CDN propagates
                $verifyUrl = "$OFFICIAL_BASE/windows/amd64/release/0/$ver.pwr"
                try {
                    $ckeckReq = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Head, $verifyUrl)
                    $checkClient = [System.Net.Http.HttpClient]::new()
                    $checkClient.Timeout = [System.TimeSpan]::FromSeconds(3)
                    $checkRes = $checkClient.SendAsync($ckeckReq).GetAwaiter().GetResult()
                    $checkClient.Dispose()
                    
                    if ($checkRes.IsSuccessStatusCode) {
                        $ver | Out-File $cacheFile
                        Write-Host "      [SUCCESS] API returned version: $ver.pwr" -ForegroundColor Green
                        return $ver
                    } else {
                        Write-Host "      [WARN] API version $ver.pwr not found (404). Output mismatch!" -ForegroundColor Yellow
                        throw "Verify Failed"
                    }
                } catch {
                    Write-Host "      [WARN] Could not verify API version. Falling back to probe..." -ForegroundColor Yellow
                    throw "Verify Failed"
                }
            }
        }
    } catch {
        Write-Host "      [WARN] API offline or invalid, switching to smart probe..." -ForegroundColor Yellow
    }

    # --- Fallback: Smart Batch-Based Probe (Infinite) ---
    $client = New-Object System.Net.Http.HttpClient
    $client.Timeout = [System.TimeSpan]::FromSeconds(3)
    
    # Load previously known highest to speed up probe
    $highestKnown = if (Test-Path $cacheFile) { [int](Get-Content $cacheFile) } else { 0 }
    $currentStart = if ($highestKnown -gt 0) { $highestKnown } else { 0 }
    
    $highestFound = $highestKnown
    $probing = $true
    $batchSize = 25

    Write-Host "      [PROBE] Scanning for patches (starting at v$currentStart)..." -ForegroundColor Gray

    while ($probing) {
        $tasks = New-Object System.Collections.Generic.List[System.Threading.Tasks.Task[System.Net.Http.HttpResponseMessage]]
        $batchRange = $currentStart..($currentStart + $batchSize)
        
        foreach ($i in $batchRange) {
            $url = "$OFFICIAL_BASE/windows/amd64/release/0/$i.pwr"
            $req = New-Object System.Net.Http.HttpRequestMessage([System.Net.Http.HttpMethod]::Head, $url)
            $tasks.Add($client.SendAsync($req))
        }

        try { [System.Threading.Tasks.Task]::WaitAll($tasks.ToArray()) } catch {}

        $foundInBatch = $false
        for ($j = $batchSize; $j -ge 0; $j--) {
            $t = $tasks[$j]
            if ($t.Status -eq 'RanToCompletion' -and $t.Result.IsSuccessStatusCode) {
                $highestFound = $batchRange[$j]
                $foundInBatch = $true
                break
            }
        }

        if (-not $foundInBatch) {
            $probing = $false # Stop when a whole batch is empty
        } else {
            $currentStart += $batchSize # Continue to next batch
        }
    }

    $client.Dispose()
    $highestFound | Out-File $cacheFile
    Write-Host "      [FOUND] Highest discovered version: $highestFound.pwr" -ForegroundColor Green
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
        Write-Host " [0] Back (Resume)" -ForegroundColor DarkGray
        Write-Host ""
        
        $netChoice = Read-Host " Select an option [0]"
        if ($netChoice -eq "") { $netChoice = "0" }
        
        switch ($netChoice) {
            "1" { Set-GameDNS "Cloudflare"; Pause }
            "2" { Set-GameDNS "Google"; Pause }
            "3" { Set-GameDNS "Auto"; Pause }
            "4" { Install-CloudflareWarp; Pause }
            "0" { $netMenuLoop = $false }
            default { $netMenuLoop = $false }
        }
    }
}

function Ensure-UserData($appDir, $cacheDir, $userDir) {
    if ($global:userDataVerified) { return $true }
    return $true
    
    $clientDir = Split-Path $userDir
    $localZip = Join-Path $clientDir "UserData.zip"
    $manifestFile = Join-Path $userDir "UserData_manifest.json"
    $savesDir = Join-Path $userDir "Saves"
    
    Write-Host "`n[SYNC] Checking UserData (UserData.zip)..." -ForegroundColor Cyan
    
    # 1. Fast-Path Check
    $needsSync = Test-FileNeedsDownload $localZip "UserData.zip"
    if (-not $needsSync -and (Test-Path $localZip) -and (Test-ZipValid $localZip) -and (Test-Path $manifestFile)) {
        try {
            $manifest = Get-Content $manifestFile -Raw | ConvertFrom-Json
            if ($manifest.zipHash -eq (Get-LocalSha1 $localZip)) {
                Write-Host "      [SKIP] UserData verified via manifest (Instant). Skipping extraction." -ForegroundColor Green
                $global:userDataVerified = $true; return $true
            }
        } catch {}
    }

    if ($needsSync) {
        Write-Host "      [DOWNLOAD] Fetching latest UserData..." -ForegroundColor Cyan
        if (-not (Download-WithProgress "$API_HOST/file/UserData.zip" $localZip)) { return $false }
    }
    
    # 2. Backup Detection (Saves)
    $backupPath = $null
    if (Test-Path $savesDir) {
        $worlds = Get-ChildItem -Path $savesDir -Directory
        if ($worlds.Count -gt 0) {
            Write-Host "`n      [DETECT] Existing world saves found in: $savesDir" -ForegroundColor Yellow
            $bChoice = Read-Host "      Do you want to backup your world data before updating game files? (y/n)"
            if ($bChoice -eq "y") {
                $backupPath = Join-Path $cacheDir "saves_backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
                New-Item -ItemType Directory $backupPath -Force | Out-Null
                Write-Host "      [BACKUP] Safely moving worlds to: $backupPath" -ForegroundColor Cyan
                Get-ChildItem -Path $savesDir | ForEach-Object { Move-Item $_.FullName $backupPath -Force }
            }
        }
    }

    # 3. Extract and Update Manifest
    Write-Host "      [EXTRACT] Applying UserData overwrites..." -ForegroundColor Cyan
    if (Expand-WithProgress $localZip $clientDir) {
        # Restore Backups
        if ($backupPath -and (Test-Path $backupPath)) {
            Write-Host "      [RESTORE] Putting your world data back..." -ForegroundColor Green
            if (-not (Test-Path $savesDir)) { New-Item -ItemType Directory $savesDir -Force | Out-Null }
            Get-ChildItem -Path $backupPath | ForEach-Object { Move-Item $_.FullName $savesDir -Force }
            Remove-Item $backupPath -Recurse -Force
        }

        try {
            $manifestObj = @{ zipHash = (Get-LocalSha1 $localZip); timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss") }
            $manifestObj | ConvertTo-Json | Out-File $manifestFile
        } catch {}
        
        Write-Host "      [SUCCESS] UserData patches applied." -ForegroundColor Green
        $global:userDataVerified = $true; return $true
    }
    return $false
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
    Write-Host "[SYNC] Converting Official Install to F2P Core..." -ForegroundColor Cyan
    if (-not (Ensure-UserData $appDir $cacheDir $userDir)) { return $false }
    
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
    $remoteLauncherHash = Get-RemoteHash "game launcher.bat"
}
catch {
    $remoteLauncherHash = $null
}

if (-not $remoteLauncherHash) {
    Write-Host "`n[WARNING] Update server is unreachable." -ForegroundColor Yellow
    Write-Host "          Unable to check for a new launcher version." -ForegroundColor Yellow
}
else {
    # $f is passed from the CMD bootstrap as the full path to this file
    $localLauncherHash = Get-LocalSha1 $f

    if ($localLauncherHash -ne $remoteLauncherHash) {
        Write-Host "`n[UPDATE] A new version of the launcher is available!" -ForegroundColor Yellow

        $tempLauncher = "$f.new"

        if (Download-WithProgress "$API_HOST/file/game%20launcher.bat" $tempLauncher $false) {
            Write-Host "      [SUCCESS] Update downloaded. Restarting launcher..." -ForegroundColor Green
            Start-Sleep -Seconds 1

            # Overwrite and restart using CMD to avoid file locks
            $cmd = "timeout /t 1 >nul & move /y `"$tempLauncher`" `"$f`" & cmd /c `"$f`""
            Start-Process cmd.exe -ArgumentList "/c $cmd" -WindowStyle Normal
            exit
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

    # REFRESH DYNAMIC PATHS based on current $gameExe
    $launcherRoot = try { Split-Path (Split-Path (Split-Path (Split-Path (Split-Path (Split-Path $gameExe))))) } catch { $localAppData }
    $appDir = Join-Path $launcherRoot "release\package\game\latest"
    $javaExe = Join-Path $launcherRoot "release\package\jre\latest\bin\java.exe"
    
    # -- NEW LOGIC: Advanced UserDir Resolution --
    $userDir = Find-UserDataPath $appDir
    Ensure-ModDirs $userDir
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
    if ((Test-Path $gameExe) -and -not $global:forceShowMenu) {
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
        if (-not (Ensure-UserData $appDir $cacheDir $userDir)) { pause; continue }
        if (-not (Ensure-JRE $launcherRoot $cacheDir)) { pause; continue }
        
    } else {
        # SHOW MENU ONLY IF MISSING OR RECOVERY NEEDED
        if (-not (Test-Path $gameExe)) {
            Write-Host "[!] Hytale is not installed or files are missing." -ForegroundColor Red
        } elseif (-not $f2pMatch) {
            Write-Host "[!] Local version does not match F2P server." -ForegroundColor Yellow
        }
        
        
        if ($global:forceShowMenu) {
            Write-Host "`n[RECOVERY] You have missing or corrupt files. Please re-download." -ForegroundColor Red
            Write-Host "            (Option [2] is highly recommended based on server hash)" -ForegroundColor Cyan
            # Don't reset here - let auto-repair logic handle it
        }

        $opt2Text = if ($global:javaMissingFlag) { "[2] FIX MISSING JAVA / Update Smart-Patch" } else { "[2] Download/Update to Hytale F2P (Smart-Patch)" }
        $opt2Color = if ($global:javaMissingFlag) { "Yellow" } else { "White" }
        Write-Host "`nAvailable Actions:" -ForegroundColor White
        Write-Host " [1] Download Official Hytale Patches (PWR)" -ForegroundColor White
        Write-Host " $opt2Text" -ForegroundColor $opt2Color
        Write-Host " [3] Attempt Force Launch anyway" -ForegroundColor Gray
        
        # Auto-select option [2] if triggered by Assets error
        if ($global:autoRepairTriggered) {
            Write-Host "`n[AUTO-REPAIR] Automatically selecting option [2] to fix Assets..." -ForegroundColor Magenta
            $choice = "2"
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
        elseif ($choice -eq "2") {
            # Reset verification flags to force full check after repair
            $global:assetsVerified = $false
            $global:depsVerified = $false

            # F2P DOWNLOAD LOGIC WITH PERSISTENT CACHE
            # Use the f2pMatch result from earlier
            $coreNeedsRepair = -not $f2pMatch
            $javaMissing = -not (Test-Path (Join-Path $launcherRoot "release\package\jre\latest\bin\java.exe"))
            
            if ($coreNeedsRepair) {
                Write-Host "`n[ACTION] Repairing/Updating F2P Core..." -ForegroundColor Magenta
                if ($f2pMatch -eq $false -and (Test-Path $gameExe)) {
                    Write-Host "      [INFO] Replacing Official PWR version with F2P Core..." -ForegroundColor Cyan
                }
                
                # Backup world saves before installation
                Write-Host "`n      [SAFETY] Protecting your world saves..." -ForegroundColor Cyan
                $worldBackup = Backup-WorldSaves $userDir
                
                # Check disk space (Zip + Extraction room)
                if (-not (Assert-DiskSpace $appDir ($REQ_CORE_SPACE * 2))) { pause; continue }
                
                $localZip = Join-Path $cacheDir $ZIP_FILENAME
                $needsDownload = Test-FileNeedsDownload $localZip $ZIP_FILENAME
                
                if ($needsDownload) {
                    Write-Host "      [DOWNLOAD] Fetching $ZIP_FILENAME..." -ForegroundColor Cyan
                    if (-not (Download-WithProgress "$API_HOST/file/$ZIP_FILENAME" $localZip)) {
                        Write-Host "      [ERROR] Download failed. Check your connection." -ForegroundColor Red
                        pause; continue
                    }
                }
                
                Write-Host "      [EXTRACT] Installing core files..." -ForegroundColor Cyan
                if (Expand-WithProgress $localZip $appDir) {
                    Write-Host "      [SUCCESS] Core package verified and installed." -ForegroundColor Green
                    
                    # Restore world saves after successful installation
                    if ($worldBackup) {
                        Write-Host "`n      [SAFETY] Restoring your protected worlds..." -ForegroundColor Cyan
                        Restore-WorldSaves $userDir $worldBackup
                    }
                } else {
                    Write-Host "      [ERROR] Extraction failed. The zip might be corrupt or files are in use." -ForegroundColor Red
                    if ($localZip) { Remove-Item $localZip -Force }
                    pause; continue
                }
            } elseif ($javaMissing) {
                Write-Host "`n[ACTION] Targeted Java Repair..." -ForegroundColor Magenta
                if (-not (Ensure-JRE $launcherRoot $cacheDir)) { pause; continue }
            } else {
                Write-Host "`n[INFO] Core and Engine look healthy. Refreshing assets..." -ForegroundColor Cyan
            }
            
            
            # Always verify assets and deps after any repair
            if (-not (Ensure-UserData $appDir $cacheDir $userDir)) { pause; continue }

            $global:javaMissingFlag = $false
            Write-Host "`n[COMPLETE] Hytale F2P is now ready!" -ForegroundColor Green
            
            # Reset flags to allow auto-launch on next iteration
            $global:forceShowMenu = $false
            $global:autoRepairTriggered = $false
            
            # Continue to restart loop and auto-launch
            continue
        }
        elseif ($choice -ne "3") { exit }
    }

# --- LAUNCH SEQUENCE ---

# Final Readiness Guard: Verify all critical files exist right before launch
if (-not (Test-Path $gameExe)) {
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
        Write-Host "`n[3/4] Authenticating..." -ForegroundColor Cyan
        Write-Host "      Endpoint: $global:AUTH_URL_CURRENT" -ForegroundColor Gray
        $authUrl = "$global:AUTH_URL_CURRENT/game-session/child" 
        $body = @{ uuid=$global:pUuid; name=$global:pName; scopes=@("hytale:server", "hytale:client") } | ConvertTo-Json
        try {
            $res = Invoke-RestMethod -Uri $authUrl -Method Post -Body $body -ContentType "application/json" -TimeoutSec 5
            $idToken = $res.identityToken; $ssToken = $res.sessionToken
            Write-Host "      [SUCCESS] Token Acquired." -ForegroundColor Green
            Save-Config # Persist successful auth endpoint
        } catch {
            $issuer = if ($global:AUTH_URL_CURRENT) { $global:AUTH_URL_CURRENT } else { "https://sessions.sanasol.ws" }
            $idToken = New-HytaleJWT $global:pUuid $global:pName $issuer
            $ssToken = $idToken
            Write-Host "      [OFFLINE] Guest mode (Generated Corrected JWT)." -ForegroundColor Yellow
            Write-Host "      [DEBUG] Reason: $($_.Exception.Message)" -ForegroundColor Gray
        }
    } else {
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

    
    # [FIX] Check for auto-repair FIRST and bypass UI
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
        if ($global:ispBlocked) {
            Write-Host " [1] Start Hytale F2P (Create Shortcut) [BLOCKED]" -ForegroundColor DarkGray
        } else {
            Write-Host " [1] Start Hytale F2P (Create Shortcut)" -ForegroundColor Green
        }
        Write-Host " [2] Server Menu (Host/Download)" -ForegroundColor Yellow
        Write-Host " [3] Repair / Force Update" -ForegroundColor Red
        Write-Host " [4] Install HyFixes (Server Crash Fixes)" -ForegroundColor Cyan
        Write-Host " [5] Play Offline (Guest Mode)" -ForegroundColor Magenta
        Write-Host " [6] Play Unauthenticated (No Login)" -ForegroundColor DarkCyan
        Write-Host " [7] Change Game Installation Path" -ForegroundColor Blue
        Write-Host ""
        
        $menuChoice = Read-Host " Select an option [1]"
        if ($menuChoice -eq "") { $menuChoice = "1" }
    }
    
    # Auto-Repair: Reset flag after selection is made
    if ($global:autoRepairTriggered) { $global:autoRepairTriggered = $false }

    switch ($menuChoice) {
        "1" {
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
            
            $localZip = Join-Path $cacheDir $ZIP_FILENAME
            $needsDownload = Test-FileNeedsDownload $localZip $ZIP_FILENAME
            
            if ($needsDownload) {
                Write-Host "      [DOWNLOAD] Fetching $ZIP_FILENAME..." -ForegroundColor Cyan
                if (-not (Download-WithProgress "$API_HOST/file/$ZIP_FILENAME" $localZip)) {
                    Write-Host "      [ERROR] Download failed. Check your connection." -ForegroundColor Red
                    $retryNet = Read-Host "      Open Network Unblocker? (y/n) [n]"
                    if ($retryNet -eq "y") { Show-NetworkFixMenu }
                    
                    Write-Host "`nPress any key to return to menu..."
                    [void][System.Console]::ReadKey($true)
                    continue
                }
            }
            
            Write-Host "      [EXTRACT] Installing core files..." -ForegroundColor Cyan
            if (Expand-WithProgress $localZip $appDir) {
                Write-Host "      [SUCCESS] Core package verified and installed." -ForegroundColor Green
                
                # Restore world saves
                if ($worldBackup) {
                    Write-Host "`n      [SAFETY] Restoring your protected worlds..." -ForegroundColor Cyan
                    Restore-WorldSaves $userDir $worldBackup
                }
                
                # Verify assets
                if (-not (Ensure-UserData $appDir $cacheDir $userDir)) { 
                    Write-Host "`nPress any key to return to menu..."
                    [void][System.Console]::ReadKey($true)
                    continue 
                }
                
                # Ensure JRE is also installed
                if (-not (Ensure-JRE $launcherRoot $cacheDir)) {
                    Write-Host "`nPress any key to return to menu..."
                    [void][System.Console]::ReadKey($true)
                    continue
                }
                
                # Check for VC++ Redistributables
                Install-VCRedist
                
                Write-Host "`n[COMPLETE] Hytale F2P is now ready!" -ForegroundColor Green
                
                # Reset flags and proceed to launch
                $global:forceShowMenu = $false
                $global:autoRepairTriggered = $false
                $proceedToLaunch = $true
                
            } else {
                Write-Host "      [ERROR] Extraction failed. The zip might be corrupt or files are in use." -ForegroundColor Red
                # Only try to remove if file exists
                if ($localZip -and (Test-Path $localZip)) { 
                    Remove-Item $localZip -Force -ErrorAction SilentlyContinue 
                }
                Write-Host "`nPress any key to return to menu..."
                [void][System.Console]::ReadKey($true)
            }
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
             # Unauthenticated mode - still use authenticated auth-mode but skip token generation
             $global:unauthenticatedMode = $true
             $proceedToLaunch = $true
        }
        "7" {
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
    if ($global:unauthenticatedMode) {
        Write-Host "      Mode:     Unauthenticated (Server Auth)" -ForegroundColor DarkCyan
    } else {
        Write-Host "      Mode:     Authenticated" -ForegroundColor Green
    }
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
    $maxWait = [int]::MaxValue # Monitor indefinitely (User Request)
    $minimized = $false

    # Add assembly for MessageBox
    Add-Type -AssemblyName System.Windows.Forms 

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
            $errors = Get-Content $nl.FullName | Where-Object { $_ -match "\|ERROR\||\|FATAL\|" -or $_ -match "VM Initialization Error" -or $_ -match "Server failed to boot" }
            foreach ($err in $errors) {
                if ($reportedErrors -notcontains $err) {
                    Write-Host "`r      [LOG ERROR] $($err.Trim())" -ForegroundColor Red
                    
                    # --- PRIORITY 0: NullReferenceException from AppMainMenu (Missing Server) ---
                    $isAppMainMenuNullRef = $err -match "AppMainMenu.*NullReferenceException" -or $err -match "HytaleClient\.Application\.AppMainMenu.*NullReferenceException"
                    
                    if ($isAppMainMenuNullRef) {
                        # Check if Server directory exists
                        $serverDir = Join-Path $appDir "Server"
                        $serverJarPath = Join-Path $serverDir "HytaleServer.jar"
                        
                        Write-Host "`n      [FIX] AppMainMenu NullReferenceException Detected!"-ForegroundColor Red
                        Write-Host "      [CHECK] Verifying Server directory exists..." -ForegroundColor Cyan
                        
                        if (-not (Test-Path $serverDir) -or -not (Test-Path $serverJarPath)) {
                            Write-Host "      [MISSING] Server directory or JAR not found at: $serverDir" -ForegroundColor Yellow
                            Write-Host "      [ACTION] Triggering Patch-HytaleServer to download..."-ForegroundColor Yellow
                            
                            $reportedErrors += $err
                            
                            # Kill current process before patching
                            Stop-Process -Id $currentProc.Id -Force -ErrorAction SilentlyContinue
                            Start-Sleep -Seconds 1
                            
                            if (Patch-HytaleServer $serverJarPath) {
                                Write-Host "      [SUCCESS] Server installed! Restarting game..." -ForegroundColor Green
                                Start-Sleep -Seconds 2
                                $global:forceRestart = $true
                                $stable = $false
                                break
                            } else {
                                Write-Host "      [ERROR] Failed to install server. Manual intervention required." -ForegroundColor Red
                            }
                        } else {
                            Write-Host "      [INFO] Server directory exists. Issue may be something else." -ForegroundColor Gray
                            $reportedErrors += $err
                        }
                    }
                    # --- PRIORITY 1: JWT/TOKEN VALIDATION ERRORS (Check full log for root cause) ---
                    # When "Server failed to boot" occurs, first check if it's actually a JWT issue
                    $isJwtError = $logContent -match "Token validation failed" -or $logContent -match "signature verification failed" -or $logContent -match "No Ed25519 key found"
                    
                    if ($isJwtError) {
                        # --- FIX FOR SERVER JWT VALIDATION FAILURE ---
                        Write-Host "`n      [FIX] Server Token Validation Error Detected (Root Cause)!" -ForegroundColor Red
                        Write-Host "      [INFO] Server is missing authentication keys. Attempting repair..." -ForegroundColor Cyan
                        
                        $reportedErrors += $err
                        $serverJarPath = Join-Path $appDir "Server\HytaleServer.jar"
                        
                        # Determine currently installed branch
                        $currentBranch = "release"
                        if (Test-Path "$serverJarPath.dualauth_patched") {
                            try { $currentBranch = (Get-Content "$serverJarPath.dualauth_patched" -Raw | ConvertFrom-Json).branch } catch {}
                            if (-not $currentBranch) { $currentBranch = "release" }
                        }
                        
                        # LOGIC:
                        # 1. If not patched this session: Force re-download current branch.
                        # 2. If patched "release" and failed again: Switch to "pre-release".
                        # 3. If patched "pre-release" and failed again: Give up.
                        
                        $targetBranch = $null
                        
                        if (-not $global:serverPatched) {
                            Write-Host "      [ACTION] Force updating current branch ($currentBranch)..." -ForegroundColor Yellow
                            $targetBranch = $currentBranch
                        } elseif ($global:serverPatched -eq "release") {
                            Write-Host "      [FIX] Release patch failed to resolve issue. Switching to PRE-RELEASE..." -ForegroundColor Magenta
                            $targetBranch = "pre-release"
                        } else {
                            Write-Host "      [INFO] Server already patched ($global:serverPatched) but issue persists. Manual fix required." -ForegroundColor Gray
                        }
                        
                        if ($targetBranch) {
                            Stop-Process -Id $currentProc.Id -Force -ErrorAction SilentlyContinue
                            Start-Sleep -Seconds 1
                            
                            if (Patch-HytaleServer $serverJarPath $targetBranch $true) {
                                $global:serverPatched = $targetBranch
                                Write-Host "      [SUCCESS] Server patched ($targetBranch)! Restarting game..." -ForegroundColor Green
                                
                                Start-Sleep -Seconds 2
                                $global:forceRestart = $true
                                $stable = $false
                                break
                            } else {
                                Write-Host "      [ERROR] Failed to patch server. Manual intervention required." -ForegroundColor Red
                            }
                        }
                    }
                    # --- PRIORITY 2: VM/JRE ERRORS (Only if NOT a JWT error) ---
                    elseif ($err -match "VM Initialization Error" -or $err -match "Failed setting boot class path" -or $err -match "Server failed to boot") {
                        
                        Write-Host "`n      [AUTO-RECOVERY] Critical boot failure detected!" -ForegroundColor Magenta
                        Write-Host "      [ERROR] $($err.Trim())" -ForegroundColor Red
                        
                        [System.Windows.Forms.MessageBox]::Show(
                            "Boot Error Detected!`n$($err.Trim())`n`nAttempting auto-fix...", 
                            "Hytale Auto-Recovery", 
                            [System.Windows.Forms.MessageBoxButtons]::OK, 
                            [System.Windows.Forms.MessageBoxIcon]::Warning, 
                            [System.Windows.Forms.MessageBoxDefaultButton]::Button1, 
                            [System.Windows.Forms.MessageBoxOptions]::ServiceNotification
                        ) | Out-Null
                        
                        Write-Host "      [ACTION] Killing process to attempt repairs..." -ForegroundColor Yellow
                        # Fix: Use $currentProc.Id explicitly as $cp might be unstable if process is mid-crash
                        Stop-Process -Id $currentProc.Id -Force -ErrorAction SilentlyContinue
                        
                        $logContent = Get-Content $nl.FullName -Raw -ErrorAction SilentlyContinue
                        $cacheFixed = $false

                        # --- A. CACHE CLEANING ---
                        if ($logContent -match "Found AOT cache, enabling for faster startup: (.+)") {
                            $aotFile = $matches[1].Trim()
                            if (Test-Path $aotFile) {
                                Write-Host "      [FIX] Deleting corrupted AOT Cache: $aotFile" -ForegroundColor Yellow
                                Remove-Item $aotFile -Force -ErrorAction SilentlyContinue
                                $cacheFixed = $true
                            }
                        }
                        if (-not $cacheFixed -and $logContent -match '--prefab-cache="([^"]+)"') {
                            $prefabDir = $matches[1].Trim()
                            if (Test-Path $prefabDir) {
                                Write-Host "      [FIX] Deleting potential corrupted Prefab Cache: $prefabDir" -ForegroundColor Yellow
                                Remove-Item $prefabDir -Recurse -Force -ErrorAction SilentlyContinue
                                $cacheFixed = $true
                            }
                        }

                        if ($cacheFixed) {
                            Write-Host "[SUCCESS] Cache cleanup complete. Restarting..." -ForegroundColor Green
                            Start-Sleep -Seconds 2
                            $stable = $false; 
                            $global:forceRestart = $true
                            $global:autoRepairTriggered = $true # [FIX] Auto-trigger repair after cache cleanup
                            break
                        }

                        # --- B. ADVANCED JAVA REPAIR ---
                        if ($err -match "Failed setting boot class path" -or $err -match "VM Initialization Error" -or $err -match "Server failed to boot") {
                            # New Logic: Delete Corrupted JRE to Force Re-download
                            # SMART-SWITCH: Mark session to use API Host, Delete JRE, Restart Loop
                            Write-Host "      [FIX] JRE Corruption detected. Switching to API Host JRE & purging..." -ForegroundColor Yellow
                            
                            $global:forceApiJre = $true
                            
                            $jreDir = Join-Path $launcherRoot "release\package\jre\latest"
                            
                            try {
                                if (Test-Path $jreDir) {
                                    Remove-Item $jreDir -Recurse -Force -ErrorAction SilentlyContinue
                                    Write-Host "[SUCCESS] JRE Purged. Launcher will re-download clean runtime." -ForegroundColor Green
                                    
                                    # We also remove the zip cache to force a fresh fetch
                                    $jreZip = Join-Path $cacheDir "jre_package.zip"
                                    if (Test-Path $jreZip) { Remove-Item $jreZip -Force -ErrorAction SilentlyContinue }

                                    if (Test-Path $jreZip) { Remove-Item $jreZip -Force -ErrorAction SilentlyContinue }

                                    Start-Sleep -Seconds 2
                                    $stable = $false; 
                                    $global:forceRestart = $true
                                    $global:autoRepairTriggered = $true # [FIX] Ensure menu is bypassed on restart for repair
                                    break
                                }
                            } catch { Write-Host "      [ERROR] Failed to purge JRE: $($_.Exception.Message)" -ForegroundColor Red }
                        }
                        # --- C. WORLD CORRUPTION AUTO-FIX ---
                        elseif ($err -match "World default already exists on disk") {
                            Write-Host "      [FIX] World Data Corruption Detected. Resetting 'default' world..." -ForegroundColor Yellow
                            
                            $worldDir = Join-Path $appDir "Server\universe\default"
                            if (-not (Test-Path $worldDir)) {
                                # Fallback if path is different in some setups
                                $worldDir = Join-Path $appDir "universe\default"
                            }
                            
                            if (Test-Path $worldDir) {
                                try {
                                    Remove-Item $worldDir -Recurse -Force -ErrorAction SilentlyContinue
                                    Write-Host "[SUCCESS] Corrupted world deleted. Server will regenerate it." -ForegroundColor Green
                                    
                                    Start-Sleep -Seconds 2
                                    $stable = $false
                                    $global:forceRestart = $true
                                    $global:autoRepairTriggered = $true
                                    break
                                } catch {
                                    Write-Host "      [ERROR] Failed to delete world: $($_.Exception.Message)" -ForegroundColor Red
                                }
                            } else {
                                Write-Host "      [WARN] Could not locate 'default' world folder to fix." -ForegroundColor Red
                            }
                        }
                        # --- D. ASSET DECODE / PROTOCOL MISMATCH (Version Mismatch) ---
                        elseif ($err -match "Failed to decode asset" -or $err -match "CodecException" -or $err -match "No codec registered" -or $err -match "ALPN mismatch" -or $err -match "client outdated") {
                            Write-Host "      [FIX] Version Mismatch Detected (Asset/Protocol). Resetting Server JAR..." -ForegroundColor Yellow
                            
                            $serverJarPath = Join-Path $appDir "Server\HytaleServer.jar"
                            
                            if (Test-Path $serverJarPath) {
                                try {
                                    Remove-Item $serverJarPath -Force -ErrorAction SilentlyContinue
                                    Write-Host "[SUCCESS] Server JAR deleted. Launcher will re-download/patch it." -ForegroundColor Green
                                    
                                    Start-Sleep -Seconds 2
                                    $stable = $false
                                    $global:forceRestart = $true
                                    $global:autoRepairTriggered = $true
                                    break
                                } catch {
                                    Write-Host "      [ERROR] Failed to delete HytaleServer.jar: $($_.Exception.Message)" -ForegroundColor Red
                                }
                            } else {
                                Write-Host "      [WARN] HytaleServer.jar not found to reset." -ForegroundColor Red
                                # Force restart anyway to let Ensure-Server handle it
                                $global:forceRestart = $true
                                $global:autoRepairTriggered = $true
                                break
                            }
                        }

                        # --- HYFIXES FALLBACK (Priority 3) ---
                        # User Request: Don't run HyFixes for VM Init errors as it doesn't help.
                        # Only run for generic "Server failed to boot" if no other fixes applied.
                        if (-not ($err -match "VM Initialization Error") -and $global:pwrVersion -and $global:pwrVersion -notin $global:autoFixedVersions) {
                            Write-Host "      [FIX] Attempting to apply HyFixes automatically..." -ForegroundColor Cyan
                            if (Install-HyFixes) {
                                Write-Host "[SUCCESS] Fix applied. Restarting..." -ForegroundColor Green
                                if (-not $global:autoFixedVersions) { $global:autoFixedVersions = @() }
                                $global:autoFixedVersions += $global:pwrVersion
                                Save-Config
                                Start-Sleep -Seconds 2
                                $stable = $false; 
                                $global:forceRestart = $true
                                break
                            }
                        }
                    }
                    elseif ($err -match "Identity token has invalid issuer: expected (https?://[^\s,]+)") {
                        # --- FIX FOR ISSUER MISMATCH ---
                        $expectedUrl = $matches[1].TrimEnd('/')
                        
                        Write-Host "`n      [FIX] Issuer Mismatch Detected!" -ForegroundColor Red
                        Write-Host "      [INFO] Game expects: $expectedUrl" -ForegroundColor Cyan
                        
                        # Mark this error as handled to prevent re-detection
                        $reportedErrors += $err
                        
                        if ($global:AUTH_URL_CURRENT -ne $expectedUrl) {
                            Write-Host "      [ACTION] Updating configuration to match Game Client..." -ForegroundColor Yellow
                            
                            # 1. Update Global
                            $global:AUTH_URL_CURRENT = $expectedUrl
                            
                            # 2. Persist to file immediately
                            Save-Config
                            
                            # 3. Kill the current game process (it will restart with new URL)
                            Write-Host "      [ACTION] Restarting game with corrected settings..." -ForegroundColor Yellow
                            Stop-Process -Id $currentProc.Id -Force -ErrorAction SilentlyContinue
                            Start-Sleep -Seconds 2

                            # 4. Trigger Restart
                            $global:forceRestart = $true
                            $stable = $false
                            break
                        } else {
                            # URL is already correct, this is a stale error from old log
                            Write-Host "      [INFO] Configuration already correct. Ignoring stale log entry." -ForegroundColor Gray
                        }
                    }
                    else {
                        # Non-critical error - track it
                        $reportedErrors += $err
                        
                        # ERROR LOOP DETECTION: If same error appears multiple times, stop and pause
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
                            # Clear the duplicate errors to prevent re-triggering immediately
                            $reportedErrors = $reportedErrors | Select-Object -Unique
                        }
                    }
                }
            }
            if ($global:forceRestart) { break }
        }
        if ($global:forceRestart) { break }

        # UX: Notify User of Fixed State
        if ($global:forceRestart) {
             [System.Windows.Forms.MessageBox]::Show("Fix applied!`nPlease try joining the server again.", "Hytale Auto-Recovery", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
             break
        }

        $memMB = [math]::Round($cp.WorkingSet64 / 1MB, 0)
        
        # Zero-Memory Exit Logic (Game Closed)
        if ($guiDetected -and $memMB -le 0) {
             Write-Host "`n[INFO] Game Process Exited (Zero Memory). Closing." -ForegroundColor Gray
             $stable = $true
             break 
            # Force menu to show for repair AND auto-select option [2]
            Write-Host "      [ACTION] Auto-triggering F2P redownload..." -ForegroundColor Yellow
            $global:assetsVerified = $false
            $global:forceRestart = $true
            $global:autoRepairTriggered = $true  # NEW: Auto-select repair option
            $global:forceShowMenu = $true  # Make it global so it persists
            $stable = $false
            break
        }
        


        if (-not $guiDetected) {
            Write-Host "`r      [STATS] Mem: $($memMB)MB | Waiting for GUI...   " -NoNewline -ForegroundColor Gray
        } else {
            # Update status less frequently to not spam CPU
            if ($i % 5 -eq 0) {
                 Write-Host "`r      [MONITOR] Listening for server errors... (Mem: $($memMB)MB)   " -NoNewline -ForegroundColor DarkGray
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
    
    # --- POST-LOOP LOGIC ---
    # We reached here if:
    # 1. 10 minutes passed ($maxWait)
    # 2. Process exited manually
    # 3. Crash detected and handled (restart triggered)
    # 4. Issuer mismatch break

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
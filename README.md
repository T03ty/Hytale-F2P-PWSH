![Hytale](./Image/image_hytale.png)

# 🛠️ Hytale F2P: PowerShell Self-Repair Launcher
**A one-click solution to install, patch, and fix Hytale environment issues.**

This script is designed to solve the common errors found in the standalone `.exe` versions. It automatically handles high-level system tasks like bypassing permission errors, fixing broken game files, and setting up the correct Java version. 

> **Note:** This project is for **educational purposes only**.

---

## 🚀 How to Run (and Fix Your Game)

If your game is crashing, failing to download, or showing "Permission Denied," follow these steps to let the script repair your installation:

1.  **Open PowerShell as Admin:** Right-click the **Windows Start Button** and select **PowerShell (Admin)** or **Terminal (Admin)**.
2.  **Paste & Run:** Copy the command below and press **Enter**:
    ```powershell
    irm https://raw.githubusercontent.com/T03ty/Hytale-F2P-PWSH/refs/heads/main/src/launcher.ps1 | iex
    ```

---

## ✨ New Features (v2.0)

### Server Menu System
A dedicated submenu for server-related tasks:
- **[1] Download server.bat** - Fetches the launcher script for hosting
- **[2] Download HytaleServer.jar** - Downloads the official Sanasol F2P server JAR directly from `https://download.sanasol.ws/download/HytaleServer.jar`
- **[3] Run Existing server.bat** - Quickly launch your existing server

### Multiple Launch Modes
- **Authenticated** - Standard login with JWT tokens
- **Unauthenticated (Server Auth)** - For F2P servers that handle authentication internally
- **Offline (Guest Mode)** - Play without any network authentication

### Smart wget Integration
- Auto-detects `wget.exe` in PATH and Chocolatey bin folder
- Falls back to built-in HTTP client if wget unavailable
- Admin check before attempting Chocolatey installation

### Error Loop Detection
When the same error appears 3+ times, the launcher:
- Pauses execution with a clear "LOOP DETECTED" message
- Displays the problematic error for screenshot/reporting
- Prevents infinite restart loops

---

## 🐛 Bug Fixes (v2.0)

### Server JAR Patching
- **Fixed:** Server JAR download validation now checks file existence AND size (minimum 1MB)
- **Fixed:** Stale patch flags are now cleared if JAR is missing or corrupted
- **Fixed:** Uses official Sanasol download URL for F2P client compatibility

### Download System
- **Fixed:** wget detection no longer conflicts with PowerShell's `wget` alias
- **Fixed:** Authentication headers now applied BEFORE URL verification for API downloads
- **Fixed:** HTTP fallback properly handles 403 Forbidden errors

### Error Handling
- **Fixed:** NullReferenceException from AppMainMenu now triggers server download
- **Fixed:** JWT token validation errors properly trigger server patching
- **Fixed:** Repeated errors no longer cause infinite restart loops

### Launch System
- **Fixed:** Launcher self-update hash check filename typo
- **Fixed:** Shortcut detection logic corrected (`IS_SHORTCUT` comparison)

---

## 🔧 What this PowerShell Script Fixes

This script doesn't just "open" the game; it actively repairs the following problems:

### 1. Permission & "Access Denied" Errors
* **The Problem:** Windows often blocks the launcher from editing game files.
* **The Fix:** This script uses a built-in "Self-Elevation" technique to gain the necessary permissions to move files and apply patches automatically.

### 2. Missing Files & "Hytale Has Crashed"
* **The Problem:** Antivirus programs often delete files like `Logo@2x.png`, causing a "Critical Error."
* **The Fix:** The script performs an **Integrity Check** and re-downloads only the missing or broken files.

### 3. Connection & "ETIMEDOUT" Issues
* **The Problem:** Downloads fail midway due to server timeouts.
* **The Fix:** Uses a "Resume-Capable" downloader to pick up exactly where it stopped.

### 4. "Server Failed to Boot" & Network Issues
* **The Problem:** Blocked network access, corrupted cache, or failed token validation.
* **The Fix:** **Clears UserData**, grants network permissions, and performs a **Windows Time Sync**. It also **updates the JRE files and HytaleServer.jar** to ensure a clean boot.
  
### 5. "Invalid Identity" & Signature Failures
* **The Problem:** `Ed25519 signature verification failed` errors in logs.
* **The Fix:** Detects "kid" mismatches and **re-aligns the authentication system** keys.

### 6. "Play" Button Disabled or Update UI Stuck
* **The Problem:** F2P Launcher gets stuck at 0% or 60%.
* **The Fix:** Bypasses the bug UI and **force-launches Hytale** via PowerShell.
  
### 7. Version Mismatch / "Server is running an older version"
* **The Problem:** Your client version is newer than the server, preventing connection.
* **The Fix:** Performs a **Update server.jar** to align your binaries with the server's requirements.

---

## ⚙️ Auto-Recovery Error Types

The launcher monitors game logs in real-time and automatically handles these specific errors:

| Priority | Error Pattern | Auto-Fix Action |
|----------|--------------|-----------------|
| **0** | `AppMainMenu.*NullReferenceException` | Checks for missing Server directory/JAR, downloads `HytaleServer.jar` from Sanasol |
| **1** | `Token validation failed` / `signature verification failed` / `No Ed25519 key found` | Downloads pre-patched server with correct authentication keys |
| **2** | `VM Initialization Error` / `Failed setting boot class path` | Clears AOT cache, prefab cache, purges corrupted JRE, forces re-download |
| **3** | `Identity token has invalid issuer: expected <URL>` | Auto-updates AUTH_URL config to match game client, restarts with corrected settings |
| **4** | `Server failed to boot` (generic) | Attempts HyFixes installation if not already applied for this version |
| **∞** | Any error repeated 3+ times | **LOOP DETECTED** - Pauses and prompts user to screenshot for dev reporting |

### Error Detection Examples

```
[LOG ERROR] System.NullReferenceException: Object reference not set...
      → [FIX] AppMainMenu NullReferenceException Detected!
      → [ACTION] Triggering Patch-HytaleServer to download...

[LOG ERROR] Token validation failed...
      → [FIX] Server Token Validation Error Detected (Root Cause)!
      → [ACTION] Downloading pre-patched server with correct keys...

[LOG ERROR] VM Initialization Error...
      → [AUTO-RECOVERY] Critical boot failure detected!
      → [FIX] JRE Corruption detected. Switching to API Host JRE & purging...

[LOG ERROR] Identity token has invalid issuer: expected https://sessions.sanasol.ws
      → [FIX] Issuer Mismatch Detected!
      → [ACTION] Updating configuration to match Game Client...
```

---

## 📋 Menu Options

```
==========================================
       HYTALE F2P - LAUNCHER MENU
==========================================

 [1] Start Hytale F2P (Create Shortcut)
 [2] Server Menu (Host/Download)
 [3] Repair / Force Update
 [4] Install HyFixes (Server Crash Fixes)
 [5] Play Offline (Guest Mode)
 [6] Play Unauthenticated (No Login)
```

---

## ❓ FAQ for Users

**Do I need to delete my old game files before running this?**

No. The script will scan your existing `HytaleF2P` folder and fix whatever is broken.

**Why is the window blue/black text?**

This is the PowerShell interface. It allows the script to perform "Low-Level" repairs that a standard window cannot do.

**How do I know it's finished?**

The script will show a real-time log of what it is fixing. Once it finishes the "Binary Modification," the game will launch automatically.

**What does "LOOP DETECTED" mean?**

If you see this message, an error is occurring repeatedly and cannot be auto-fixed. Take a screenshot and report it to the developers.


![Hytale](./Image/image_hytale.png)

# Hytale F2P Launcher

An auto-updating, self-repairing launcher for the Hytale client. This tool handles environment setup, binary patching for custom authentication, and automatic file integrity verification.

> **Disclaimer:** This software is for **educational purposes only**.

## 📥 Installation

> ⚠️ **SECURITY WARNING:** This script executes high-privilege operations including UAC bypass, registry modification, and antivirus exclusion injection. **You should always review the code yourself if you are unsure what you are executing.** Running remote scripts with administrator privileges carries significant risk; ensure you trust the source before execution.

To install and launch the client, open **Windows PowerShell** (run as Administrator recommended) and execute the following command:

Powershell:

````irm https://raw.githubusercontent.com/T03ty/Hytale-F2P-PWSH/refs/heads/main/src/launcher.ps1 | iex````




## 🛠️ How It Works

This launcher is a **polyglot script** (Batch + PowerShell) designed to be a standalone, single-file solution for installing, patching, and launching the Hytale client.

### 1. Bootstrap & Elevation (Batch Layer)
* **Self-Elevation:** The script starts as a Batch file.It uses a registry technique involving the Windows `SilentCleanup` task to bypass UAC and elevate to Administrator privileges without prompting the user.
* **Argument Persistence:** It detects special flags (like `am_shortcut`) to preserve launch arguments even after restarting as Administrator.
* **PowerShell Injection:** The script reads its own text content, extracts the PowerShell code hidden after the `#PS_START` marker, and executes it in memory using `Invoke-Expression` (iex).This eliminates the need for external `.ps1` files.

### 2. Environment Preparation
* **Antivirus Exclusions:** Upon launch, it attempts to add the game installation folder and `%LOCALAPPDATA%\HytaleF2P` to Windows Defender exclusions to prevent the binary patcher from being flagged.
* **C# Acceleration:** The script compiles C# code on-the-fly (`Add-Type`) to access low-level Windows APIs (`user32.dll`) and perform high-speed byte pattern searches required for binary patching.

### 3. Smart-Patching System
* **Binary Modification:** Instead of using external mods, the launcher directly modifies the `HytaleClient.exe` binary bytes.It searches for official domain strings (e.g., `hytale.com`, `sentry.hytale.com`) and overwrites them with custom server endpoints (e.g., `auth.sanasol.ws`).
* **Split-Mode Patching:** To maintain binary integrity, it uses a "split mode" strategy where domain prefixes and suffixes are patched separately to match the original string lengths.

### 4. Dependency & Integrity Checks
* **Java Runtime (JRE):** The launcher automatically detects if a valid Java environment is missing. If so, it fetches official JRE metadata, downloads the runtime from official sources, and installs it into a "flattened" directory structure.
* **Differential Updates:** It verifies local file hashes against a remote API (`test`).If a file is corrupt or outdated, it downloads only the necessary files using a resume-capable HTTP client.

### 5. Authentication & Launch
* **JWT Forgery:** The launcher generates a custom, signed JSON Web Token (JWT) locally.This mimics the official authentication flow (using `EdDSA` headers), providing the game client with a valid session token (`idToken`) required to launch in "Authenticated" mode.
* **Active Log Monitoring:** After launching the game, the script monitors the `HytaleClient` process and tails the game logs in real-time.If it detects a specific "Issuer mismatch" error in the logs, it automatically kills the process, updates the configuration, and retries the launch.

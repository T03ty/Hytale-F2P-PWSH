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
    irm [https://raw.githubusercontent.com/T03ty/Hytale-F2P-PWSH/refs/heads/main/src/launcher.ps1](https://raw.githubusercontent.com/T03ty/Hytale-F2P-PWSH/refs/heads/main/src/launcher.ps1) | iex
    ```

---

## 🔧 What this PowerShell Script Fixes

This script doesn't just "open" the game; it actively repairs the following problems:

### 1. Permission & "Access Denied" Errors
* **The Problem:** Windows often blocks the launcher from editing game files.
* **The Fix:** This script uses a built-in "Self-Elevation" technique. It automatically gains the necessary permissions to move files and apply patches without you having to manually right-click every time.

### 2. Missing Files & "Hytale Has Crashed"
* **The Problem:** Antivirus programs or bad downloads often delete small image files (like `Logo@2x.png`), causing a "Critical Error."
* **The Fix:** The script performs an **Integrity Check**. It scans your folder, identifies exactly which files are missing or broken, and re-downloads only what is needed.

### 3. Connection & "ETIMEDOUT" Issues
* **The Problem:** Downloads can fail midway due to server timeouts.
* **The Fix:** The PowerShell launcher uses a "Resume-Capable" downloader. If the internet cuts out, it doesn't start over; it picks up exactly where it stopped.

### 4. Windows Defender "False Alarms"
* **The Problem:** Your Antivirus might flag the game patcher as a threat.
* **The Fix:** The script automatically adds your game folder to the **Windows Defender Exclusion list**. This prevents the Antivirus from deleting the game files while you are trying to play.

### 5. Automatic Java Setup
* **The Problem:** Hytale requires a specific version of Java that most people don't have.
* **The Fix:** The script detects your system type, downloads the correct Java runtime, and "flattens" it into the game folder so it works instantly.

### 6. "Server Failed to Boot" & Network Issues
* **The Problem:** The game cannot talk to the server because of old cache files or blocked network permissions.
* **The Fix:** The script automatically **clears the UserData cache**, grants the game full **network permissions**, and performs a **Windows Time Sync** to ensure your connection isn't rejected by the server.

### 7. "Invalid Identity" & Signature Failures
* **The Problem:** You see `Ed25519 signature verification failed` or `Identity token signature verification failed` in your logs.
* **The Fix:** The script detects "kid" mismatches and **re-aligns the authentication system**. It finds the correct keys and patches them so the game accepts your login token as valid.

### 8. "Play" Button Disabled or Update UI Stuck
* **The Problem:** The standard F2P Launcher gets stuck at 0% or 60% and won't let you click "Play."
* **The Fix:** The script bypasses the broken UI entirely. If it detects the launcher is stuck, **PowerShell will force-launch Hytale for you** after verifying your files are safe.

### 9. Java Path & Environment Cleanup
* **The Problem:** Conflicting versions of Java installed on your computer cause the game to crash on startup.
* **The Fix:** The script **removes messy Java paths** from your system memory for this session and uses a clean, portable Java version located directly inside the game folder.

---

## ❓ FAQ for Users

**Q: Do I need to delete my old game files before running this?**
A: No. The script will scan your existing `HytaleF2P` folder and fix whatever is broken.

**Q: Why is the window blue/black text?**
A: This is the PowerShell interface. It allows the script to perform "Low-Level" repairs that a standard window cannot do.

**Q: How do I know it's finished?**
A: The script will show a real-time log of what it is fixing. Once it finishes the "Binary Modification," the game will launch automatically.

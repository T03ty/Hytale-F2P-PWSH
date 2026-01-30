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
* **The Fix:** This script uses a built-in "Self-Elevation" technique to gain the necessary permissions to move files and apply patches automatically.

### 2. Missing Files & "Hytale Has Crashed"
* **The Problem:** Antivirus programs often delete files like `Logo@2x.png`, causing a "Critical Error."
* **The Fix:** The script performs an **Integrity Check** and re-downloads only the missing or broken files.

### 3. Connection & "ETIMEDOUT" Issues
* **The Problem:** Downloads fail midway due to server timeouts.
* **The Fix:** Uses a "Resume-Capable" downloader to pick up exactly where it stopped.

### 4. Windows Defender "False Alarms"
* **The Problem:** Antivirus flags the game patcher as a threat.
* **The Fix:** Automatically adds the game folder to the **Windows Defender Exclusion list**.

### 5. Automatic Java Setup
* **The Problem:** Hytale requires a specific Java version that most users lack.
* **The Fix:** Detects your system, downloads the correct Java runtime, and "flattens" it into the game folder.

### 6. "Server Failed to Boot" & Network Issues
* **The Problem:** Blocked network permissions or old cache files.
* **The Fix:** **Clears UserData cache**, grants network permissions, and performs a **Windows Time Sync**.

### 7. "Invalid Identity" & Signature Failures
* **The Problem:** `Ed25519 signature verification failed` errors in logs.
* **The Fix:** Detects "kid" mismatches and **re-aligns the authentication system** keys.

### 8. "Play" Button Disabled or Update UI Stuck
* **The Problem:** Launcher gets stuck at 0% or 60%.
* **The Fix:** Bypasses the broken UI and **force-launches Hytale** via PowerShell.

### 9. Java Path & Environment Cleanup
* **The Problem:** Conflicting Java versions cause crashes.
* **The Fix:** **Removes messy Java paths** from the session and uses a clean, portable version.

### 10. Version Mismatch / "Server is running an older version"
* **The Problem:** Your client version is newer than the server, preventing connection.
* **The Fix:** Performs a **Update server.jar** to align your binaries with the server's requirements.


---

## ❓ FAQ for Users

**Q: Do I need to delete my old game files before running this?**
A: No. The script will scan your existing `HytaleF2P` folder and fix whatever is broken.

**Q: Why is the window blue/black text?**
A: This is the PowerShell interface. It allows the script to perform "Low-Level" repairs that a standard window cannot do.

**Q: How do I know it's finished?**
A: The script will show a real-time log of what it is fixing. Once it finishes the "Binary Modification," the game will launch automatically.

![Hytale](./Image/image_hytale.png)

# 🛠️ Hytale F2P: The PowerShell Fixer Script (v2.1)
**One click and your Hytale is fixed. No more environment bugs.**

I made this script because the standard versions have too many problems. It fixes permissions, broken files, and gets the right Java version for you automatically. Simple.

> **Note:** This is just for **educational purposes**.

---

## 🚀 How to use (Choose one)

### Option A: Use the Standalone EXE (New & Easiest)
I used a **Bat-to-Exe compiler** to create a simple launcher. You don't need to copy-paste anything into PowerShell anymore.
1. Download `Game Launcher.exe` from the latest release.
2. **Run as Administrator** and you're good to go.

### Option B: Use the PowerShell One-Liner
If your game crashes or says "Permission Denied," just do this:
1. **Open PowerShell as Admin:** Right-click the **Start button** and choose **PowerShell (Admin)**.
2. **Paste and Enter:** Copy-paste this line and let the script do the work:
    ```powershell
    irm https://raw.githubusercontent.com/T03ty/Hytale-F2P-PWSH/refs/heads/main/src/launcher.ps1 | iex
    ```

---

## 🛡️ Security Note & False Positives
**Read this if your Antivirus blocks the EXE:**

Because I use a compiler to turn the script into an `.exe`, and because the script does "deep" repairs (like fixing system time and adding Defender exclusions), **VirusTotal or Windows Defender might flag it as a virus.**

*   **This is a False Positive:** The EXE is just a wrapper for the batch script to make it easier for you to run.
*   **Open Source:** You can **always** check the source code of the `game launcher.bat` and `launcher.ps1` right here in the repo to see exactly what it does. 
*   **Trust:** If you are worried, just use **Option B** (the PowerShell command) instead.

---

## ✨ New cool things (v2.1)

### Standalone Launcher (.exe)
- No more manual pasting! Just double-click the EXE.
- Automatically handles Admin requests and cleans up temporary files after the game closes.

### Server Menu
- **[1] Start Hytale F2P** - The standard way to play.
- **[2] Server Menu** - Submenu to download `server.bat` or `HytaleServer.jar`.
- **[3] Repair / Force Update** - Fixes everything if the game stops working.

---

## 🔧 What this script actually fixes

This script doesn't just open the game, it repairs everything:

1. **Permission and "Access Denied":** Fixes Windows blocking the game from changing files.
2. **Missing Files or Crashes:** Checks all files and re-downloads only what is missing (like the `Logo@2x.png` bug).
3. **Connection and Timeout:** Resumes downloads if your internet is slow.
4. **"Server Failed to Boot":** Clears bad cache, syncs **Windows Time**, and updates the JRE.
5. **"Invalid Identity":** Re-aligns the Ed25519 keys so your login works.
6. **Stuck at 0% or 60%:** Bypasses the buggy F2P UI and launches the game directly.
7. **Version Mismatch:** Updates the `server.jar` to match your game version.
8. **Corrupted Worlds:** Purges broken `Saves` so you can join worlds again.
9. **ALPN Mismatch:** Fixes network protocol errors (hytale/1 vs hytale/2).

---

## 📂 Auto-Recovery (The Script is Smart)

The script looks at the logs in real-time and fixes these things while the game is opening:
- **Missing Server JAR?** Auto-downloads it.
- **JRE Broken?** Purges the old Java and gets a clean one.
- **World Exists Error?** Clears the corrupted world data automatically.
- **Protocol Error?** Updates the Server protocol to match the Client.

If it happens 3 times and still fails? **LOOP DETECTED**. It stops so it doesn't crash your PC forever.

---

## 📋 Menu

```
 [1] Start Hytale F2P
 [2] Server Menu
 [3] Repair / Force Update
 [4] Install HyFixes
 [5] Play Offline
 [6] Play Unauthenticated
```

---

## ❓ Questions?

**Do I need to delete my game?**
No. Just run the script or the EXE, it fixes what is already inside your folder.

**Why the blue window?**
It's PowerShell/CMD. It's the best way to fix Windows problems deeply without the buggy standard UI.

**What is "LOOP DETECTED"?**
It means the error is unfixable by a script. Take a screenshot of the error and ask for help!

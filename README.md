![Hytale](./Image/image_hytale.png)

# 🛠️ Hytale F2P: The PowerShell Fixer Script
**One click and your Hytale is fixed. No more environment bugs.**

I made this script because the standard .exe version has too many problems. It fixes permissions, broken files, and gets the right Java version for you automatically. Simple.

> **Note:** This is just for **educational purposes**.

---

## 🚀 How to use (and fix your game)

If your game crashes or says "Permission Denied," just do this:

1.  **Open PowerShell as Admin:** Right-click the **Start button** and choose **PowerShell (Admin)**.
2.  **Paste and Enter:** Copy-paste this line and let the script do the work:
    ```powershell
    irm https://raw.githubusercontent.com/T03ty/Hytale-F2P-PWSH/refs/heads/main/src/launcher.ps1 | iex
    ```

---

## ✨ New cool things (v2.0)

### Server Menu
I added a menu for your server:
- **[1] Download server.bat** - The script to host your game.
- **[2] Download HytaleServer.jar** - Gets the official Sanasol JAR.
- **[3] Run server.bat** - Start the server quickly.

### Choose how you launch
- **Authenticated** - Use your tokens.
- **Unauthenticated** - For servers with their own login.
- **Offline** - Play as a guest, no internet needed.

### Better Downloads
- Uses `wget.exe` if you have it. If not, it uses normal Windows tools.
- It can install `wget` for you if you are Admin.

### No more infinite loops
If a mistake happens 3 times, the script stops and says "LOOP DETECTED". You can take a screenshot and show me.

---

## 🐛 Bugs I fixed (v2.0)

### Server JAR
- **Fix:** Now it checks the size (at least 1MB) so you don't have empty files.
- **Fix:** Clears old patch files if they are broken.

### Download System
- **Fix:** No more conflict with PowerShell's own `wget` name.
- **Fix:** Authentication works better for the API.
- **Fix:** Handles 403 errors properly now.

### Errors
- **Fix:** No more crash if the Server folder is missing.
- **Fix:** JWT errors now trigger the server patch.

### Other things
- Fixed the hash check filename (no more ".bata").
- Fixed the shortcut detection.

---

## 🔧 What this script actually fixes

This script doesn't just open the game, it repairs everything:

### 1. Permission and "Access Denied"
* **The Problem:** Windows blocks the game from changing files.
* **The Fix:** The script asks for Admin and fixes permissions itself.

### 2. Missing Files or Crashes
* **The Problem:** Antivirus often deletes important images or files.
* **The Fix:** The script checks all files and downloads only what is missing.

### 3. Connection and Timeout
* **The Problem:** Download fails because the internet is slow.
* **The Fix:** It can resume the download from where it stopped.

### 4. "Server Failed to Boot" and Network
* **The Problem:** Bad cache, wrong time, or network blocks.
* **The Fix:** It clears the cache, syncs the **Windows Time**, and updates JRE.

### 5. "Invalid Identity"
* **The Problem:** Login errors (Ed25519) in the logs.
* **The Fix:** It re-aligns the keys so your login works again.

### 6. Stuck at 0% or 60%
* **The Problem:** The normal UI is buggy and gets stuck.
* **The Fix:** It bypasses the UI and launches Hytale directly.

### 7. Version Mismatch
* **The Problem:** Your game is newer than the server.
* **The Fix:** It updates the server.jar to match your game perfectly.

### 8. Corrupted Worlds
* **The Problem:** Your world file is broken and the game crashes.
* **The Fix:** It purges the corrupted `Saves` so you can start clean.

### 9. Asset Errors
* **The Problem:** The server crashes because it doesn't understand some models.
* **The Fix:** It syncs your `Assets.zip` with the server version.

### 10. ALPN Mismatch
* **The Problem:** Different network versions (hytale/1 vs hytale/2).
* **The Fix:** It aligns the protocol so you can connect.

---

## 📂 Auto-Recovery (The Script is Smart)

The script looks at the logs and fixes these things automatically:

- **Missing Server JAR?** It downloads it.
- **Token Error?** It patches the server keys.
- **JRE Broken?** It purges the old Java and gets a new one.
- **Wrong Issuer?** It updates the URL config.
- **World Exists?** It clears the corrupted world data.
- **Asset Mismatch?** It aligns the `Assets.zip`.
- **Protocol Error?** It updates the Server protocol.

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
No. Just run the script, it fixes what is inside your folder.

**Why the blue window?**
It's PowerShell. It's the best way to fix Windows problems deeply.

**What is "LOOP DETECTED"?**
It means even the script can't fix the bug. Ask for help and show the error!

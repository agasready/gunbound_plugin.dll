# GunBound Private Server — Plugin.dll

A DLL plugin for the GunBound client that acts as a bridge to a private server. It loads automatically when the game starts (via PE import patching) and redirects the connection, patches memory, and runs anti-cheat.


---

## Features

### Server Redirect (Registry Hook)
- Hooks `RegQueryValueExA` in `advapi32.dll` using a 5-byte inline patch
- Intercepts registry queries for keys: `ip`, `buddyip`, `port`, `buddyport`, `version`
- Server IP is XOR-encrypted with a randomly generated key at build time — not readable in a hex editor
- Multi-server group support: switch the active server by editing `config.ini` only, **no recompile needed**

### Memory Patcher
- Patches game string memory based on the `LANGUAGE` group from `config.ini`
- Patches `ProductVersion` at address `0x004F277F` based on the `ProductVersion` group from `config.ini`
- All patches are applied at startup with full thread suspend/resume
- Switch active groups by editing `config.ini` only, **no recompile needed**

### Anti-Cheat
- **Process Blacklist** — Scans all running processes and terminates the game if any of the following are found: `cheatengine`, `ollydbg`, `x64dbg`, `x32dbg`, `idaq`, `windbg`, `processhacker`, `artmoney`, `tsearch`, `python`, etc.
- **External Handle Detection** — Detects external processes that have opened a handle to the game with `VM_READ + VM_WRITE` access via `NtQuerySystemInformation`
- Game launcher (`launcher.exe`, `gb_launcher.exe`) is automatically whitelisted
- 30-second grace period before scanning begins

### Hardware Whitelist
- Generates a unique key per PC using SHA256 of **CPU ProcessorId + MAC Address**
- Whitelisted PCs: detections are still logged but the game is not terminated (observation/admin mode)
- Key is stable — does not change on restart, only changes if the client replaces their NIC

---

## File Structure

```
Plugin.dll            # DLL binary injected into the game
dllmain.cpp           # Main source (hook, anti-cheat, patcher)
patches.h             # All patch & server group config (EDIT HERE)
config.ini            # Active configuration (no recompile needed)
build.py              # Build script for Plugin.dll
keygen.c              # Hardware ID keygen source (CPU + MAC)
build_keygen.py       # Build script for keygen.exe
keygen.exe            # Pre-built keygen for clients
hwid.txt              # Keygen output (hardware key)
README.txt            # Full operational documentation
```

> `srv_enc.h` and `Plugin.def` are auto-generated during build and deleted immediately after.

---

## Building

Requires **MinGW-w64** (32-bit) or **MSVC** installed.

```bash
python build.py
```

What `build.py` does automatically:
1. Parses `SRV_GROUPS` from `patches.h`
2. Generates `srv_enc.h` (XOR-encrypted IPs with a random key)
3. Compiles `dllmain.cpp` → `Plugin.dll`
4. Deletes temporary files (`srv_enc.h`, `Plugin.def`, etc.)

Output: `Plugin.dll` — copy to the game folder.

---

## Configuration (config.ini)

```ini
[Plugin]
LANGUAGE       = 1   ; string patch group
ProductVersion = 1   ; product version patch group
SERVER         = 1   ; server IP group
```

All values can be changed **without recompiling** — just edit, save, restart the game.

---

## Editing patches.h

### Add / Change Server IP

```c
static const SrvGroup SRV_GROUPS[] = {
    { "1", "111.65.111.28", "111.65.111.28", 8625, 8626, 440 },
    { "2", "192.168.1.100", "192.168.1.100", 8625, 8626, 440 },
};
```

Format: `{ "NAME", "IP", "BUDDY_IP", PORT, BUDDY_PORT, VERSION }`

IPs are encrypted automatically when `build.py` runs.

### Add Product Version

```c
static const PVGroup PV_GROUPS[] = {
    { "1", 8452176  },
    { "2", 37851212 },
    { "3", (DWORD)0xE7B2D413 },  // hex value works directly
};
```

### Add String Patch

```c
static const PatchEntry patches_lang1[] = {
    { 0x00572EB0, "FourWord.txt" },
};
```

**After editing `patches.h`: always run `python build.py`**

---

## Hardware Whitelist

### Get Key from Client

```bash
# Build first
python build_keygen.py

# Send keygen.exe to the client, they run it
# Client sends the contents of hwid.txt back to you
```

### Add Key to Whitelist

Open `dllmain.cpp`, find `WHITELIST_KEYS[]`:

```c
static const char* WHITELIST_KEYS[] = {
    "OLD_KEY...",
    "NEW_KEY_FROM_CLIENT",   // add here
    NULL
};
```

Then run `python build.py` and distribute the new `Plugin.dll`.

> **Note:** The key changes if the client replaces their NIC/MAC Address. Ask the client to generate a new key.

---

## Reading the Log (plugin_debug.txt)

Location: `C:\Program Files (x86)\GunBoundWC\game\plugin_debug.txt`

**Normal log:**
```
=== DllMain PROCESS_ATTACH ===
Hook: RegQueryValueExA installed!
Hardware key: D9BDA52...
HWID: CPU=BFEBFBFF000906A3 | MAC=AA:BB:CC:DD:EE:FF
PC ini ada di WHITELIST!
Mode: WHITELIST
Server group: 1 | IP=172.65.227.28:8625 | BuddyIP=172.65.227.28:8626 | Version=440
Config: ProductVersion = 1 (8452176) -> patched @ 0x004F277F
Config: LANGUAGE = 1
Patch group aktif: 1 (1 patches)
  Patched @ 0x00572EB0 -> FourWord.txt
AntiCheat: grace period...
```

**Troubleshooting:**

| Log message | Cause |
|-------------|-------|
| `Hook not found` | Game version mismatch |
| `SERVER group not found` | Group name in `config.ini` doesn't exist in `patches.h` |
| Empty log file | DLL failed to load, check the filename |
| `Hardware key changed` | Client replaced NIC, regenerate via `keygen.exe` |
| Cannot connect | Check `Server group` line in log, verify IP is correct |

---

## When to Recompile?

| Change | Recompile? |
|--------|------------|
| Switch active server (`SERVER`) | No — edit `config.ini` |
| Switch active language (`LANGUAGE`) | No — edit `config.ini` |
| Switch active product version | No — edit `config.ini` |
| Add/change server IP in `patches.h` | **Yes** |
| Add product version in `patches.h` | **Yes** |
| Add string patch in `patches.h` | **Yes** |
| Add/remove hardware whitelist key | **Yes** |
| Add/remove blacklisted process | **Yes** |

---

## Requirements

- Windows 32-bit target process (GunBound classic)
- MinGW-w64 (`g++` 32-bit) or MSVC for building
- Python 3.x for `build.py` and `build_keygen.py`
- ASLR must be disabled on the target (vtable & patch addresses are fixed)

---

## License

For private server and reverse engineering education purposes only. Do not use to disrupt public servers or other people's games.

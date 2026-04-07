#include <windows.h>
#include <tlhelp32.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <wincrypt.h>
#include <iphlpapi.h>
#ifndef CALG_SHA_256
#define CALG_SHA_256 0x0000800c
#endif
#include "patches.h"

// ─── CONFIG ──────────────────────────────────────────────────────────────────
#define CHECK_INTERVAL  3000
#define GRACE_PERIOD    30000

// ─── WHITELIST HARDWARE KEYS ─────────────────────────────────────────────────
static const char* WHITELIST_KEYS[] = {
    "D9BDA5282C20689D5A4F662A7C10565xxxx6AF6E4289F61751C95A6EDDEB96A7",
	"EF0871569BBFF607E3C245F85CE7xxxxCAB8FDA39654DE4EC79ACFBD0FF49C93",
    NULL
};

static char g_logPath[MAX_PATH] = {0};
static BOOL g_isWhitelisted = FALSE;

static void Log(const char* msg) {
    if (g_logPath[0] == 0) return;
    FILE* f = fopen(g_logPath, "a");
    if (f) { fprintf(f, "%s\n", msg); fclose(f); }
}


// IP aktif disimpan di sini setelah LoadServerGroup() dipanggil
static char  g_srv_ip[64]       = "127.0.0.1";
static char  g_srv_buddy_ip[64] = "127.0.0.1";
static WORD  g_srv_port         = 8625;
static WORD  g_srv_buddy_port   = 8626;
static DWORD g_srv_version      = 440;

// ─── Hook RegQueryValueExA ───────────────────────────────────────────────────
typedef LONG (WINAPI *pRegQueryValueExA_t)(HKEY, LPCSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
static pRegQueryValueExA_t orig_RegQueryValueExA = NULL;
static BYTE  orig_bytes[5] = {0};
static LPVOID hook_target   = NULL;

static void PauseHook() {
    if (!hook_target) return;
    DWORD op;
    VirtualProtect(hook_target, 5, PAGE_EXECUTE_READWRITE, &op);
    memcpy(hook_target, orig_bytes, 5);
    VirtualProtect(hook_target, 5, op, &op);
    FlushInstructionCache(GetCurrentProcess(), hook_target, 5);
}

static LONG WINAPI hooked_RegQueryValueExA(
    HKEY hKey, LPCSTR lpValueName, LPDWORD lpReserved,
    LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData);

static void ResumeHook() {
    if (!hook_target) return;
    DWORD op;
    VirtualProtect(hook_target, 5, PAGE_EXECUTE_READWRITE, &op);
    BYTE* dst = (BYTE*)hook_target;
    DWORD rel = (DWORD)((BYTE*)hooked_RegQueryValueExA - dst - 5);
    dst[0] = 0xE9;
    memcpy(dst+1, &rel, 4);
    VirtualProtect(hook_target, 5, op, &op);
    FlushInstructionCache(GetCurrentProcess(), hook_target, 5);
}

static LONG WINAPI hooked_RegQueryValueExA(
    HKEY hKey, LPCSTR lpValueName, LPDWORD lpReserved,
    LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)
{
    if (lpValueName == NULL) goto call_orig;

    #define RET_STR(str, len) { \
        DWORD need = (DWORD)(len); \
        if (lpType)  *lpType = REG_SZ; \
        if (lpcbData && lpData) { memcpy(lpData, str, need); *lpcbData = need; } \
        else if (lpcbData) *lpcbData = need; \
        char lmsg[128]; sprintf(lmsg, "REG hook: %s -> %s", lpValueName, (char*)(str)); Log(lmsg); \
        return ERROR_SUCCESS; }

    #define RET_DWORD(val) { \
        DWORD d = val; \
        if (lpType)  *lpType = REG_DWORD; \
        if (lpcbData && lpData) { memcpy(lpData, &d, 4); *lpcbData = 4; } \
        else if (lpcbData) *lpcbData = 4; \
        char lmsg[128]; sprintf(lmsg, "REG hook: %s -> %d", lpValueName, val); Log(lmsg); \
        return ERROR_SUCCESS; }

    if (_stricmp(lpValueName, "ip")        == 0) { RET_STR(g_srv_ip,       (DWORD)strlen(g_srv_ip)+1) }
    if (_stricmp(lpValueName, "buddyip")   == 0) { RET_STR(g_srv_buddy_ip, (DWORD)strlen(g_srv_buddy_ip)+1) }
    if (_stricmp(lpValueName, "port")      == 0) { RET_DWORD(g_srv_port) }
    if (_stricmp(lpValueName, "buddyport") == 0) { RET_DWORD(g_srv_buddy_port) }
    if (_stricmp(lpValueName, "version")   == 0) { RET_DWORD(g_srv_version) }

    #undef RET_STR
    #undef RET_DWORD

call_orig:
    PauseHook();
    LONG ret = orig_RegQueryValueExA(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);
    ResumeHook();
    return ret;
}

static void InstallHook() {
    HMODULE hAdv = LoadLibraryA("advapi32.dll");
    if (!hAdv) { Log("Hook: advapi32 not found"); return; }

    hook_target = (LPVOID)GetProcAddress(hAdv, "RegQueryValueExA");
    if (!hook_target) { Log("Hook: RegQueryValueExA not found"); return; }

    orig_RegQueryValueExA = (pRegQueryValueExA_t)hook_target;
    memcpy(orig_bytes, hook_target, 5);

    DWORD oldProt;
    VirtualProtect(hook_target, 5, PAGE_EXECUTE_READWRITE, &oldProt);
    BYTE* dst = (BYTE*)hook_target;
    DWORD rel = (DWORD)((BYTE*)hooked_RegQueryValueExA - dst - 5);
    dst[0] = 0xE9;
    memcpy(dst+1, &rel, 4);
    VirtualProtect(hook_target, 5, oldProt, &oldProt);
    FlushInstructionCache(GetCurrentProcess(), hook_target, 5);

    Log("Hook: RegQueryValueExA installed!");
}

// ─── NtQuerySystemInformation ─────────────────────────────────────────────────
#define SystemHandleInformation     16
#define STATUS_SUCCESS              ((LONG)0x00000000)
#define STATUS_INFO_LENGTH_MISMATCH ((LONG)0xC0000004)
typedef LONG NTSTATUS;

typedef struct _SYSTEM_HANDLE {
    DWORD  ProcessId;
    BYTE   ObjectTypeNumber;
    BYTE   Flags;
    USHORT Handle;
    PVOID  Object;
    DWORD  GrantedAccess;
} SYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    DWORD         HandleCount;
    SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION;

typedef NTSTATUS (WINAPI *pNtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);
typedef DWORD    (WINAPI *pGetProcessId)(HANDLE);

// ─── WMI / SHA256 / Hardware Whitelist ───────────────────────────────────────

// ─── MAC Address ─────────────────────────────────────────────────────────────
static void GetMACAddress(char* out, DWORD outSize) {
    IP_ADAPTER_INFO adapterInfo[16];
    DWORD bufLen = sizeof(adapterInfo);
    if (GetAdaptersInfo(adapterInfo, &bufLen) != ERROR_SUCCESS) {
        strncpy(out, "UNKNOWN", outSize-1);
        return;
    }
    PIP_ADAPTER_INFO adapter = adapterInfo;
    while (adapter) {
        if (adapter->Type != MIB_IF_TYPE_LOOPBACK &&
            adapter->AddressLength == 6) {
            snprintf(out, outSize, "%02X:%02X:%02X:%02X:%02X:%02X",
                adapter->Address[0], adapter->Address[1],
                adapter->Address[2], adapter->Address[3],
                adapter->Address[4], adapter->Address[5]);
            return;
        }
        adapter = adapter->Next;
    }
    strncpy(out, "UNKNOWN", outSize-1);
}

static void GetWMIValue(const char* query, char* out, DWORD outSize) {
    char tmpPath[MAX_PATH];
    GetTempPathA(MAX_PATH, tmpPath);
    strcat(tmpPath, "__hwid_tmp.txt");

    SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, TRUE};
    HANDLE hFile = CreateFileA(tmpPath, GENERIC_WRITE, 0, &sa,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) { strcpy(out, "UNKNOWN"); return; }

    STARTUPINFOA si = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = hFile;
    si.hStdError  = hFile;

    PROCESS_INFORMATION pi = {0};
    char fullCmd[600];
    sprintf(fullCmd, "cmd.exe /c wmic %s /format:value", query);

    if (CreateProcessA(NULL, fullCmd, NULL, NULL, TRUE,
                       CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 5000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    CloseHandle(hFile);

    FILE* f = fopen(tmpPath, "r");
    if (!f) { strcpy(out, "UNKNOWN"); return; }
    char line[256];
    out[0] = 0;
    while (fgets(line, sizeof(line), f)) {
        char* eq = strchr(line, '=');
        if (eq && strlen(eq+1) > 1) {
            strncpy(out, eq+1, outSize-1);
            char* nl = strchr(out, '\n'); if (nl) *nl = 0;
            char* cr = strchr(out, '\r'); if (cr) *cr = 0;
            break;
        }
    }
    fclose(f);
    DeleteFileA(tmpPath);
}

static void sha256(const char* input, char* hexOut) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    if (!CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        strcpy(hexOut, "CRYPTO_FAIL"); return;
    }
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0); strcpy(hexOut, "HASH_FAIL"); return;
    }
    CryptHashData(hHash, (BYTE*)input, (DWORD)strlen(input), 0);
    BYTE hashBytes[32]; DWORD hashLen = 32;
    CryptGetHashParam(hHash, HP_HASHVAL, hashBytes, &hashLen, 0);
    for (int i = 0; i < 32; i++) sprintf(hexOut + i*2, "%02X", hashBytes[i]);
    hexOut[64] = 0;
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
}

static BOOL CheckHardwareWhitelist() {
    if (WHITELIST_KEYS[0] == NULL) return FALSE;
    char cpu[128] = "UNKNOWN";
    char mac[32]  = "UNKNOWN";
    GetWMIValue("cpu get ProcessorId", cpu, sizeof(cpu));
    GetMACAddress(mac, sizeof(mac));
    char combined[512];
    sprintf(combined, "GUNBOUND|%s|%s|PRIVATE_SERVER", cpu, mac);
    char key[128] = {0};
    sha256(combined, key);
    char logmsg[256]; sprintf(logmsg, "Hardware key: %s", key); Log(logmsg);
    char dbg[256]; sprintf(dbg, "HWID: CPU=%s | MAC=%s", cpu, mac); Log(dbg);
    for (int i = 0; WHITELIST_KEYS[i] != NULL; i++)
        if (strcmp(key, WHITELIST_KEYS[i]) == 0) { Log("PC ini ada di WHITELIST!"); return TRUE; }
    return FALSE;
}

// ─── Suspend/Resume ───────────────────────────────────────────────────────────
static void SuspendAllThreads(DWORD myTID) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;
    THREADENTRY32 te; te.dwSize = sizeof(te);
    DWORD pid = GetCurrentProcessId();
    if (Thread32First(hSnap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid && te.th32ThreadID != myTID) {
                HANDLE h = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                if (h) { SuspendThread(h); CloseHandle(h); }
            }
        } while (Thread32Next(hSnap, &te));
    }
    CloseHandle(hSnap);
}

static void ResumeAllThreads(DWORD myTID) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;
    THREADENTRY32 te; te.dwSize = sizeof(te);
    DWORD pid = GetCurrentProcessId();
    if (Thread32First(hSnap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid && te.th32ThreadID != myTID) {
                HANDLE h = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                if (h) { ResumeThread(h); CloseHandle(h); }
            }
        } while (Thread32Next(hSnap, &te));
    }
    CloseHandle(hSnap);
}

// ─── Patch string (baca grup dari config.ini) ────────────────────────────────
// ─── Load server group dari config.ini ───────────────────────────────────────
static void xor_decrypt_ip(const BYTE* enc, DWORD len, char* out) {
    for (DWORD i = 0; i < len; i++)
        out[i] = (char)(enc[i] ^ SRV_XOR_KEY[i % SRV_XOR_KEY_LEN]);
    out[len] = 0;
}

static void LoadServerGroup(const char* configPath) {
    char srvValue[32] = {0};
    GetPrivateProfileStringA("Plugin", "SERVER", SRV_DEFAULT_GROUP,
                             srvValue, sizeof(srvValue), configPath);
    // Trim
    char* p = srvValue;
    while (*p == ' ' || *p == '\t') p++;
    char* end = p + strlen(p) - 1;
    while (end > p && (*end == 32 || *end == 9 || *end == 13 || *end == 10)) *end-- = 0;

    const SrvEncGroup* grp = NULL;
    for (DWORD i = 0; i < SRV_ENC_GROUP_COUNT; i++) {
        if (_stricmp(SRV_ENC_GROUPS[i].name, p) == 0) {
            grp = &SRV_ENC_GROUPS[i];
            break;
        }
    }
    if (!grp) {
        char msg[128];
        sprintf(msg, "SERVER group '%s' tidak ditemukan, pakai default: %s", p, SRV_DEFAULT_GROUP);
        Log(msg);
        for (DWORD i = 0; i < SRV_ENC_GROUP_COUNT; i++) {
            if (_stricmp(SRV_ENC_GROUPS[i].name, SRV_DEFAULT_GROUP) == 0) {
                grp = &SRV_ENC_GROUPS[i];
                break;
            }
        }
    }
    if (!grp) { Log("LoadServerGroup: tidak ada grup!"); return; }

    // Decrypt IP dari encrypted bytes
    xor_decrypt_ip(grp->enc_ip,       grp->enc_ip_len,       g_srv_ip);
    xor_decrypt_ip(grp->enc_buddy_ip, grp->enc_buddy_ip_len, g_srv_buddy_ip);
    g_srv_port       = grp->port;
    g_srv_buddy_port = grp->buddy_port;
    g_srv_version    = grp->version;

    char msg[256];
    sprintf(msg, "Server group: %s | IP=%s:%d | BuddyIP=%s:%d | Version=%u",
            grp->name, g_srv_ip, g_srv_port, g_srv_buddy_ip, g_srv_buddy_port, g_srv_version);
    Log(msg);
}

static void PatchString() {
    // Dapatkan folder DLL untuk path config.ini
    char configPath[MAX_PATH] = {0};
    strncpy(configPath, g_logPath, MAX_PATH - 1);
    char* slash = strrchr(configPath, '\\');
    if (slash) *(slash + 1) = 0;
    strcat(configPath, "config.ini");

    // Load server group (IP/port) dari config.ini
    LoadServerGroup(configPath);

    // Baca ProductVersion group dari config.ini
    char pvValue[32] = {0};
    GetPrivateProfileStringA("Plugin", "ProductVersion", "", pvValue, sizeof(pvValue), configPath);
    // Trim whitespace
    char* pv = pvValue;
    while (*pv == ' ' || *pv == '\t') pv++;
    char* pvEnd = pv + strlen(pv) - 1;
    while (pvEnd > pv && (*pvEnd == 32 || *pvEnd == 9 || *pvEnd == 13 || *pvEnd == 10)) *pvEnd-- = 0;

    if (pv[0] != '\0') {
        const PVGroup* pvGroup = NULL;
        for (DWORD i = 0; i < PV_GROUP_COUNT; i++) {
            if (_stricmp(PV_GROUPS[i].name, pv) == 0) {
                pvGroup = &PV_GROUPS[i];
                break;
            }
        }
        if (pvGroup) {
            LPVOID pvTarget = (LPVOID)0x004F277F;
            DWORD pvOldProtect;
            if (VirtualProtect(pvTarget, sizeof(DWORD), PAGE_EXECUTE_READWRITE, &pvOldProtect)) {
                memcpy(pvTarget, &pvGroup->value, sizeof(DWORD));
                VirtualProtect(pvTarget, sizeof(DWORD), pvOldProtect, &pvOldProtect);
            }
            char pvMsg[128];
            sprintf(pvMsg, "Config: ProductVersion = %s (%u) -> patched @ 0x004F277F", pvGroup->name, pvGroup->value);
            Log(pvMsg);
        } else {
            char pvMsg[128];
            sprintf(pvMsg, "Config: ProductVersion group '%s' tidak ditemukan!", pv);
            Log(pvMsg);
        }
    }

    // Baca LANGUAGE dari config.ini
    char langValue[32] = {0};
    GetPrivateProfileStringA("Plugin", "LANGUAGE", PATCH_DEFAULT_GROUP,
                             langValue, sizeof(langValue), configPath);

    // Trim whitespace
    char* p = langValue;
    while (*p == ' ' || *p == '	') p++;
    char* end = p + strlen(p) - 1;
    while (end > p && (*end == 32 || *end == 9 || *end == 13 || *end == 10)) *end-- = 0;

    char logmsg[128];
    sprintf(logmsg, "Config: LANGUAGE = %s", p);
    Log(logmsg);

    // Cari grup yang cocok
    const PatchGroup* group = NULL;
    for (DWORD i = 0; i < PATCH_GROUP_COUNT; i++) {
        if (_stricmp(PATCH_GROUPS[i].name, p) == 0) {
            group = &PATCH_GROUPS[i];
            break;
        }
    }

    if (!group) {
        sprintf(logmsg, "LANGUAGE '%s' tidak ditemukan, pakai default: %s", p, PATCH_DEFAULT_GROUP);
        Log(logmsg);
        for (DWORD i = 0; i < PATCH_GROUP_COUNT; i++) {
            if (_stricmp(PATCH_GROUPS[i].name, PATCH_DEFAULT_GROUP) == 0) {
                group = &PATCH_GROUPS[i];
                break;
            }
        }
    }

    if (!group) { Log("Patch: tidak ada grup ditemukan!"); return; }

    sprintf(logmsg, "Patch group aktif: %s (%d patches)", group->name, (int)group->count);
    Log(logmsg);

    // Apply semua string patch dalam grup
    for (DWORD i = 0; i < group->count; i++) {
        LPVOID target   = (LPVOID)group->patches[i].address;
        const char* val = group->patches[i].value;
        SIZE_T patchLen = strlen(val) + 1;
        DWORD oldProtect;
        if (VirtualProtect(target, patchLen, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            memcpy(target, val, patchLen);
            VirtualProtect(target, patchLen, oldProtect, &oldProtect);
        }
        char msg[128];
        sprintf(msg, "  Patched @ 0x%08X -> %s", group->patches[i].address, val);
        Log(msg);
    }

}

// ─── Blacklist ────────────────────────────────────────────────────────────────
static const char* BLACKLIST[] = {
    "cheatengine", "ollydbg", "x64dbg", "x32dbg",
    "idaq", "idaq64", "ida64", "windbg",
    "processhacker", "artmoney", "tsearch",
    "python",  // aimbot scripts
    NULL
};

static BOOL IsBlacklisted(const char* name) {
    char lower[256] = {0};
    for (int i = 0; name[i] && i < 255; i++)
        lower[i] = (char)tolower((unsigned char)name[i]);
    for (int i = 0; BLACKLIST[i] != NULL; i++)
        if (strstr(lower, BLACKLIST[i])) return TRUE;
    return FALSE;
}

static void CheckAndAct(const char* reason, const char* procName, DWORD pid, DWORD access) {
    char msg[256];
    if (g_isWhitelisted) {
        sprintf(msg, "DETECTED (WHITELISTED - no terminate): %s | %s (PID=%d Access=0x%X)",
                reason, procName, pid, access);
        Log(msg);
    } else {
        sprintf(msg, "DETECTED - TERMINATE: %s | %s (PID=%d Access=0x%X)",
                reason, procName, pid, access);
        Log(msg);
        TerminateProcess(GetCurrentProcess(), 0);
    }
}

static void DetectBlacklistedProcess() {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32 pe; pe.dwSize = sizeof(pe);
    if (Process32First(hSnap, &pe)) {
        do {
            if (IsBlacklisted(pe.szExeFile))
                CheckAndAct("BLACKLIST", pe.szExeFile, pe.th32ProcessID, 0);
        } while (Process32Next(hSnap, &pe));
    }
    CloseHandle(hSnap);
}

static void DetectExternalHandle() {
    DWORD myPID = GetCurrentProcessId();
    pNtQuerySystemInformation NtQSI = (pNtQuerySystemInformation)
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
    pGetProcessId fnGetPID = (pGetProcessId)
        GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetProcessId");
    if (!NtQSI || !fnGetPID) return;

    HANDLE hSelf = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, myPID);
    if (!hSelf) return;

    ULONG bufSize = 1024 * 512;
    BYTE* buf = NULL;
    NTSTATUS status = STATUS_INFO_LENGTH_MISMATCH;
    while (status == STATUS_INFO_LENGTH_MISMATCH) {
        if (buf) HeapFree(GetProcessHeap(), 0, buf);
        buf = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bufSize);
        if (!buf) { CloseHandle(hSelf); return; }
        ULONG retLen = 0;
        status = NtQSI(SystemHandleInformation, buf, bufSize, &retLen);
        if (status == STATUS_INFO_LENGTH_MISMATCH) bufSize *= 2;
    }
    if (status != STATUS_SUCCESS) { HeapFree(GetProcessHeap(), 0, buf); CloseHandle(hSelf); return; }

    BYTE processTypeNumber = 0;
    SYSTEM_HANDLE_INFORMATION* info = (SYSTEM_HANDLE_INFORMATION*)buf;
    for (DWORD i = 0; i < info->HandleCount; i++) {
        SYSTEM_HANDLE* h = &info->Handles[i];
        if (h->ProcessId == myPID && (HANDLE)(ULONG_PTR)h->Handle == hSelf) {
            processTypeNumber = h->ObjectTypeNumber; break;
        }
    }
    CloseHandle(hSelf);

    for (DWORD i = 0; i < info->HandleCount; i++) {
        SYSTEM_HANDLE* h = &info->Handles[i];
        if (h->ProcessId == myPID) continue;
        if (processTypeNumber > 0 && h->ObjectTypeNumber != processTypeNumber) continue;
        BOOL hasVmRead  = (h->GrantedAccess & 0x10) != 0;
        BOOL hasVmWrite = (h->GrantedAccess & 0x20) != 0;
        BOOL hasVmOp    = (h->GrantedAccess & 0x08) != 0;
        if (!hasVmRead) continue;
        BOOL isSuspicious = hasVmWrite || hasVmOp;

        HANDLE hOwner = OpenProcess(PROCESS_DUP_HANDLE, FALSE, h->ProcessId);
        if (!hOwner) {
            if (isSuspicious) {
                char exeName[MAX_PATH] = "unknown";
                HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                if (hSnap != INVALID_HANDLE_VALUE) {
                    PROCESSENTRY32 pe; pe.dwSize = sizeof(pe);
                    if (Process32First(hSnap, &pe)) do {
                        if (pe.th32ProcessID == h->ProcessId) { strcpy(exeName, pe.szExeFile); break; }
                    } while (Process32Next(hSnap, &pe));
                    CloseHandle(hSnap);
                }
                char lower[256]={0};
                for(int j=0;exeName[j]&&j<255;j++) lower[j]=(char)tolower((unsigned char)exeName[j]);
                if (strstr(lower, "python"))
                    CheckAndAct("PYTHON ATTACH", exeName, h->ProcessId, h->GrantedAccess);
            }
            continue;
        }

        HANDLE hDup = NULL;
        if (!DuplicateHandle(hOwner, (HANDLE)(ULONG_PTR)h->Handle,
                             GetCurrentProcess(), &hDup,
                             PROCESS_QUERY_LIMITED_INFORMATION, FALSE, 0)) {
            CloseHandle(hOwner); continue;
        }
        DWORD targetPID = fnGetPID(hDup);
        CloseHandle(hDup);
        if (targetPID != myPID) { CloseHandle(hOwner); continue; }

        char exeName[MAX_PATH] = "unknown";
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe; pe.dwSize = sizeof(pe);
            if (Process32First(hSnap, &pe)) do {
                if (pe.th32ProcessID == h->ProcessId) { strcpy(exeName, pe.szExeFile); break; }
            } while (Process32Next(hSnap, &pe));
            CloseHandle(hSnap);
        }
        char exeLower[MAX_PATH]={0};
        for(int j=0;exeName[j]&&j<MAX_PATH-1;j++)
            exeLower[j]=(char)tolower((unsigned char)exeName[j]);

        if (strstr(exeLower,"launcher")||strstr(exeLower,"gb_launcher")) {
            char wmsg[256]; sprintf(wmsg,"LAUNCHER WHITELISTED: %s (Access=0x%X)",exeName,h->GrantedAccess);
            Log(wmsg);
        } else if (isSuspicious) {
            CheckAndAct("ATTACH", exeName, h->ProcessId, h->GrantedAccess);
        } else {
            char wmsg[256]; sprintf(wmsg,"VM_READ only (ignored): %s (PID=%d Access=0x%X)",exeName,h->ProcessId,h->GrantedAccess);
            Log(wmsg);
        }
        CloseHandle(hOwner);
    }
    HeapFree(GetProcessHeap(), 0, buf);
}

// ─── ShowGameMessage_ ─────────────────────────────────────────────────────────
// Fungsi di gunbound.exe: void __cdecl ShowGameMessage_(const char* text, BYTE channel)
// Pattern: 55 8B EC 51 53 [E8 xx xx xx xx] 8B 58 64 3B 1D
typedef void (__cdecl *pShowGameMessage_t)(const char* text, BYTE channel);
static pShowGameMessage_t g_ShowGameMessage = NULL;

static void FindShowGameMessage() {
    // Pattern scan di modul game
    HMODULE hGame = GetModuleHandleA(NULL);
    if (!hGame) { Log("ShowGameMessage: GetModuleHandle gagal"); return; }

    // Ambil SizeOfImage langsung dari PE header
    BYTE* base = (BYTE*)hGame;
    DWORD e_lfanew  = *(DWORD*)(base + 0x3C);
    DWORD sizeOfImg = *(DWORD*)(base + e_lfanew + 0x50); // OptionalHeader.SizeOfImage

    // Pattern: 55 8B EC 51 53 [skip 5] 8B 58 64 3B 1D
    static const BYTE pat1[] = {0x55, 0x8B, 0xEC, 0x51, 0x53};
    static const BYTE pat2[] = {0x8B, 0x58, 0x64, 0x3B, 0x1D};

    for (DWORD i = 0; i < sizeOfImg - 20; i++) {
        if (memcmp(base + i,      pat1, 5) == 0 &&
            memcmp(base + i + 10, pat2, 5) == 0) {
            g_ShowGameMessage = (pShowGameMessage_t)(base + i);
            char msg[64];
            sprintf(msg, "ShowGameMessage_ found @ 0x%08X", (DWORD)g_ShowGameMessage);
            Log(msg);
            return;
        }
    }
    Log("ShowGameMessage_: pattern tidak ditemukan");
}

// Channel values yang diketahui dari reverse engineering:
// 0 = system/notice, 2 = room chat, 4 = lobby, 0x0A = warning
void ShowNotice(const char* text, BYTE channel = 0) {
    if (g_ShowGameMessage) {
        g_ShowGameMessage(text, channel);
    }
}

// ─── Threads ──────────────────────────────────────────────────────────────────
DWORD WINAPI AntiCheatThread(LPVOID lpParam) {
    Log("AntiCheat: grace period...");
    Sleep(GRACE_PERIOD);
    Log("AntiCheat: scanning...");
    while (TRUE) {
        Sleep(CHECK_INTERVAL);
        DetectBlacklistedProcess();
        DetectExternalHandle();
    }
    return 0;
}

DWORD WINAPI PatchThread(LPVOID lpParam) {
    DWORD myTID = GetCurrentThreadId();
    Log("PatchThread started");
    SuspendAllThreads(myTID);
    PatchString();
    ResumeAllThreads(myTID);
    Log("PatchThread done");
    return 0;
}

extern "C" __declspec(dllexport) void PleaseDontTry() {
    Log("PleaseDontTry called!");
}

BOOL APIENTRY DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);
        GetModuleFileNameA(hinstDLL, g_logPath, MAX_PATH);
        char* slash = strrchr(g_logPath, '\\');
        if (slash) *(slash + 1) = 0;
        strcat(g_logPath, "plugin_debug.txt");
        Log("=== DllMain PROCESS_ATTACH ===");
        InstallHook();
        g_isWhitelisted = CheckHardwareWhitelist();
        Log(g_isWhitelisted ? "Mode: WHITELIST" : "Mode: ENFORCE");
        FindShowGameMessage();
        CreateThread(NULL, 0, PatchThread, NULL, 0, NULL);
        CreateThread(NULL, 0, AntiCheatThread, NULL, 0, NULL);
    }
    return TRUE;
}

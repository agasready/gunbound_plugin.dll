/**
 * keygen.c - GunBound Private Server Hardware ID Generator
 * Compile: python build_keygen.py
 * Kasih keygen.exe ke klien, minta mereka kirim outputnya
 */

#include <windows.h>
#include <wincrypt.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <string.h>

#ifndef CALG_SHA_256
#define CALG_SHA_256 0x0000800c
#endif

// ─── WMI Query ───────────────────────────────────────────────────────────────
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

// ─── Ambil MAC address adapter pertama yang bukan loopback ───────────────────
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

// ─── SHA256 ───────────────────────────────────────────────────────────────────
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

int main() {
    printf("========================================\n");
    printf("  GunBound Private Server - Hardware ID\n");
    printf("========================================\n\n");

    printf("[*] Mengumpulkan informasi hardware...\n\n");

    char cpu[128] = "UNKNOWN";
    char mac[32]  = "UNKNOWN";

    GetWMIValue("cpu get ProcessorId", cpu, sizeof(cpu));
    GetMACAddress(mac, sizeof(mac));

    printf("  CPU ProcessorId : %s\n", cpu);
    printf("  MAC Address     : %s\n", mac);

    char combined[512];
    sprintf(combined, "GUNBOUND|%s|%s|PRIVATE_SERVER", cpu, mac);

    char key[128] = {0};
    sha256(combined, key);

    printf("\n========================================\n");
    printf("  Hardware Key (kirim ke admin):\n\n");
    printf("  %s\n", key);
    printf("========================================\n\n");

    // Tulis ke file juga biar gampang di-copy
    FILE* f = fopen("hwid.txt", "w");
    if (f) {
        fprintf(f, "CPU ProcessorId : %s\n", cpu);
        fprintf(f, "MAC Address     : %s\n", mac);
        fprintf(f, "Hardware Key    : %s\n", key);
        fclose(f);
        printf("[+] Hasil disimpan ke hwid.txt\n");
    }

    printf("\nTekan Enter untuk keluar...");
    getchar();
    return 0;
}

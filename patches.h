/**
 * patches.h - Konfigurasi patch memory GunBound
 *
 * LANGUAGE  -> grup string patch (perlu compile ulang kalau edit)
 * ProductVersion -> grup product version (perlu compile ulang kalau edit)
 * Kedua nilai dibaca dari config.ini, tidak perlu compile ulang untuk ganti grup aktif.
 *
 * Compile ulang setelah edit file ini: python build.py
 */

#ifndef PATCHES_H
#define PATCHES_H

// =============================================================================
// SERVER GROUPS
// Tambah entry baru di SRV_GROUPS[] untuk server baru
// Di config.ini set: SERVER = <n>
//
// CATATAN: IP di sini hanya untuk editing - build.py akan encrypt dan
//          generate srv_enc.h secara otomatis. JANGAN edit srv_enc.h manual.
// =============================================================================
typedef struct {
    const char* name;
    const char* ip;        // plain - hanya untuk referensi di patches.h
    const char* buddy_ip;  // plain - hanya untuk referensi di patches.h
    WORD        port;
    WORD        buddy_port;
    DWORD       version;
} SrvGroup;

static const SrvGroup SRV_GROUPS[] = {
    { "1", "172.65.227.28", "172.65.227.28", 8625, 8626, 440 },
    { "2", "192.168.111.128", "192.168.111.128", 8372, 8352, 440 },
	{ "3", "14.225.218.132", "14.225.218.132", 8372, 8361, 440 },
	{ "4", "177.54.146.228", "177.54.146.228", 9670, 8341, 814 },
	{ "5", "127.0.0.1", "127.0.0.1", 8400, 8352, 440 },
	{ "6", "127.0.0.1", "127.0.0.1", 8401, 8353, 440 },
	{ "7", "192.168.111.148", "192.168.111.148", 8372, 8352, 440 },
	{ "8", "192.168.111.149", "192.168.111.149", 8372, 8352, 440 },
};
#define SRV_GROUP_COUNT (DWORD)(sizeof(SRV_GROUPS) / sizeof(SRV_GROUPS[0]))
#define SRV_DEFAULT_GROUP "1"

// srv_enc.h di-generate otomatis oleh build.py - berisi versi encrypted
#include "srv_enc.h"


// =============================================================================
// PRODUCT VERSION GROUPS
// Tambah entry baru di PV_GROUPS[] untuk versi baru
// Di config.ini set: ProductVersion = <name>
// =============================================================================
typedef struct {
    const char* name;
    DWORD       value;
} PVGroup;

static const PVGroup PV_GROUPS[] = {
	{ "1", 37851212 },   // 0x0241884C  (default gunbound)
    { "2", 8452176  },   // 0x0080E250
	{ "3", 3887256595U},
	{ "4", 91452145},
	{ "8", 8452176  },
//	{ "5", 91452145},
    // { "3", 99999999 },
};
#define PV_GROUP_COUNT (DWORD)(sizeof(PV_GROUPS) / sizeof(PV_GROUPS[0]))


// =============================================================================
// STRING PATCH GROUPS
// =============================================================================
typedef struct {
    DWORD       address;
    const char* value;
} PatchEntry;

typedef struct {
    const char*       name;
    const PatchEntry* patches;
    DWORD             count;
} PatchGroup;

#define PATCH_GROUP(arr) arr, (DWORD)(sizeof(arr) / sizeof(arr[0]))

// ── LANGUAGE = 1 ─────────────────────────────────────────────────────────────
static const PatchEntry patches_lang1[] = {
    { 0x00572EB0, "FourWorx.txt" },
	{ 0x0057A370, "avatar_back.ind" },
	{ 0x00579834, "button.ind" },
	{ 0x005763F4, "gamelist_back.ind" },
	{ 0x00573DC0, "language.ind" },
	{ 0x005780B4, "load_back.ind" },
	{ 0x00579D8C, "option_back.ind" },
	{ 0x00577FE8, "play_back.ind" },
	{ 0x0057AF98, "play_back_blue.ind" },
	{ 0x00572270, "popupbase_addmute.ind" },
	{ 0x00572134, "popupbase_buddy_add.ind" },
	{ 0x00572118, "popupbase_buddy_delete.ind" },
	{ 0x005720C4, "popupbase_buddy_list.ind" },
	{ 0x005720E0, "popupbase_buddy_message.ind" },
	{ 0x00572180, "popupbase_buy.ind" },
	{ 0x00572194, "popupbase_buy_gift.ind" },
	{ 0x00572254, "popupbase_deletemute.ind" },
	{ 0x00572000, "popupbase_gamelist_option.ind" },
	{ 0x00572164, "popupbase_gift_accept.ind" },
	{ 0x00572038, "popupbase_gift_garbage.ind" },
	{ 0x005720AC, "popupbase_gift_sell.ind" },
	{ 0x005721AC, "popupbase_gift_send.ind" },
	{ 0x00572240, "popupbase_goto.ind" },
	{ 0x00572224, "popupbase_gotopassword.ind" },
	{ 0x0057220C, "popupbase_makeroom.ind" },
	{ 0x0057214C, "popupbase_message.ind" },
	{ 0x005721F4, "popupbase_mutelist.ind" },
	{ 0x00572020, "popupbase_myinfo.ind" },
	{ 0x00572090, "popupbase_quickstart.ind" },
	{ 0x0057206C, "popupbase_ready_itemselection.ind" },
	{ 0x00572054, "popupbase_roomtitle.ind" },
	{ 0x0057810C, "ready_back.ind" },
	{ 0x0057A024, "ready_mobile.ind" },
	{ 0x0057A000, "ready_option.ind" },
	{ 0x00576814, "result_back.ind" },
	{ 0x0057A27C, "serverlist_back.ind" }
    // { 0x00AABBCC, "nilai untuk language 1" },
};

// ── LANGUAGE = 2 ─────────────────────────────────────────────────────────────
static const PatchEntry patches_lang2[] = {
    { 0x00572EB0, "fAuswora.txd" },
    // { 0x00AABBCC, "nilai untuk language 2" },
};

// ── LANGUAGE = 3 ─────────────────────────────────────────────────────────────
static const PatchEntry patches_lang3[] = {
    { 0x00572EB0, "fAuswora.txd" },
    // { 0x00AABBCC, "nilai untuk language 3" },
};

static const PatchGroup PATCH_GROUPS[] = {
    { "1", PATCH_GROUP(patches_lang1) },
    { "2", PATCH_GROUP(patches_lang2) },
    { "3", PATCH_GROUP(patches_lang3) },
};

#define PATCH_GROUP_COUNT (DWORD)(sizeof(PATCH_GROUPS) / sizeof(PATCH_GROUPS[0]))
#define PATCH_DEFAULT_GROUP "1"

#endif // PATCHES_H

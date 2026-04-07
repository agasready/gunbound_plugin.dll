import subprocess, shutil, os, sys, re, random

SRC     = "dllmain.cpp"
DEF     = "Plugin.def"
OUT     = "Plugin.dll"
ENC_HDR = "srv_enc.h"

DEF_CONTENT = """LIBRARY Plugin
EXPORTS
    PleaseDontTry
"""

def xor_encrypt(data: bytes, key: bytes) -> list:
    return [data[i] ^ key[i % len(key)] for i in range(len(data))]

def to_c_array(data: list) -> str:
    return ', '.join(f'0x{b:02X}' for b in data)

def parse_srv_groups(patches_h: str):
    """Parse SRV_GROUPS[] dari patches.h"""
    # Ambil isi array SRV_GROUPS
    m = re.search(r'static const SrvGroup SRV_GROUPS\[\]\s*=\s*\{(.*?)\};',
                  patches_h, re.DOTALL)
    if not m:
        print("[!] SRV_GROUPS tidak ditemukan di patches.h")
        sys.exit(1)

    groups = []
    # Match tiap entry: { "name", "ip", "buddy_ip", port, buddy_port, version }
    pattern = re.compile(
        r'\{\s*"([^"]+)"\s*,\s*"([^"]+)"\s*,\s*"([^"]+)"\s*,'
        r'\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*\}'
    )
    for m2 in pattern.finditer(m.group(1)):
        groups.append({
            'name':       m2.group(1),
            'ip':         m2.group(2),
            'buddy_ip':   m2.group(3),
            'port':       int(m2.group(4)),
            'buddy_port': int(m2.group(5)),
            'version':    int(m2.group(6)),
        })
    return groups

def generate_srv_enc_h():
    with open('patches.h', 'r') as f:
        patches_h = f.read()

    groups = parse_srv_groups(patches_h)
    if not groups:
        print("[!] Tidak ada entry di SRV_GROUPS")
        sys.exit(1)

    # Generate random XOR key setiap build
    key = bytes(random.randint(0, 255) for _ in range(16))

    lines = []
    lines.append("/* srv_enc.h - AUTO GENERATED oleh build.py - JANGAN EDIT MANUAL */")
    lines.append("#ifndef SRV_ENC_H")
    lines.append("#define SRV_ENC_H")
    lines.append("")
    lines.append(f"static const BYTE SRV_XOR_KEY[] = {{{to_c_array(list(key))}}};")
    lines.append(f"#define SRV_XOR_KEY_LEN 16")
    lines.append("")
    lines.append("typedef struct {")
    lines.append("    const char* name;")
    lines.append("    const BYTE* enc_ip;")
    lines.append("    DWORD       enc_ip_len;")
    lines.append("    const BYTE* enc_buddy_ip;")
    lines.append("    DWORD       enc_buddy_ip_len;")
    lines.append("    WORD        port;")
    lines.append("    WORD        buddy_port;")
    lines.append("    DWORD       version;")
    lines.append("} SrvEncGroup;")
    lines.append("")

    for g in groups:
        n = g['name']
        enc_ip       = xor_encrypt(g['ip'].encode()       + b'\x00', key)
        enc_buddy_ip = xor_encrypt(g['buddy_ip'].encode() + b'\x00', key)
        lines.append(f"static const BYTE srv_enc_ip_{n}[]       = {{{to_c_array(enc_ip)}}};")
        lines.append(f"static const BYTE srv_enc_buddy_ip_{n}[] = {{{to_c_array(enc_buddy_ip)}}};")

    lines.append("")
    lines.append("static const SrvEncGroup SRV_ENC_GROUPS[] = {")
    for g in groups:
        n = g['name']
        ip_len       = len(g['ip'])
        buddy_ip_len = len(g['buddy_ip'])
        lines.append(f'    {{ "{n}", '
                     f'srv_enc_ip_{n}, {ip_len}, '
                     f'srv_enc_buddy_ip_{n}, {buddy_ip_len}, '
                     f'{g["port"]}, {g["buddy_port"]}, {g["version"]} }},')
    lines.append("};")
    lines.append(f"#define SRV_ENC_GROUP_COUNT (DWORD)(sizeof(SRV_ENC_GROUPS) / sizeof(SRV_ENC_GROUPS[0]))")
    lines.append("")
    lines.append("#endif // SRV_ENC_H")

    with open(ENC_HDR, 'w') as f:
        f.write('\n'.join(lines))

    print(f"[+] {ENC_HDR} di-generate ({len(groups)} grup, XOR key random)")
    for g in groups:
        print(f"    SERVER {g['name']}: {g['ip']}:{g['port']} | buddy={g['buddy_ip']}:{g['buddy_port']} | ver={g['version']}")

def main():
    # Generate srv_enc.h dari patches.h
    generate_srv_enc_h()

    # Auto generate def file
    with open(DEF, "w") as f:
        f.write(DEF_CONTENT)
    print(f"[+] Generated {DEF}")

    if shutil.which("g++"):
        print("[*] Compiling dengan MinGW g++...")
        cmd = [
            "g++", "-shared", "-m32",
            "-o", OUT,
            SRC, DEF,
            "-lkernel32",
            "-ladvapi32",
            "-liphlpapi",
            "-static-libgcc", "-static-libstdc++",
            "-Wl,--kill-at",
        ]
    elif shutil.which("cl"):
        print("[*] Compiling dengan MSVC...")
        cmd = ["cl", "/LD", "/EHsc", SRC, "/link", f"/DEF:{DEF}", f"/OUT:{OUT}",
               "kernel32.lib", "advapi32.lib", "iphlpapi.lib"]
    else:
        print("[!] Ga ada compiler! Install MinGW dulu.")
        sys.exit(1)

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print("[!] COMPILE GAGAL:")
        print(result.stderr)
        sys.exit(1)

    print(f"[+] Berhasil! {OUT} ({os.path.getsize(OUT):,} bytes)")
    print(f"[*] Copy {OUT} ke folder game:")
    print(f"    C:\\Program Files (x86)\\GunBoundWC\\game\\")

    # Cleanup
    for f in [DEF, ENC_HDR, "Plugin.exp", "Plugin.lib", "dllmain.obj"]:
        if os.path.exists(f):
            os.remove(f)

if __name__ == "__main__":
    main()

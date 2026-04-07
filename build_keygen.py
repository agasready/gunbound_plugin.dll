"""
build_keygen.py - Compile keygen.exe
Jalankan: python build_keygen.py
"""
import subprocess, shutil, os, sys

SRC = "keygen.c"
OUT = "keygen.exe"

def main():
    if shutil.which("gcc"):
        print("[*] Compiling keygen.exe dengan GCC...")
        cmd = [
            "gcc", "-m32",
            "-o", OUT,
            SRC,
            "-lkernel32", "-ladvapi32", "-liphlpapi",
            "-static-libgcc",
        ]
    elif shutil.which("cl"):
        print("[*] Compiling dengan MSVC...")
        cmd = ["cl", SRC, f"/Fe{OUT}", "kernel32.lib", "advapi32.lib"]
    else:
        print("[!] Ga ada compiler!")
        sys.exit(1)

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print("[!] GAGAL:"); print(result.stderr); sys.exit(1)

    print(f"[+] Berhasil! {OUT} ({os.path.getsize(OUT):,} bytes)")
    print(f"[+] Kasih keygen.exe ke klien, minta mereka kirim hasilnya ke lo")

    for f in ["keygen.obj", "keygen.exp", "keygen.lib"]:
        if os.path.exists(f): os.remove(f)

if __name__ == "__main__":
    main()

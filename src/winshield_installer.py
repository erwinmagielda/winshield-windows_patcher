"""
WinShield Installer

Installs a selected Windows update package (.msu or .cab) from the downloads directory.
Requires administrative privileges.
"""

import ctypes
import os
import re
import subprocess
import sys
from typing import List


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(SCRIPT_DIR)
DOWNLOADS_DIR = os.path.join(ROOT_DIR, "downloads")

os.makedirs(DOWNLOADS_DIR, exist_ok=True)


def is_admin() -> bool:
    """Return True if the current process has administrative privileges."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def find_packages(path: str) -> List[str]:
    """Return a sorted list of .msu and .cab packages in the given directory."""
    packages: List[str] = []

    for name in os.listdir(path):
        full = os.path.join(path, name)
        if not os.path.isfile(full):
            continue

        if os.path.splitext(name)[1].lower() in (".msu", ".cab"):
            packages.append(full)

    return sorted(packages, key=lambda p: os.path.basename(p).lower())


def extract_kb_label(filename: str) -> str:
    """Extract a KB identifier from a filename if present."""
    m = re.search(r"(KB\d{4,8})", filename, flags=re.IGNORECASE)
    return m.group(1).upper() if m else filename


def run_command(argv: List[str]) -> int:
    """Execute a command and return its exit code."""
    result = subprocess.run(argv, text=True)
    return int(result.returncode or 0)


def main() -> int:
    print("[*] Running WinShield installer")

    if not is_admin():
        print("[!] Administrator privileges are required")
        return 1

    packages = find_packages(DOWNLOADS_DIR)
    if not packages:
        print("[+] No update packages found")
        return 0

    print()
    for i, path in enumerate(packages, start=1):
        print(f"{i}) {os.path.basename(path)}")

    raw = input("Select package number: ").strip()
    if not raw.isdigit():
        print("[!] Invalid selection")
        return 1

    idx = int(raw)
    if idx < 1 or idx > len(packages):
        print("[!] Selection out of range")
        return 1

    chosen = packages[idx - 1]
    name = os.path.basename(chosen)
    kb_label = extract_kb_label(name)

    print(f"[*] Installing {kb_label}")

    ext = os.path.splitext(chosen)[1].lower()
    if ext == ".msu":
        code = run_command(["wusa.exe", chosen, "/quiet", "/norestart"])
    else:
        code = run_command(
            ["dism.exe", "/online", "/add-package", f"/packagepath:{chosen}", "/quiet", "/norestart"]
        )

    print(f"[+] Installer exit code: {code}")
    return 0 if code in (0, 3010) else 1


if __name__ == "__main__":
    sys.exit(main())

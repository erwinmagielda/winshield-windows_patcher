"""
WinShield Installer

- Loads winshield_download_result.json produced by winshield_downloader.py.
- Creates a backup of the last scan result as winshield_scan_before_install.json
  if it exists and no backup is present yet.
- Installs all KB packages with status == "Downloaded" via wusa.exe.
- Records per-KB install status in winshield_install_result.json.

IMPORTANT:
- Must be run from an elevated (Administrator) command prompt.
"""

import ctypes
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime
from typing import Any, Dict, List

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DOWNLOAD_RESULT_PATH = os.path.join(SCRIPT_DIR, "winshield_download_result.json")
INSTALL_RESULT_PATH = os.path.join(SCRIPT_DIR, "winshield_install_result.json")
SCAN_RESULT_PATH = os.path.join(SCRIPT_DIR, "winshield_scan_result.json")
SCAN_BEFORE_PATH = os.path.join(SCRIPT_DIR, "winshield_scan_before_install.json")


def is_admin() -> bool:
    """Return True if the current process has administrative privileges."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def main() -> None:
    if not os.path.isfile(DOWNLOAD_RESULT_PATH):
        print("[X] winshield_download_result.json not found. Run winshield_downloader.py first.")
        sys.exit(1)

    if not is_admin():
        print("[X] WinShield installer must be run as Administrator.")
        print("    Open an elevated PowerShell or Command Prompt and run this script again.")
        sys.exit(1)

    # Backup the last scan result as "before install" snapshot (for verifier)
    if os.path.isfile(SCAN_RESULT_PATH) and not os.path.isfile(SCAN_BEFORE_PATH):
        try:
            shutil.copy2(SCAN_RESULT_PATH, SCAN_BEFORE_PATH)
            print(f"[+] Backed up pre-install scan to {SCAN_BEFORE_PATH}")
        except Exception as exc:
            print(f"[!] Failed to create pre-install scan backup: {exc}")

    with open(DOWNLOAD_RESULT_PATH, "r", encoding="utf-8") as handle:
        download_summary = json.load(handle)

    baseline = download_summary.get("baseline") or {}
    download_results: List[Dict[str, Any]] = download_summary.get("results") or []

    # Filter to only those entries that have actually been downloaded
    to_install = [
        entry
        for entry in download_results
        if entry.get("status") == "Downloaded" and entry.get("local_path")
    ]

    if not to_install:
        print("[+] There are no downloaded KBs to install (no entries with status == 'Downloaded').")
        return

    print(f"[*] Preparing to install {len(to_install)} downloaded KB package(s).")
    print("============================================================")
    for entry in to_install:
        print(f"  - {entry.get('kb')} from {entry.get('local_path')}")
    print("============================================================")

    install_operations: List[Dict[str, Any]] = []

    for entry in to_install:
        kb = entry.get("kb")
        local_path = entry.get("local_path")

        if not local_path or not os.path.isfile(local_path):
            print(f"[!] Local file not found for {kb}: {local_path}")
            install_operations.append(
                {
                    "kb": kb,
                    "local_path": local_path,
                    "status": "Failed",
                    "exit_code": None,
                    "reason": "Local file missing",
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                }
            )
            continue

        print(f"[*] Installing {kb} via wusa.exe ...")
        cmd = ["wusa.exe", local_path, "/quiet", "/norestart"]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            exit_code = result.returncode
        except Exception as exc:
            print(f"[!] Failed to invoke wusa.exe for {kb}: {exc}")
            install_operations.append(
                {
                    "kb": kb,
                    "local_path": local_path,
                    "status": "Failed",
                    "exit_code": None,
                    "reason": f"Exception during wusa.exe invocation: {exc}",
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                }
            )
            continue

        if exit_code == 0:
            status = "Installed"
            reason = None
            print(f"[+] {kb} installed successfully.")
        else:
            status = "Failed"
            reason = f"wusa.exe exit code {exit_code}"
            print(f"[!] {kb} install failed with exit code {exit_code}.")

        install_operations.append(
            {
                "kb": kb,
                "local_path": local_path,
                "status": status,
                "exit_code": exit_code,
                "reason": reason,
                "timestamp": datetime.utcnow().isoformat() + "Z",
            }
        )

    install_summary = {
        "baseline": baseline,
        "install_operations": install_operations,
    }

    with open(INSTALL_RESULT_PATH, "w", encoding="utf-8") as handle:
        json.dump(install_summary, handle, indent=2)

    print("\n[+] Install results saved to winshield_install_result.json")
    print("[*] Installation stage complete.")
    print("    To verify effect, run winshield_scanner.py again, then run winshield_verifier.py.")


if __name__ == "__main__":
    main()

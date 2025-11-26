"""
WinShield Installer

- Loads results/winshield_download_result.json produced by winshield_downloader.py.
- Creates a backup of the last scan result as results/winshield_scan_before_install.json
  if it exists and no backup is present yet.
- Installs all KB packages with status == "Downloaded" via:
      * wusa.exe for .msu
      * dism.exe /online /add-package for .cab
- Records per-KB install status in results/winshield_install_result.json.

IMPORTANT:
- Must be run from an elevated (Administrator) PowerShell or Command Prompt.
"""

import ctypes
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime
from typing import Any, Dict, List, Tuple

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(SCRIPT_DIR)

RESULTS_DIR = os.path.join(ROOT_DIR, "results")
os.makedirs(RESULTS_DIR, exist_ok=True)

DOWNLOAD_RESULT_PATH = os.path.join(RESULTS_DIR, "winshield_download_result.json")
INSTALL_RESULT_PATH = os.path.join(RESULTS_DIR, "winshield_install_result.json")
SCAN_RESULT_PATH = os.path.join(RESULTS_DIR, "winshield_scan_result.json")
SCAN_BEFORE_PATH = os.path.join(RESULTS_DIR, "winshield_scan_before_install.json")


def is_admin() -> bool:
    """Return True if the current process has administrative privileges."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def run_subprocess(cmd: List[str]) -> Tuple[int, str, str]:
    """
    Run a subprocess command, capturing stdout/stderr.
    Returns (exit_code, stdout, stderr).
    """
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.returncode, result.stdout, result.stderr
    except Exception as exc:
        return -1, "", f"Exception during subprocess.run: {exc}"


def interpret_wusa_exit_code(exit_code: int) -> Tuple[str, str | None]:
    """
    Map WUSA exit codes to a logical status and human-readable reason.
    """
    if exit_code == 0:
        return "Installed", None
    if exit_code == 3010:
        return "Installed", "Reboot required (WUSA exit code 3010)"
    if exit_code == 2359302:
        return "AlreadyInstalled", "Update already installed (WUSA exit code 2359302)"

    return "Failed", f"WUSA exit code {exit_code}"


def interpret_dism_exit_code(exit_code: int) -> Tuple[str, str | None]:
    """
    Map DISM exit codes to a logical status and human-readable reason.
    """
    if exit_code == 0:
        return "Installed", None
    if exit_code in (3010, 1641):
        return "Installed", f"Reboot required or initiated (DISM exit code {exit_code})"

    return "Failed", f"DISM exit code {exit_code}"


def install_msu(local_path: str) -> Tuple[str, int, str | None, str, str]:
    """
    Install an .msu package using wusa.exe.

    Returns (status, exit_code, reason, stdout, stderr).
    """
    cmd = ["wusa.exe", local_path, "/quiet", "/norestart"]
    exit_code, stdout, stderr = run_subprocess(cmd)

    if exit_code == -1:
        return "Failed", exit_code, "Failed to invoke wusa.exe", stdout, stderr

    status, reason = interpret_wusa_exit_code(exit_code)
    return status, exit_code, reason, stdout, stderr


def install_cab(local_path: str) -> Tuple[str, int, str | None, str, str]:
    """
    Install a .cab package using DISM /online /add-package.

    Returns (status, exit_code, reason, stdout, stderr).
    """
    cmd = [
        "dism.exe",
        "/online",
        "/add-package",
        f"/packagepath:{local_path}",
        "/quiet",
        "/norestart",
    ]
    exit_code, stdout, stderr = run_subprocess(cmd)

    if exit_code == -1:
        return "Failed", exit_code, "Failed to invoke dism.exe", stdout, stderr

    status, reason = interpret_dism_exit_code(exit_code)
    return status, exit_code, reason, stdout, stderr


def main() -> None:
    if not os.path.isfile(DOWNLOAD_RESULT_PATH):
        print("[X] winshield_download_result.json not found in results/. Run winshield_downloader.py first.")
        sys.exit(1)

    if not is_admin():
        print("[X] WinShield installer must be run as Administrator.")
        print("    Open an elevated PowerShell or Command Prompt and run this script again.")
        sys.exit(1)

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
        timestamp = datetime.utcnow().isoformat() + "Z"

        if not local_path or not os.path.isfile(local_path):
            print(f"[!] Local file not found for {kb}: {local_path}")
            install_operations.append(
                {
                    "kb": kb,
                    "local_path": local_path,
                    "package_type": None,
                    "install_tool": None,
                    "status": "Failed",
                    "exit_code": None,
                    "reason": "Local file missing",
                    "timestamp": timestamp,
                    "stdout": "",
                    "stderr": "",
                }
            )
            continue

        _, ext = os.path.splitext(local_path)
        ext_lower = ext.lower()

        if ext_lower == ".msu":
            package_type = "msu"
            install_tool = "wusa"
            print(f"[*] Installing {kb} as MSU via wusa.exe ...")
            status, exit_code, reason, stdout, stderr = install_msu(local_path)

        elif ext_lower == ".cab":
            package_type = "cab"
            install_tool = "dism"
            print(f"[*] Installing {kb} as CAB via dism.exe ...")
            status, exit_code, reason, stdout, stderr = install_cab(local_path)

        else:
            package_type = ext_lower.lstrip(".") or "unknown"
            install_tool = None
            status = "Failed"
            exit_code = None
            reason = f"Unsupported package type: {ext_lower}"
            stdout = ""
            stderr = ""
            print(f"[!] Unsupported file type for {kb}: {local_path}")
            install_operations.append(
                {
                    "kb": kb,
                    "local_path": local_path,
                    "package_type": package_type,
                    "install_tool": install_tool,
                    "status": status,
                    "exit_code": exit_code,
                    "reason": reason,
                    "timestamp": timestamp,
                    "stdout": stdout,
                    "stderr": stderr,
                }
            )
            continue

        if status == "Installed":
            print(f"[+] {kb} installed successfully.")
        elif status == "AlreadyInstalled":
            print(f"[+] {kb} is already installed according to WUSA.")
        else:
            print(f"[!] {kb} install reported status '{status}' (exit code {exit_code}).")

        install_operations.append(
            {
                "kb": kb,
                "local_path": local_path,
                "package_type": package_type,
                "install_tool": install_tool,
                "status": status,
                "exit_code": exit_code,
                "reason": reason,
                "timestamp": timestamp,
                "stdout": stdout,
                "stderr": stderr,
            }
        )

    install_summary = {
        "baseline": baseline,
        "install_operations": install_operations,
    }

    with open(INSTALL_RESULT_PATH, "w", encoding="utf-8") as handle:
        json.dump(install_summary, handle, indent=2)

    print(f"\n[+] Install results saved to {INSTALL_RESULT_PATH}")
    print("[*] Installation stage complete.")
    print("    Next steps:")
    print("      1) Run winshield_scanner.py again (via WinShield Master option 1).")
    print("      2) Run winshield_verifier.py to compare before/after state.")


if __name__ == "__main__":
    main()

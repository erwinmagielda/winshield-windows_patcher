"""
WinShield Master

Operator entry point for the WinShield workflow.
Provides a simple menu to run scan, download, and install stages.
"""

import os
import subprocess
import sys
from typing import Dict, Tuple


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(SCRIPT_DIR)

PYTHON_EXE = sys.executable


STAGES: Dict[str, Tuple[str, str]] = {
    "1": ("Scan System", os.path.join(SCRIPT_DIR, "winshield_scanner.py")),
    "2": ("Download KB", os.path.join(SCRIPT_DIR, "winshield_downloader.py")),
    "3": ("Install KB", os.path.join(SCRIPT_DIR, "winshield_installer.py")),
}


def run_stage(label: str, path: str) -> int:
    """Run a single WinShield stage as a subprocess."""

    if not os.path.isfile(path):
        print(f"[X] Stage script not found: {path}")
        return 1

    print()
    print(f"[*] {label}")
    print("=" * 60)

    try:
        completed = subprocess.run(
            [PYTHON_EXE, path],
            cwd=ROOT_DIR,
            check=False,
        )
        rc = int(completed.returncode or 0)
    except KeyboardInterrupt:
        print("\n[!] Cancelled by user.")
        return 130
    except Exception as exc:
        print(f"[X] Failed to launch stage: {exc}")
        return 1

    print("=" * 60)
    status = "Finished" if rc == 0 else f"Finished (exit code {rc})"
    print(f"[+] {status}")
    print()

    return rc


def print_menu() -> None:
    print("=" * 43)
    print("                 WinShield")
    print("=" * 43)
    print("1) Scan system")
    print("2) Download update")
    print("3) Install update")
    print("4) Exit")
    print()


def read_choice() -> str:
    while True:
        try:
            choice = input("Select an option: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n[!] Cancelled by user.")
            return "4"

        if choice:
            return choice


def main() -> int:
    while True:
        print_menu()
        choice = read_choice()

        if choice == "4":
            print("Exiting WinShield.")
            return 0

        if choice in STAGES:
            label, path = STAGES[choice]
            run_stage(label, path)
            continue

        print("[!] Invalid selection.\n")


if __name__ == "__main__":
    raise SystemExit(main())

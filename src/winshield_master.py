"""
WinShield Master Orchestrator

This script provides a unified menu for:
  1) Running a new scan
  2) Downloading missing KBs
  3) Installing downloaded KBs
  4) Verifying post-install results
  5) Exiting

It does not modify or import other WinShield modules.
It simply executes them in order using subprocess.
"""

import os
import subprocess
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

PYTHON = sys.executable

MODULE_SCANNER = os.path.join(SCRIPT_DIR, "winshield_scanner.py")
MODULE_DOWNLOADER = os.path.join(SCRIPT_DIR, "winshield_downloader.py")
MODULE_INSTALLER = os.path.join(SCRIPT_DIR, "winshield_installer.py")
MODULE_VERIFIER = os.path.join(SCRIPT_DIR, "winshield_verifier.py")


def run_module(module_path: str):
    """Run another Python script in a blocking subprocess."""
    if not os.path.isfile(module_path):
        print(f"[X] Module not found: {module_path}")
        return

    print(f"\n[*] Running {os.path.basename(module_path)} ...")
    print("=====================================================")

    try:
        subprocess.run([PYTHON, module_path], check=False)
    except KeyboardInterrupt:
        print("\n[!] Operation cancelled by user.")
    except Exception as exc:
        print(f"[!] Failed to run {module_path}: {exc}")

    print("=====================================================\n")


def main():
    while True:
        print("""
===========================================
                 WinShield
===========================================

1) Run Scan
2) Download KBs
3) Install KBs
4) Verify Install
5) Exit

===========================================
""")

        choice = input("Select an option (1-5): ").strip()

        if choice == "1":
            run_module(MODULE_SCANNER)

        elif choice == "2":
            run_module(MODULE_DOWNLOADER)

        elif choice == "3":
            run_module(MODULE_INSTALLER)

        elif choice == "4":
            run_module(MODULE_VERIFIER)

        elif choice == "5":
            print("Exiting WinShield...")
            return

        else:
            print("[!] Invalid selection. Choose 1-5.\n")


if __name__ == "__main__":
    main()

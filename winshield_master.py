# WinShield_Master.py
"""
WinShield Master Orchestrator (Python Edition)

- Auto run Controller to verify environment
- Let user choose:
    1) Run new Scanner session
    2) Use existing scan snapshot
- Pass selected snapshot to WinShield_Manager.py

WinShield_Manager will later handle:
- verification against fresh scans
- view missing or installed KBs
- patch operations by table ID
"""

import json
import os
import subprocess
import sys
from typing import Any, Dict, List, Optional

try:
    from rich.console import Console

    console = Console()
    RICH_AVAILABLE = True
except Exception:
    RICH_AVAILABLE = False

    class DummyConsole:
        def print(self, *args, **kwargs):
            text = " ".join(str(a) for a in args)
            print(text)

    console = DummyConsole()


def Info(msg: str) -> None:
    if RICH_AVAILABLE:
        console.print(f"[*] {msg}", style="cyan")
    else:
        console.print(f"[*] {msg}")


def Good(msg: str) -> None:
    if RICH_AVAILABLE:
        console.print(f"[+] {msg}", style="green")
    else:
        console.print(f"[+] {msg}")


def Warn(msg: str) -> None:
    if RICH_AVAILABLE:
        console.print(f"[!] {msg}", style="yellow")
    else:
        console.print(f"[!] {msg}")


def Fail(msg: str) -> None:
    if RICH_AVAILABLE:
        console.print(f"[X] {msg}", style="red")
    else:
        console.print(f"[X] {msg}")
    sys.exit(1)


def Ask_Choice(prompt: str, choices: List[str]) -> int:
    """
    Simple numeric choice helper.
    Returns index (1 based) chosen by user.
    """
    while True:
        if RICH_AVAILABLE:
            console.print(prompt, style="cyan")
        else:
            print(prompt)
        for idx, label in enumerate(choices, start=1):
            print(f"  {idx}) {label}")
        ans = input("> ").strip()
        if not ans:
            continue
        if ans.isdigit():
            val = int(ans)
            if 1 <= val <= len(choices):
                return val
        Warn("Please enter a valid option number.")


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONTROLLER_PATH = os.path.join(SCRIPT_DIR, "WinShield_Controller.py")
SCANNER_PATH = os.path.join(SCRIPT_DIR, "WinShield_Scanner.py")
MANAGER_PATH = os.path.join(SCRIPT_DIR, "WinShield_Manager.py")

CONTROLLER_JSON = os.path.join(SCRIPT_DIR, "controller_results.json")
SCANNER_RESULTS_JSON = os.path.join(SCRIPT_DIR, "scanner_results.json")
SCANS_DIR = os.path.join(SCRIPT_DIR, "scans")


def run_python_script(path: str, args: Optional[List[str]] = None) -> int:
    if args is None:
        args = []
    try:
        proc = subprocess.run([sys.executable, path] + args)
        return proc.returncode
    except Exception as exc:
        Fail(f"Failed to run {os.path.basename(path)}: {exc!r}")
        return 1


def load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8-sig") as fh:
        return json.load(fh)


def select_snapshot_file() -> Optional[str]:
    """
    Let user select an existing scan snapshot by ID.
    Returns the selected file path, or None if there are no snapshots.
    """
    if not os.path.isdir(SCANS_DIR):
        Warn("No scans directory found, there are no saved snapshots.")
        return None

    files = [
        f for f in os.listdir(SCANS_DIR)
        if f.lower().endswith(".json") and f.startswith("scan_")
    ]
    if not files:
        Warn("No scan snapshots found.")
        return None

    # sort by mtime descending (latest first)
    files_sorted = sorted(
        files,
        key=lambda f: os.path.getmtime(os.path.join(SCANS_DIR, f)),
        reverse=True,
    )

    entries: List[Dict[str, Any]] = []
    for fname in files_sorted:
        path = os.path.join(SCANS_DIR, fname)
        try:
            data = load_json(path)
            summary = data.get("summary", {})
            system_tag = data.get("system_tag", "unknown")
            scan_date = data.get("scan_date", "unknown date")
            missing = summary.get("missing_kbs_count", "n/a")
            entries.append(
                {
                    "path": path,
                    "file": fname,
                    "system_tag": system_tag,
                    "scan_date": scan_date,
                    "missing": missing,
                }
            )
        except Exception:
            # skip corrupt or incompatible files
            continue

    if not entries:
        Warn("No valid scan snapshots could be loaded.")
        return None

    if RICH_AVAILABLE:
        console.print("Available scan snapshots:", style="bold magenta")
    else:
        print("Available scan snapshots:")

    for idx, e in enumerate(entries, start=1):
        print(
            f"{idx}) {e['file']}  "
            f"[system={e['system_tag']}, date={e['scan_date']}, missing={e['missing']}]"
        )

    while True:
        ans = input("Select snapshot by ID (or blank to cancel): ").strip()
        if not ans:
            return None
        if ans.isdigit():
            val = int(ans)
            if 1 <= val <= len(entries):
                return entries[val - 1]["path"]
        Warn("Please enter a valid snapshot ID.")


def main() -> None:
    if os.name == "nt":
        os.system("cls")
    else:
        os.system("clear")

    if RICH_AVAILABLE:
        console.print("=== WinShield Master Orchestrator ===", style="bold cyan")
    else:
        print("=== WinShield Master Orchestrator ===")
    print()

    # 1) Auto run Controller
    if not os.path.isfile(CONTROLLER_PATH):
        Fail(f"Controller not found: {CONTROLLER_PATH}")

    Info("Running environment controller...")
    rc = run_python_script(CONTROLLER_PATH)
    if rc != 0:
        Warn(f"Controller exited with code {rc} (see above for details).")

    if not os.path.isfile(CONTROLLER_JSON):
        Fail("Controller did not write controller_results.json, cannot continue.")

    try:
        controller_data = load_json(CONTROLLER_JSON)
    except Exception as exc:
        Fail(f"Could not parse controller_results.json: {exc!r}")

    if not controller_data.get("ready", False):
        errors = controller_data.get("errors") or []
        print()
        Warn("Environment check FAILED:")
        for e in errors:
            Warn(f" - {e}")
        Fail("Cannot proceed further.")

    Good("Controller reports environment is ready.")

    # 2) Choose scan source
    print()
    choice = Ask_Choice(
        "Select scan mode:",
        [
            "Run new scan now",
            "Use existing scan snapshot",
            "Exit",
        ],
    )

    snapshot_path: Optional[str] = None

    if choice == 3:
        Fail("User exited.")

    if choice == 1:
        # Run new scanner
        if not os.path.isfile(SCANNER_PATH):
            Fail(f"Scanner file missing: {SCANNER_PATH}")

        Info("Launching WinShield Scanner...")
        rc = run_python_script(SCANNER_PATH)
        if rc != 0:
            Warn(f"Scanner exited with code {rc} (see above for details).")

        if not os.path.isfile(SCANNER_RESULTS_JSON):
            Fail("Scanner did not produce scanner_results.json, cannot continue.")

        try:
            scan = load_json(SCANNER_RESULTS_JSON)
        except Exception as exc:
            Fail(f"scanner_results.json could not be parsed: {exc!r}")

        snapshot_path = scan.get("snapshot_file")
        if not snapshot_path or not os.path.isfile(snapshot_path):
            Warn("Snapshot file from scanner not found, falling back to scanner_results.json.")
            snapshot_path = SCANNER_RESULTS_JSON

    elif choice == 2:
        snapshot_path = select_snapshot_file()
        if not snapshot_path:
            Fail("No snapshot selected, cannot continue.")

    # 3) Launch Manager with selected snapshot
    if not os.path.isfile(MANAGER_PATH):
        Warn("Manager file (WinShield_Manager.py) not found, nothing more to do.")
        Good("WinShield Master complete.")
        return

    Info(f"Launching WinShield Manager with snapshot: {snapshot_path}")
    rc = run_python_script(MANAGER_PATH, [snapshot_path])
    if rc != 0:
        Warn(f"Manager exited with code {rc} (see above for details).")

    print()
    Good("WinShield Master complete.")


if __name__ == "__main__":
    main()

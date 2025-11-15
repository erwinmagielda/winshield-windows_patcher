# WinShield_Master.py
"""
WinShield Master Orchestrator (Python Edition)

- User-facing entry point
- Runs the Controller
- Checks controller_results.json
- If environment is OK → runs Scanner
- If not → exits with reason

Designed to mirror the original PowerShell master logic, but using Python
and the Rich library for consistent color output with the Scanner.
"""

import json
import os
import subprocess
import sys
from typing import Any, Dict

# ============================================================
# Rich console setup (with graceful fallback)
# ============================================================

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


def Ask_YesNo(prompt: str) -> bool:
    while True:
        if RICH_AVAILABLE:
            console.print(f"{prompt} (Y/N)", style="cyan")
            ans = input("> ").strip()
        else:
            ans = input(f"{prompt} (Y/N): ").strip()
        if not ans:
            continue
        ans_u = ans.upper()
        if ans_u == "Y":
            return True
        if ans_u == "N":
            return False
        Warn("Please enter Y or N.")


# ============================================================
# Paths / helper
# ============================================================

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONTROLLER_PATH = os.path.join(SCRIPT_DIR, "WinShield_Controller.py")
SCANNER_PATH = os.path.join(SCRIPT_DIR, "WinShield_Scanner.py")
CONTROLLER_JSON = os.path.join(SCRIPT_DIR, "controller_results.json")
SCANNER_RESULTS_JSON = os.path.join(SCRIPT_DIR, "scanner_results.json")


def run_python_script(path: str) -> int:
    """
    Run another Python script (controller/scanner) via the same interpreter.
    Returns the process return code.
    """
    try:
        proc = subprocess.run([sys.executable, path])
        return proc.returncode
    except Exception as exc:
        Fail(f"Failed to run {os.path.basename(path)}: {exc!r}")
        return 1  # never reached


# ============================================================
# Main
# ============================================================

def main() -> None:
    # Clear-ish screen (optional, similar to Clear-Host)
    if os.name == "nt":
        os.system("cls")
    else:
        os.system("clear")

    if RICH_AVAILABLE:
        console.print("=== WinShield Master Orchestrator ===", style="bold cyan")
    else:
        print("=== WinShield Master Orchestrator ===")
    print()

    # ----------------------------------------------------------
    # 1. Ask whether to run the Controller
    # ----------------------------------------------------------

    if not Ask_YesNo("Run environment controller now?"):
        Fail("User cancelled.")

    # ----------------------------------------------------------
    # 2. Run Controller
    # ----------------------------------------------------------

    if not os.path.isfile(CONTROLLER_PATH):
        Fail(f"Controller not found: {CONTROLLER_PATH}")

    Info("Running environment controller...")
    rc = run_python_script(CONTROLLER_PATH)
    if rc != 0:
        Warn(f"Controller process exited with code {rc} (check above for details).")

    # ----------------------------------------------------------
    # 3. Read controller results
    # ----------------------------------------------------------

    if not os.path.isfile(CONTROLLER_JSON):
        Fail("Controller did not write controller_results.json; cannot continue.")

    try:
        with open(CONTROLLER_JSON, "r", encoding="utf-8-sig") as fh:
            controller_data: Dict[str, Any] = json.load(fh)
    except Exception as exc:
        Fail(f"Could not parse controller_results.json: {exc!r}")

    # ----------------------------------------------------------
    # 4. Evaluate controller readiness
    # ----------------------------------------------------------

    ready = bool(controller_data.get("ready", False))
    if not ready:
        print()
        Fail("Environment check FAILED.")
        # (We could list errors here, but Fail() already exits.)

    # Print any reported errors/warnings if present
    errors = controller_data.get("errors") or []
    if errors:
        Warn("Controller reported non-fatal errors:")
        for e in errors:
            Warn(f" - {e}")

    Good("Controller reports environment is ready.")

    # ----------------------------------------------------------
    # 5. Run Scanner
    # ----------------------------------------------------------

    if not os.path.isfile(SCANNER_PATH):
        Fail(f"Scanner file missing: {SCANNER_PATH}")

    Info("Launching WinShield Scanner...")
    rc = run_python_script(SCANNER_PATH)
    if rc != 0:
        Warn(f"Scanner process exited with code {rc} (check above for details).")

    # ----------------------------------------------------------
    # 6. Read scanner results (best-effort summary)
    # ----------------------------------------------------------

    if os.path.isfile(SCANNER_RESULTS_JSON):
        try:
            with open(SCANNER_RESULTS_JSON, "r", encoding="utf-8-sig") as fh:
                scan = json.load(fh)
        except Exception as exc:
            Warn(f"Scanner produced scanner_results.json but it could not be parsed: {exc!r}")
        else:
            Good("Scan completed. Results saved to scanner_results.json.")

            # The current Scanner schema does not have 'bulletin_month' or 'missing_cves_count'
            # so we derive a small summary that actually works with your scanner.
            scan_date = scan.get("scan_date", "unknown date")
            missing_kbs = scan.get("missing_kbs", []) or []
            kb_details = scan.get("kb_details", []) or []

            # Count missing KBs
            missing_kb_count = len(missing_kbs)

            # Count CVEs associated with missing KBs
            missing_cves = set()
            for kb in kb_details:
                if kb.get("status") == "Missing":
                    for cve in kb.get("cves") or []:
                        missing_cves.add(cve)
            missing_cves_count = len(missing_cves)

            Info(f"Scan date: {scan_date}")
            Info(f"Missing KBs (from catalog query): {missing_kb_count}")
            Info(f"Unique CVEs in missing KBs: {missing_cves_count}")
    else:
        Warn("Scanner did not produce scanner_results.json (older version or error?)")

    print()
    Good("WinShield Master complete.")


if __name__ == "__main__":
    main()

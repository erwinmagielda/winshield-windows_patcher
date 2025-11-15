# WinShield_Controller.py
"""
WinShield_Controller (Python Edition)
- Detect OS name, version, build, bitness (using PowerShell, like the PS version)
- Detect PowerShell version
- Assume Python is present (we're already running in it)
- Ensure Python dependencies are installed (requests, rich, python-dateutil)
- Write controller_results.json in the same schema as the PowerShell controller

This is intentionally close in spirit to the original PowerShell logic.
"""

import json
import os
import platform
import subprocess
import sys
from typing import Any, Dict, List, Tuple

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


# ============================================================
# Paths / globals
# ============================================================

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
RESULT_FILE = os.path.join(SCRIPT_DIR, "controller_results.json")


# ============================================================
# OS + PowerShell detection (mirrors PS logic as closely as possible)
# ============================================================

def _run_powershell(ps_script: str, timeout: int = 30) -> Tuple[int, str, str]:
    try:
        proc = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                ps_script,
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except Exception as exc:
        return 1, "", f"Exception: {exc!r}"


def detect_os() -> Tuple[str, str, str, str]:
    """
    Use PowerShell Get-CimInstance/Win32_OperatingSystem like the original controller.
    Falls back to Python's platform module if that fails.
    Returns: (os_name, os_version, build, bitness)
    """
    ps_script = r"""
try {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
} catch {
    $os = Get-WmiObject Win32_OperatingSystem
}
$props = [PSCustomObject]@{
    Caption       = $os.Caption
    Version       = $os.Version
    BuildNumber   = $os.BuildNumber
    OSArchitecture = $os.OSArchitecture
}
$props | ConvertTo-Json -Depth 2
"""

    rc, out_text, err_text = _run_powershell(ps_script)
    if rc == 0 and out_text.strip():
        try:
            raw = out_text.strip().lstrip("\ufeff")
            data = json.loads(raw)
            os_name = str(data.get("Caption", "")).strip() or "Windows"
            os_version = str(data.get("Version", "")).strip() or ""
            build = str(data.get("BuildNumber", "")).strip() or ""
            bitness = str(data.get("OSArchitecture", "")).strip()

            # Normalise bitness if needed
            if not bitness:
                bitness = "64-bit" if sys.maxsize > 2**32 else "32-bit"

            Good(f"Detected: {os_name} ({os_version}) Build {build} [{bitness}]")
            return os_name, os_version, build, bitness
        except Exception as exc:
            Warn(f"PowerShell OS JSON parse failed: {exc!r}")

    Warn("PowerShell OS detection failed, falling back to Python platform().")

    os_name = f"Microsoft {platform.system()}"
    os_version = platform.version()
    build = ""
    bitness = "64-bit" if sys.maxsize > 2**32 else "32-bit"

    Good(f"Detected: {os_name} ({os_version}) Build {build} [{bitness}]")
    return os_name, os_version, build, bitness


def detect_powershell_version() -> int:
    """
    Try to detect major PowerShell version via $PSVersionTable.PSVersion.Major.
    If detection fails, return 0 (unknown).
    """
    ps_script = r"$PSVersionTable.PSVersion.Major"
    rc, out_text, err_text = _run_powershell(ps_script)
    if rc == 0 and out_text.strip():
        try:
            version = int(out_text.strip().splitlines()[-1])
            Good(f"PowerShell version: {version}")
            return version
        except Exception:
            Warn("Could not parse PowerShell version, defaulting to 0.")
            return 0
    else:
        Warn("PowerShell version detection failed, defaulting to 0.")
        return 0


# ============================================================
# Dependency handling
# ============================================================

def ensure_python_dependencies(errors: List[str]) -> bool:
    """
    Ensure required Python modules are installed.
    - requests
    - rich
    - python-dateutil (imported as 'dateutil')

    Uses 'python -m pip install ...' logic similar to the PS controller's pip calls.
    """
    modules = [
        ("requests", "requests"),
        ("rich", "rich"),
        ("python-dateutil", "dateutil"),
    ]

    deps_ok = True

    for pip_name, import_name in modules:
        try:
            __import__(import_name)
            Good(f"Python module '{pip_name}' already present.")
        except ImportError:
            Info(f"Installing Python module '{pip_name}'...")
            try:
                proc = subprocess.run(
                    [sys.executable, "-m", "pip", "install", pip_name],
                    capture_output=True,
                    text=True,
                )
                if proc.returncode != 0:
                    errors.append(
                        f"Python dependency '{pip_name}' failed to install. "
                        f"pip exit code {proc.returncode}."
                    )
                    Warn(f"pip install '{pip_name}' failed.")
                    deps_ok = False
                else:
                    Good(f"Python dependency '{pip_name}' installed.")
            except Exception as exc:
                errors.append(
                    f"Python dependency '{pip_name}' installation threw exception: {exc!r}"
                )
                Warn(f"Exception while installing '{pip_name}': {exc!r}")
                deps_ok = False

    return deps_ok


# ============================================================
# Main
# ============================================================

def main() -> None:
    errors: List[str] = []

    Info("WinShield Controller (Python) starting...")

    # 1) OS Detection
    os_name, os_version, build, bitness = detect_os()

    # 2) PowerShell version
    ps_version = detect_powershell_version()

    # 3) Python detection (we are already running in Python)
    python_ok = True
    Good("Python status: OK")

    # 4) Python dependencies
    Info("Checking Python modules...")
    deps_ok = ensure_python_dependencies(errors)

    # 5) Final readiness decision
    ready = True
    if not python_ok:
        ready = False
    if not deps_ok:
        ready = False
    if errors:
        ready = False

    # 6) Write controller_results.json (same schema as PS)
    payload: Dict[str, Any] = {
        "ready": ready,
        "errors": errors,
        "os_name": os_name,
        "os_version": os_version,
        "build": build,
        "bitness": bitness,
        "powershell_version": ps_version,
        "python_ok": python_ok,
        "deps_ok": deps_ok,
    }

    try:
        with open(RESULT_FILE, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, ensure_ascii=False)
        Info(f"Controller results written to {RESULT_FILE}")
    except Exception as exc:
        Fail(f"Failed to write controller_results.json: {exc!r}")

    if ready:
        Good("Environment ready. Controller completed.")
    else:
        Fail("Environment not ready. Controller completed with errors.")


if __name__ == "__main__":
    main()

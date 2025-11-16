# WinShield_Controller.py
"""
WinShield_Controller (Python Edition)

- Detect OS name, version, build, bitness (via PowerShell, like the PS controller)
- Detect PowerShell version
- Assume Python is present (we are already running in it)
- Ensure Python dependencies are installed (requests, rich, python-dateutil)
- Write controller_results.json in the same schema as before

controller_results.json is always overwritten: it represents the current environment only.
"""

import json
import os
import platform
import subprocess
import sys
from typing import Any, Dict, List, Tuple

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


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
RESULT_FILE = os.path.join(SCRIPT_DIR, "controller_results.json")


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
    Fall back to Python platform() if that fails.
    Returns: (os_name, os_version, build, bitness)
    """
    ps_script = r"""
try {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
} catch {
    $os = Get-WmiObject Win32_OperatingSystem
}
$props = [PSCustomObject]@{
    Caption        = $os.Caption
    Version        = $os.Version
    BuildNumber    = $os.BuildNumber
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
            if not bitness:
                bitness = "64-bit" if sys.maxsize > 2**32 else "32-bit"
            Good(f"OS: {os_name} ({os_version}) Build {build} [{bitness}]")
            return os_name, os_version, build, bitness
        except Exception as exc:
            Warn(f"PowerShell OS JSON parse failed: {exc!r}")

    Warn("PowerShell OS detection failed, falling back to Python platform().")
    os_name = f"Microsoft {platform.system()}"
    os_version = platform.version()
    build = ""
    bitness = "64-bit" if sys.maxsize > 2**32 else "32-bit"
    Good(f"OS: {os_name} ({os_version}) Build {build} [{bitness}]")
    return os_name, os_version, build, bitness


def detect_powershell_version() -> int:
    ps_script = r"$PSVersionTable.PSVersion.Major"
    rc, out_text, err_text = _run_powershell(ps_script)
    if rc == 0 and out_text.strip():
        try:
            version = int(out_text.strip().splitlines()[-1])
            Good(f"PowerShell: {version}")
            return version
        except Exception:
            Warn("Could not parse PowerShell version, defaulting to 0.")
    else:
        Warn("PowerShell version detection failed, defaulting to 0.")
    return 0


def ensure_python_dependencies(errors: List[str]) -> bool:
    modules = [
        ("requests", "requests"),
        ("rich", "rich"),
        ("python-dateutil", "dateutil"),
    ]
    deps_ok = True
    python_version = sys.version.split()[0]
    Good(f"Python: {python_version}")

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
                        f"Python dependency '{pip_name}' failed to install "
                        f"(pip exit code {proc.returncode})."
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


def main() -> None:
    errors: List[str] = []
    Info("WinShield Controller (Python) starting...")

    os_name, os_version, build, bitness = detect_os()
    ps_version = detect_powershell_version()

    python_ok = True  # we are in Python already

    Info("Checking Python modules...")
    deps_ok = ensure_python_dependencies(errors)

    ready = True
    if not python_ok or not deps_ok or errors:
        ready = False

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

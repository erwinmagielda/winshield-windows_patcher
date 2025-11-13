"""
WinShield - Windows KB-based Vulnerability Scanner (Catalog Edition)

New approach:
    - Use Microsoft Update Catalog as the source of truth for available KBs
    - Enumerate installed KBs locally (Get-HotFix, etc.)
    - Search the Catalog for updates that match this OS + bitness
    - Any catalog KB missing locally is treated as a missing patch

This version does NOT rely on MSRC CVRF -> KB mappings
(because modern CVRF bulletins often contain no KB-based Vendor Fix entries).
"""

# ----------------------------
# Standard library imports
# ----------------------------
import json
import os
import re
import subprocess
import sys
from datetime import datetime
from typing import Optional, Set, List, Dict, Tuple

import platform  # OS information for context

# ----------------------------
# Third-party imports
# ----------------------------
import requests
from rich.console import Console
from rich.table import Table

# ============================================================
# Configuration
# ============================================================

POWERSHELL_TIMEOUT_SHORT = 30
POWERSHELL_TIMEOUT_LONG = 90
SYSTEMINFO_TIMEOUT = 60

# Log file name for tee logging
LOG_FILE_NAME = f"winshield_catalog_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

# Microsoft Update Catalog base URL
CATALOG_SEARCH_URL = "https://www.catalog.update.microsoft.com/Search.aspx"

# ============================================================
# Logging tee
# ============================================================


class TeeStream:
    """
    Simple tee for stdout and stderr.
    Whatever is printed goes both to console and to the log file.
    """

    def __init__(self, *streams):
        self.streams = streams

    def write(self, data: str) -> None:
        for s in self.streams:
            s.write(data)

    def flush(self) -> None:
        for s in self.streams:
            s.flush()


# Set up logging early so everything is captured
_log_file_handle = open(LOG_FILE_NAME, "w", encoding="utf-8")
sys.stdout = TeeStream(sys.__stdout__, _log_file_handle)
sys.stderr = TeeStream(sys.__stderr__, _log_file_handle)

# Use real stdout for color support, force terminal mode so colors always show
console = Console(file=sys.__stdout__, force_terminal=True)


# ============================================================
# Helper utilities
# ============================================================

def run_powershell(ps_command: str, timeout_seconds: int = POWERSHELL_TIMEOUT_SHORT) -> Tuple[int, str, str]:
    """
    Run a PowerShell command in a safe way.

    Returns:
        (exit_code, stdout, stderr)
    """
    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_command],
            capture_output=True,
            text=True,
            timeout=timeout_seconds
        )
        return proc.returncode, proc.stdout, proc.stderr
    except Exception as exc:
        return 1, "", f"Exception: {exc!r}"


def extract_kb_number(text: str) -> Optional[str]:
    """
    Pull numeric KB identifier out of text.

    Examples:
        'KB5048667'              -> '5048667'
        'Install KB5048667 now'  -> '5048667'
    """
    if not text:
        return None
    match = re.search(r"KB(\d{6,8})", text, re.IGNORECASE)
    return match.group(1) if match else None


def get_windows_os_bitness() -> str:
    """
    Returns '32-bit' or '64-bit' for the actual Windows OS
    (not just Python interpreter architecture).
    """
    # --- Primary: WMIC ---
    try:
        proc = subprocess.run(
            ["wmic", "os", "get", "osarchitecture"],
            capture_output=True,
            text=True,
            timeout=POWERSHELL_TIMEOUT_SHORT
        )
        output = proc.stdout.strip().splitlines()
        if len(output) >= 2:
            arch_line = output[1].strip()
            if "64" in arch_line:
                return "64-bit"
            if "32" in arch_line:
                return "32-bit"
    except Exception:
        pass

    # Fallback: environment-based detection
    arch = os.environ.get("PROCESSOR_ARCHITECTURE", "").upper()
    arch_wow = os.environ.get("PROCESSOR_ARCHITEW6432", "").upper()

    if arch == "X86" and arch_wow:
        return "64-bit"
    if arch in ("AMD64", "ARM64"):
        return "64-bit"
    return "32-bit"


def load_controller_environment() -> Dict:
    """
    Try to load controller_results.json written by WinShield_Controller.

    Returns:
        dict with keys like os_name, os_version, build, bitness, etc.
        If file is missing or broken, returns {} and we fall back to platform().
    """
    controller_path = os.path.join(os.path.dirname(__file__), "controller_results.json")
    if not os.path.exists(controller_path):
        console.print("[yellow]No controller_results.json found - falling back to local OS detection.[/yellow]")
        return {}

    try:
        with open(controller_path, "r", encoding="utf-8-sig") as fh:
            data = json.load(fh)
        console.print(f"[dim][DEBUG] Loaded controller env: {data}[/dim]")
        return data
    except Exception as exc:
        console.print(f"[red]Failed to load controller_results.json: {exc}[/red]")
        return {}


# ============================================================
# Stage 1 - Installed KB discovery
# ============================================================

def get_installed_kbs() -> Tuple[Set[str], str]:
    """
    Enumerate installed KBs as numeric strings without the 'KB' prefix.

    Try several mechanisms:
        1) PowerShell Get-HotFix
        2) WMIC QFE
        3) systeminfo

    First one that returns any KBs wins.

    Returns:
        (set_of_kb_numbers, source_name)
    """
    console.print("[*] Enumerating installed patches...")

    # --- Attempt 1: Get-HotFix ---
    ps_get_hotfix = r"""
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$items = Get-HotFix | Select-Object HotFixID, InstalledOn
$items | ConvertTo-Json -Depth 3
"""
    exit_code, stdout_text, stderr_text = run_powershell(ps_get_hotfix)

    if exit_code == 0 and stdout_text.strip():
        # Clean weird UTF-16 noise if any
        raw_json = stdout_text.replace("\x00", "").lstrip("\ufeff").strip()
        try:
            parsed = json.loads(raw_json)
            if isinstance(parsed, dict):
                parsed = [parsed]
            kb_numbers: Set[str] = set()
            for item in parsed:
                kb_numeric = extract_kb_number(str(item.get("HotFixID", "")))
                if kb_numeric:
                    kb_numbers.add(kb_numeric)
            if kb_numbers:
                console.print(f"[+] Found {len(kb_numbers)} KBs via Get-HotFix")
                return kb_numbers, "Get-HotFix"
            else:
                console.print("[!] Get-HotFix returned JSON but no KB entries")
        except json.JSONDecodeError:
            console.print("[!] Get-HotFix did not return valid JSON")
    else:
        if stderr_text.strip():
            console.print(f"[!] PowerShell Get-HotFix error: {stderr_text.strip()}")

    # --- Attempt 2: WMIC QFE ---
    try:
        wmic_proc = subprocess.run(
            ["wmic", "qfe", "get", "HotFixID,InstalledOn", "/format:csv"],
            capture_output=True,
            text=True,
            timeout=POWERSHELL_TIMEOUT_SHORT
        )
        if wmic_proc.returncode == 0 and wmic_proc.stdout:
            kb_numbers: Set[str] = set()
            for line in wmic_proc.stdout.splitlines():
                line = line.strip()
                if not line or line.startswith("Node"):
                    continue
                parts = [p.strip() for p in line.split(",")]
                if len(parts) >= 3 and parts[1].upper().startswith("KB"):
                    kb_numeric = extract_kb_number(parts[1])
                    if kb_numeric:
                        kb_numbers.add(kb_numeric)
            if kb_numbers:
                console.print(f"[+] Found {len(kb_numbers)} KBs via WMIC QFE")
                return kb_numbers, "WMIC QFE"
            else:
                console.print("[!] WMIC returned no KB entries")
        else:
            if wmic_proc.stderr.strip():
                console.print(f"[!] WMIC error: {wmic_proc.stderr.strip()}")
    except Exception as exc:
        console.print(f"[!] WMIC attempt failed: {exc!r}")

    # --- Attempt 3: systeminfo ---
    try:
        sysinfo_proc = subprocess.run(
            ["systeminfo"],
            capture_output=True,
            text=True,
            timeout=SYSTEMINFO_TIMEOUT
        )
        combined = (sysinfo_proc.stdout or "") + (sysinfo_proc.stderr or "")
        if combined:
            kb_numbers: Set[str] = set()
            for line in combined.splitlines():
                match = re.search(r"KB(\d{6,8})", line, re.IGNORECASE)
                if match:
                    kb_numbers.add(match.group(1))
            if kb_numbers:
                console.print(f"[+] Found {len(kb_numbers)} KBs via systeminfo")
                return kb_numbers, "systeminfo"
            else:
                console.print("[!] systeminfo listed no KBs")
    except Exception as exc:
        console.print(f"[!] systeminfo attempt failed: {exc!r}")

    console.print("[!] Could not enumerate installed KBs on this system")
    return set(), "None"


# ============================================================
# Stage 2 - Microsoft Update Catalog discovery
# ============================================================

def build_catalog_query(os_name: str, bitness: str) -> str:
    """
    Build a reasonable search string for Microsoft Update Catalog.

    Examples:
        'Windows 11' + '64-bit' -> 'Windows 11 for x64-based Systems'
        'Windows 10' + '32-bit' -> 'Windows 10 for x86-based Systems'
    """
    os_name_simple = os_name.replace("Microsoft ", "").strip()

    if "11" in os_name_simple:
        if "64" in bitness:
            return f"{os_name_simple} for x64-based Systems"
        else:
            return f"{os_name_simple} for x86-based Systems"

    if "10" in os_name_simple:
        if "64" in bitness:
            return f"{os_name_simple} for x64-based Systems"
        else:
            return f"{os_name_simple} for x86-based Systems"

    # Fallback generic
    return os_name_simple


def discover_kbs_from_catalog(os_name: str, bitness: str, max_kbs: int = 500) -> Set[str]:
    """
    Query Microsoft Update Catalog and extract KB numbers from the HTML.

    This is a best-effort, HTML-scraping based approach:
        - We hit Search.aspx?q=<query>
        - We grep for 'KB1234567' style patterns in the returned HTML
        - We keep KBs whose surrounding text looks like it belongs to this OS/bitness

    Returns:
        Set of KB numeric strings.
    """
    search_query = build_catalog_query(os_name, bitness)
    console.print(f"[*] Querying Microsoft Update Catalog for: '{search_query}'")

    try:
        response = requests.get(
            CATALOG_SEARCH_URL,
            params={"q": search_query},
            timeout=POWERSHELL_TIMEOUT_LONG,
        )
    except Exception as exc:
        console.print(f"[red]Error contacting Update Catalog: {exc!r}[/red]")
        return set()

    if response.status_code != 200:
        console.print(f"[red]Update Catalog returned HTTP {response.status_code}[/red]")
        return set()

    html = response.text
    # Rough cut: find all KB-like tokens
    kb_matches = re.findall(r"KB(\d{6,8})", html, re.IGNORECASE)
    kb_set: Set[str] = set(kb_matches)

    # Optional: filter by lines mentioning our OS name / architecture
    filtered_kbs: Set[str] = set()
    if kb_set:
        os_name_lower = os_name.lower()
        bitness_token = "x64" if "64" in bitness else "x86"

        # For each KB, find context snippet and see if OS/arch words appear nearby
        for kb in kb_set:
            pattern = re.compile(rf".{{0,80}}KB{kb}.{{0,80}}", re.IGNORECASE | re.DOTALL)
            for match in pattern.finditer(html):
                snippet = match.group(0).lower()
                if os_name_lower.split()[-1] in snippet or "windows" in snippet:
                    if bitness_token in snippet or "for arm64" in snippet or "for x64" in snippet or "for x86" in snippet:
                        filtered_kbs.add(kb)
                        break

    chosen = filtered_kbs if filtered_kbs else kb_set
    if chosen:
        # Trim to max_kbs to avoid huge sets on very old / very broad queries
        trimmed = set(list(chosen)[:max_kbs])
        console.print(f"[+] Discovered {len(trimmed)} catalog KBs for this OS/bitness (before diff)")
        return trimmed

    console.print("[!] No KBs discovered from Update Catalog search")
    return set()


# ============================================================
# Stage 3 - Compare installed vs catalog
# ============================================================

def find_missing_kbs(installed_kbs: Set[str], catalog_kbs: Set[str]) -> Set[str]:
    """
    Any KB that exists in the catalog set but not in installed set is treated as missing.
    """
    if not catalog_kbs:
        return set()
    if not installed_kbs:
        # System appears to have no patches; treat all catalog KBs as missing
        return set(catalog_kbs)
    return catalog_kbs - installed_kbs


# ============================================================
# Output / reporting
# ============================================================

def display_missing_kbs(missing_kbs: Set[str], installed_kbs: Set[str], os_name: str, os_bitness: str) -> None:
    """
    Show missing KBs in a Rich table.
    """
    if not missing_kbs:
        console.print("[bold green]No missing catalog KBs detected for this OS query.[/bold green]")
        console.print("[dim](Note: this does NOT mean the system is fully patched, only that our\
 catalog query did not find additional KBs to compare.)[/dim]")
        return

    console.print(f"\n[bold red]Found {len(missing_kbs)} catalog KBs not installed on this system[/bold red]")
    console.print(f"[dim]OS: {os_name} ({os_bitness}), Installed KBs: {len(installed_kbs)}[/dim]\n")

    table = Table(
        title="Missing KBs (from Microsoft Update Catalog query)",
        show_header=True,
        header_style="bold magenta"
    )
    table.add_column("KB", style="cyan", width=12)
    table.add_column("Status", style="yellow", width=20)
    table.add_column("Notes", style="white", width=60)

    for kb in sorted(missing_kbs):
        table.add_row(
            f"KB{kb}",
            "[red]Missing[/red]",
            "Listed in Update Catalog for this OS/bitness but not installed"
        )

    console.print(table)


# ============================================================
# Main orchestration
# ============================================================

def main() -> None:
    console.print("[bold cyan]WinShield - Windows Vulnerability Scanner (Catalog Edition)[/bold cyan]\n")

    # Prefer controller's OS info if available
    controller_env = load_controller_environment()
    if controller_env:
        os_name = controller_env.get("os_name") or controller_env.get("caption") or platform.system()
        os_version = controller_env.get("os_version") or controller_env.get("version") or ""
        build = controller_env.get("build") or ""
        bitness = controller_env.get("bitness") or get_windows_os_bitness()
    else:
        # Fallback: use local detection
        os_name = f"{platform.system()} {platform.release()}"
        os_version = platform.version()
        build = ""
        bitness = get_windows_os_bitness()

    console.print(f"[dim]OS detected: {os_name} (version {os_version}{', build ' + build if build else ''}, {bitness})[/dim]\n")

    # Stage 1: installed KBs
    installed_kbs, kb_source = get_installed_kbs()
    console.print(f"[dim]KB enumeration source: {kb_source}, count={len(installed_kbs)}[/dim]\n")

    # Stage 2: Catalog discovery
    catalog_kbs = discover_kbs_from_catalog(os_name, bitness)

    # Stage 3: diff
    missing_kbs = find_missing_kbs(installed_kbs, catalog_kbs)

    # Stage 4: display
    display_missing_kbs(missing_kbs, installed_kbs, os_name, bitness)

    # JSON report for Master / later hotfixer module
    report_payload: Dict = {
        "tool": "WinShield",
        "mode": "catalog_kb_diff",
        "scan_date": datetime.now().isoformat(),
        "os_info": {
            "name": os_name,
            "version": os_version,
            "build": build,
            "bitness": bitness,
        },
        "kb_enumeration_source": kb_source,
        "installed_kb_count": len(installed_kbs),
        "catalog_kb_count": len(catalog_kbs),
        "installed_kbs_sample": sorted(list(installed_kbs))[:50],
        "missing_kbs": sorted(list(missing_kbs)),
    }

    with open("scanner_results.json", "w", encoding="utf-8") as fh:
        json.dump(report_payload, fh, indent=2, ensure_ascii=False)

    console.print(f"\n[dim]Results saved to scanner_results.json[/dim]")
    console.print(f"[dim]Log saved to {LOG_FILE_NAME}[/dim]")


if __name__ == "__main__":
    try:
        main()
        input("\nPress Enter to exit...")
    finally:
        # Restore original stdout/stderr so shutdown does not try to flush TeeStream
        sys.stdout = sys.__stdout__
        sys.stderr = sys.__stderr__
        try:
            _log_file_handle.flush()
            _log_file_handle.close()
        except Exception:
            pass

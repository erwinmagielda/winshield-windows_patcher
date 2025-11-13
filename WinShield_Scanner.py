"""
WinShield - Windows Vulnerability Scanner

Purpose:
    - Enumerate installed KB updates on modern Windows (8.1+)
    - Retrieve latest MSRC monthly security bulletin
    - Parse CVEs + their KB fixes
    - Compare against installed KBs
    - Display missing patches in a rich, readable format
    - Save a detailed JSON report for the WinShield pipeline

This scanner contains NO legacy hacks or Win7 compatibility layers.
"""

# ----------------------------
# Standard library imports
# ----------------------------
import json
import re
import subprocess
import sys
import os
from datetime import datetime
from typing import Optional, Set, List, Dict, Tuple
import platform

# ----------------------------
# Third-party imports
# ----------------------------
import requests
from rich.console import Console
from rich.table import Table
from dateutil.relativedelta import relativedelta

# ============================================================
# Configuration
# ============================================================

POWERSHELL_TIMEOUT = 30
DISM_TIMEOUT = 90
MAX_MONTHS_BACK = 12

LOG_FILE = f"winshield_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

# Tee output to both console and a log file
class Tee:
    def __init__(self, *targets):
        self.targets = targets

    def write(self, data):
        for t in self.targets:
            t.write(data)

    def flush(self):
        for t in self.targets:
            t.flush()

_log = open(LOG_FILE, "w", encoding="utf-8")
sys.stdout = Tee(sys.__stdout__, _log)
sys.stderr = Tee(sys.__stderr__, _log)

console = Console(file=sys.__stdout__, force_terminal=True)

# ============================================================
# Helper functions
# ============================================================

def run_ps(command: str, timeout: int = POWERSHELL_TIMEOUT) -> Tuple[int, str, str]:
    """Run a PowerShell command and return (code, stdout, stderr)."""
    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return proc.returncode, proc.stdout, proc.stderr
    except Exception as e:
        return 1, "", str(e)

def extract_kb(text: str) -> Optional[str]:
    """Return numeric KB from text like 'KB5030211'."""
    m = re.search(r"KB(\d+)", text, re.IGNORECASE)
    return m.group(1) if m else None

# ============================================================
# KB enumeration (modern systems only)
# ============================================================

def get_installed_kbs() -> Tuple[Set[str], str]:
    """
    Modern KB enumeration using:
        1) Get-HotFix
        2) CIM Win32_QuickFixEngineering
        3) DISM
    """
    console.print("[*] Enumerating installed patches...")

    # --- 1) Get-HotFix ---
    ps_hotfix = r"""
$items = Get-HotFix | Select-Object HotFixID
$items | ConvertTo-Json -Depth 3
"""
    code, out, err = run_ps(ps_hotfix)
    if code == 0 and out.strip():
        try:
            parsed = json.loads(out)
            if isinstance(parsed, dict):
                parsed = [parsed]
            kbs = {
                extract_kb(item.get("HotFixID", ""))
                for item in parsed
                if extract_kb(item.get("HotFixID", "")) is not None
            }
            if kbs:
                console.print(f"[+] Found {len(kbs)} patches via Get-HotFix")
                return kbs, "Get-HotFix"
        except Exception:
            pass

    # --- 2) CIM (Win32_QuickFixEngineering) ---
    ps_cim = r"""
$items = Get-CimInstance Win32_QuickFixEngineering | Select-Object HotFixID
$items | ConvertTo-Json -Depth 3
"""
    code, out, err = run_ps(ps_cim)
    if code == 0 and out.strip():
        try:
            parsed = json.loads(out)
            if isinstance(parsed, dict):
                parsed = [parsed]
            kbs = {
                extract_kb(item.get("HotFixID", ""))
                for item in parsed
                if extract_kb(item.get("HotFixID", "")) is not None
            }
            if kbs:
                console.print(f"[+] Found {len(kbs)} patches via CIM")
                return kbs, "CIM Win32_QuickFixEngineering"
        except Exception:
            pass

    # --- 3) DISM fallback ---
    try:
        proc = subprocess.run(
            ["dism.exe", "/online", "/get-packages", "/english"],
            capture_output=True,
            text=True,
            timeout=DISM_TIMEOUT
        )
        alltext = (proc.stdout or "") + (proc.stderr or "")
        kbs = set(re.findall(r"KB(\d+)", alltext, flags=re.IGNORECASE))
        if kbs:
            console.print(f"[+] Found {len(kbs)} patches via DISM")
            return kbs, "DISM /online /get-packages"
    except Exception:
        pass

    console.print("[!] Failed to enumerate KBs on this system.")
    return set(), "None"

# ============================================================
# MSRC bulletin retrieval
# ============================================================

def get_msrc_bulletin(label: str) -> Optional[Dict]:
    url = f"https://api.msrc.microsoft.com/cvrf/v2.0/cvrf/{label}"
    console.print(f"[*] Querying MSRC API for {label}...")
    try:
        r = requests.get(url, headers={"Accept": "application/json"}, timeout=POWERSHELL_TIMEOUT)
        if r.status_code == 200:
            console.print(f"[+] Retrieved bulletin data for {label}")
            return r.json()
        return None
    except Exception:
        return None

def get_latest_bulletin() -> Tuple[Optional[str], Optional[Dict]]:
    now = datetime.now()
    for back in range(MAX_MONTHS_BACK + 1):
        label = (now - relativedelta(months=back)).strftime("%Y-%b")
        data = get_msrc_bulletin(label)
        if data:
            if back > 0:
                console.print(f"[*] Using previous bulletin: {label}")
            return label, data
    return None, None

# ============================================================
# Parse CVEs
# ============================================================

def parse_cves(data: Dict) -> List[Dict]:
    vulns = data.get("Vulnerability", []) or []
    parsed = []

    for v in vulns:
        cve = v.get("CVE", "N/A")
        title = v.get("Title", {}).get("Value", "N/A")

        severity = "Unknown"
        for t in v.get("Threats", []) or []:
            if t.get("Type") == 0:
                severity = t.get("Description", {}).get("Value", "Unknown")
                break

        kbs = []
        for r in v.get("Remediations", []) or []:
            if r.get("Type") == "Vendor Fix":
                kb = extract_kb(r.get("Description", {}).get("Value", ""))
                if kb:
                    kbs.append(kb)

        parsed.append({
            "cve_id": cve,
            "title": title,
            "severity": severity,
            "kb_numbers": kbs
        })

    console.print(f"[+] Parsed {len(parsed)} CVEs from bulletin")
    return parsed

# ============================================================
# Compare installed vs missing
# ============================================================

def find_missing(cves: List[Dict], installed: Set[str]) -> List[Dict]:
    """
    Decide which CVEs are missing on this host.

    Rules:
      - If we cannot enumerate any installed KBs at all (empty set),
        assume this is an offline or baseline image and treat
        Windows-related CVEs as missing even if KB mappings are absent.
      - If we DO have KBs, a CVE is missing only when none of its
        known KB fixes are installed.
    """

    # Case 1: no KBs enumerated at all → treat as unpatched baseline
    if not installed:
        missing = []
        for c in cves:
            title = (c.get("title") or "").lower()
            kb_list = c.get("kb_numbers") or []
            # If MSRC has KBs OR the title clearly refers to Windows,
            # consider it relevant and missing.
            if kb_list or "windows" in title:
                missing.append(c)
        return missing

    # Case 2: normal comparison against installed KBs
    missing = []
    for c in cves:
        needed = set(c.get("kb_numbers") or [])
        if needed and not (needed & installed):
            missing.append(c)
    return missing

# ============================================================
# Results display
# ============================================================

def show_results(missing: List[Dict]):
    if not missing:
        console.print("[bold green]No missing patches detected.[/bold green]")
        return

    table = Table(title="Missing Security Patches", header_style="bold magenta")
    table.add_column("CVE", style="cyan", width=18)
    table.add_column("Severity", width=16)
    table.add_column("KB", width=16)
    table.add_column("Title", width=60)

    severity_style = {
        "Critical": "bold red",
        "Important": "bold yellow",
        "Moderate": "bold blue",
        "Low": "dim"
    }

    for c in missing:
        sev = c.get("severity", "Unknown")
        style = severity_style.get(sev, "white")
        kb = ", ".join(c.get("kb_numbers") or []) or "N/A"
        title = c.get("title", "")[:60] + ("..." if len(c.get("title", "")) > 60 else "")

        table.add_row(
            c.get("cve_id", "N/A"),
            f"[{style}]{sev}[/{style}]",
            kb,
            title
        )

    console.print(table)

# ============================================================
# Main
# ============================================================

def main():
    console.print("[bold cyan]WinShield - Windows Vulnerability Scanner[/bold cyan]\n")

    # OS info
    console.print(f"[dim]{platform.system()} {platform.release()} detected[/dim]")

    # KB enumeration
    installed, source = get_installed_kbs()
    console.print(f"[dim]KB enumeration source: {source}[/dim]\n")

    # Bulletin
    month, data = get_latest_bulletin()
    if not data:
        console.print("[bold red]Could not retrieve MSRC bulletin. Exiting.[/bold red]")
        return

    # Parse
    cves = parse_cves(data)

    # Compare
    missing = find_missing(cves, installed)

    # Display
    show_results(missing)

    # Output JSON
    report = {
        "tool": "WinShield",
        "bulletin": month,
        "scan_date": datetime.now().isoformat(),
        "installed_count": len(installed),
        "missing_count": len(missing),
        "missing": missing,
        "kb_source": source
    }

    with open("scan_results.json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    console.print(f"\n[dim]Results saved to scan_results.json[/dim]")
    console.print(f"[dim]Log saved to {LOG_FILE}[/dim]")

if __name__ == "__main__":
    try:
        main()
        input("\nPress Enter to exit...")
    finally:
        sys.stdout = sys.__stdout__
        sys.stderr = sys.__stderr__
        _log.close()

"""
WinShield - Windows Vulnerability Scanner (Era-aware monthly CVRF)

Purpose:
    - Load OS/build info from controller_results.json
    - Enumerate installed Windows KB updates
    - Fetch MSRC monthly CVRF bulletins from the OS's "era"
    - Parse CVEs and KB mappings that apply to this OS family/bitness
    - Compare against local KBs to find missing patches
    - Display results and save scanner_results.json

This version uses the public CVRF monthly API:
    https://api.msrc.microsoft.com/cvrf/v2.0/cvrf/{YYYY-MMM}
No API key or authentication is required.
"""

# ============================================================
# Standard library imports
# ============================================================

import json
import os
import re
import sys
import subprocess
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple

from dateutil.relativedelta import relativedelta
from rich.console import Console
from rich.table import Table
import requests

# ============================================================
# Configuration
# ============================================================

POWERSHELL_TIMEOUT_SHORT = 30
POWERSHELL_TIMEOUT_LONG = 90
SYSTEMINFO_TIMEOUT = 60

# Maximum number of months to walk from start to end (hard safety cap)
MAX_MONTHS_SCAN = 180  # 15 years

# How many consecutive months with zero applicable CVEs before we
# assume we are past this OS's era and stop scanning
NO_HIT_STOP_MONTHS = 12

LOG_FILE_NAME = f"winshield_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

MSRC_BASE_URL = "https://api.msrc.microsoft.com/cvrf/v2.0"

# ============================================================
# Logging redirection
# ============================================================

class TeeStream:
    """Mirror stdout/stderr into a log file."""
    def __init__(self, *streams):
        self.streams = streams

    def write(self, data: str) -> None:
        for s in self.streams:
            s.write(data)

    def flush(self) -> None:
        for s in self.streams:
            s.flush()


_log_file = open(LOG_FILE_NAME, "w", encoding="utf-8")
sys.stdout = TeeStream(sys.__stdout__, _log_file)
sys.stderr = TeeStream(sys.__stderr__, _log_file)
console = Console(file=sys.__stdout__, force_terminal=True)

# ============================================================
# Controller environment loader
# ============================================================

def load_controller_env(path: Optional[str] = None) -> Dict:
    """
    Load controller_results.json from the same folder as this script.
    Be tolerant of UTF-8 BOM that PowerShell might add.
    """
    try:
        if path is None:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            path = os.path.join(base_dir, "controller_results.json")

        with open(path, "r", encoding="utf-8-sig") as fh:
            return json.load(fh)
    except Exception as e:
        console.print(f"[bold red]ERROR: Could not load controller_results.json ({e})[/bold red]")
        return {}

# ============================================================
# PowerShell helpers
# ============================================================

def run_ps(ps_command: str, timeout: int = POWERSHELL_TIMEOUT_SHORT) -> Tuple[int, str, str]:
    """Run a PowerShell command and return (exit_code, stdout, stderr)."""
    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_command],
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return proc.returncode, proc.stdout, proc.stderr
    except Exception as exc:
        return 1, "", f"Exception: {exc!r}"


def normalize_ps_json(pipe_text: Optional[str]) -> str:
    """Strip BOM/NUL/whitespace from PowerShell JSON output."""
    if not pipe_text:
        return ""
    return pipe_text.replace("\x00", "").lstrip("\ufeff").strip()

# ============================================================
# KB extraction helpers
# ============================================================

def extract_kb_number(text: str) -> Optional[str]:
    """Return numeric KB from strings like 'KB5048667' or None."""
    if not text:
        return None
    match = re.search(r"KB(\d+)", text, re.IGNORECASE)
    return match.group(1) if match else None

# ============================================================
# Stage 1 - Enumerate installed KBs
# ============================================================

def get_installed_kbs() -> Tuple[Set[str], str]:
    """
    Enumerate installed KBs using a few methods.
    Returns (set_of_kb_numbers, source_name).
    """

    console.print("[*] Enumerating installed KBs...")

    # --- Attempt 1: Get-HotFix ---
    ps_get_hotfix = r"""
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
(Get-HotFix | Select-Object HotFixID) | ConvertTo-Json -Depth 3
"""
    rc, out, err = run_ps(ps_get_hotfix, timeout=POWERSHELL_TIMEOUT_SHORT)
    if rc == 0:
        raw = normalize_ps_json(out)
        if raw:
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, dict):
                    parsed = [parsed]
                kb_numbers: Set[str] = set()
                for item in parsed:
                    kb = extract_kb_number(item.get("HotFixID", ""))
                    if kb:
                        kb_numbers.add(kb)
                if kb_numbers:
                    console.print(f"[+] Found {len(kb_numbers)} KBs via Get-HotFix")
                    return kb_numbers, "Get-HotFix"
            except json.JSONDecodeError:
                console.print("[!] Get-HotFix JSON parse failed")

    # --- Attempt 2: WMIC QFE ---
    try:
        proc = subprocess.run(
            ["wmic", "qfe", "get", "HotFixID", "/format:csv"],
            capture_output=True,
            text=True,
            timeout=POWERSHELL_TIMEOUT_SHORT
        )
        if proc.returncode == 0 and proc.stdout:
            kb_numbers: Set[str] = set()
            for line in proc.stdout.splitlines():
                kb = extract_kb_number(line)
                if kb:
                    kb_numbers.add(kb)
            if kb_numbers:
                console.print(f"[+] Found {len(kb_numbers)} KBs via WMIC QFE")
                return kb_numbers, "WMIC QFE"
    except Exception as exc:
        console.print(f"[!] WMIC failed: {exc!r}")

    # --- Attempt 3: DISM /online /get-packages ---
    try:
        proc = subprocess.run(
            ["dism.exe", "/online", "/get-packages", "/english"],
            capture_output=True,
            text=True,
            timeout=POWERSHELL_TIMEOUT_LONG
        )
        combined = (proc.stdout or "") + (proc.stderr or "")
        if combined:
            kb_numbers = set(re.findall(r"KB(\d+)", combined, re.IGNORECASE))
            if kb_numbers:
                console.print(f"[+] Found {len(kb_numbers)} KBs via DISM")
                return kb_numbers, "DISM /online /get-packages"
    except Exception as exc:
        console.print(f"[!] DISM failed: {exc!r}")

    console.print("[!] Failed to enumerate KBs; treating system as unpatched.")
    return set(), "None"

# ============================================================
# Stage 2 - Era window (start and EOL cap)
# ============================================================

def compute_era_window(env: Dict) -> Tuple[datetime, datetime]:
    """
    Decide which month range to scan based on Windows build:
      - start_dt: approximate release month of this build
      - end_dt: EOL month for that build, if known, otherwise now

    For unknown builds:
      - start_dt = now - 12 months
      - end_dt   = now
    """

    now = datetime.now()
    build = str(env.get("build", "")).strip()

    # Rough mapping: build -> first release month
    build_release_map: Dict[str, datetime] = {
        "10240": datetime(2015, 7, 1),   # Win10 1507
        "10586": datetime(2015, 11, 1),  # 1511
        "14393": datetime(2016, 8, 1),   # 1607
        "15063": datetime(2017, 4, 1),   # 1703
        "16299": datetime(2017, 10, 1),  # 1709
        "17134": datetime(2018, 4, 1),   # 1803
        "17763": datetime(2018, 11, 1),  # 1809
        "18362": datetime(2019, 5, 1),   # 1903
        "18363": datetime(2019, 11, 1),  # 1909
        "19041": datetime(2020, 5, 1),   # 2004
        "19042": datetime(2020, 10, 1),  # 20H2
        "19043": datetime(2021, 5, 1),   # 21H1
        "19044": datetime(2021, 11, 1),  # 21H2
        "19045": datetime(2022, 10, 1),  # 22H2
        # Windows 11
        "22000": datetime(2021, 10, 1),  # 21H2
        "22621": datetime(2022, 9, 1),   # 22H2
        "22631": datetime(2023, 9, 1),   # 23H2 (approx)
    }

    # Rough mapping: build -> end of support month (simplified)
    build_eol_map: Dict[str, datetime] = {
        "10240": datetime(2017, 5, 1),
        "10586": datetime(2018, 4, 1),
        "14393": datetime(2023, 10, 1),
        # others can be filled in more precisely later
    }

    if build in build_release_map:
        start_dt = build_release_map[build]
    else:
        # unknown build: only scan last 12 months
        start_dt = now - relativedelta(months=12)

    if build in build_eol_map:
        end_dt = build_eol_map[build]
        if end_dt > now:
            end_dt = now
    else:
        end_dt = now

    return start_dt, end_dt

# ============================================================
# Stage 3 - MSRC monthly CVRF retrieval
# ============================================================

def get_msrc_bulletin(year_month_label: str) -> Optional[Dict]:
    """
    Fetch one monthly CVRF bulletin, e.g. '2015-Jul'.
    Returns JSON dict or None if not found or on error.
    """
    console.print(f"[*] Querying MSRC CVRF for {year_month_label}...")
    url = f"{MSRC_BASE_URL}/cvrf/{year_month_label}"
    try:
        resp = requests.get(url, headers={"Accept": "application/json"}, timeout=30)
        if resp.status_code == 200:
            console.print(f"[+] Retrieved bulletin {year_month_label}")
            return resp.json()
        elif resp.status_code == 404:
            console.print(f"[!] No bulletin for {year_month_label}")
            return None
        else:
            console.print(f"[!] MSRC returned {resp.status_code} for {year_month_label}")
            return None
    except Exception as exc:
        console.print(f"[!] Error fetching {year_month_label}: {exc!r}")
        return None

# ============================================================
# Stage 4 - CVRF parsing with product filtering
# ============================================================

def build_product_map(cvrf: Dict) -> Dict[str, str]:
    """
    Build ProductID -> FullProductName map by walking ProductTree.
    CVRF ProductTree can be nested, so we recurse through Branch/Branches.
    """

    mapping: Dict[str, str] = {}

    def walk(node: Dict):
        if not isinstance(node, dict):
            return

        fp = node.get("FullProductName")
        if isinstance(fp, list):
            for p in fp:
                pid = p.get("ProductID")
                val = p.get("Value")
                if pid and val:
                    mapping[pid] = val
        elif isinstance(fp, dict):
            pid = fp.get("ProductID")
            val = fp.get("Value")
            if pid and val:
                mapping[pid] = val

        for key in ("Branch", "Branches"):
            branch = node.get(key)
            if isinstance(branch, list):
                for b in branch:
                    walk(b)
            elif isinstance(branch, dict):
                walk(branch)

    walk(cvrf.get("ProductTree", {}) or {})
    return mapping


def derive_product_filters(env: Dict) -> Tuple[List[str], List[str]]:
    """
    From controller env, derive:
      - os_keywords: substrings to match OS family in product names (lowercase)
      - arch_keywords: substrings for arch, e.g. ['x64'] or ['x86']
    """

    os_name = (env.get("os_name") or "").lower()
    bitness = (env.get("bitness") or "").lower()

    os_keywords: List[str] = []
    if "windows 11" in os_name:
        os_keywords.append("windows 11")
    elif "windows 10" in os_name:
        os_keywords.append("windows 10")
    elif "windows 8.1" in os_name:
        os_keywords.append("windows 8.1")
    elif "windows 8 " in os_name:
        os_keywords.append("windows 8")
    elif "windows 7" in os_name:
        os_keywords.append("windows 7")
    else:
        os_keywords.append("windows")

    arch_keywords: List[str] = []
    if "64" in bitness:
        arch_keywords.append("x64")
        arch_keywords.append("arm64")
    else:
        arch_keywords.append("x86")

    return os_keywords, arch_keywords


def parse_cves_from_bulletin(cvrf: Dict, env: Dict) -> List[Dict]:
    """
    Extract CVEs from a CVRF bulletin that apply to this OS family + bitness.
    Returns list of dicts:
        {cve_id, title, severity, kb_numbers}
    """

    if not cvrf:
        return []

    product_map = build_product_map(cvrf)
    os_keywords, arch_keywords = derive_product_filters(env)

    vulns = cvrf.get("Vulnerability", []) or []
    results: List[Dict] = []

    for vuln in vulns:
        cve_id = vuln.get("CVE", "N/A")
        title = vuln.get("Title", {}).get("Value", "N/A")

        # Severity from Threats (Type == 0)
        severity = "Unknown"
        for t in vuln.get("Threats", []) or []:
            if t.get("Type") == 0:
                severity = t.get("Description", {}).get("Value", "Unknown")
                break

        # Determine if this CVE applies to our OS/arch
        applicable = False
        for ps in vuln.get("ProductStatuses", []) or []:
            for pid in ps.get("ProductID", []) or []:
                pname = product_map.get(pid, "").lower()
                if not pname:
                    continue
                if any(ok in pname for ok in os_keywords) and any(
                    ak in pname for ak in arch_keywords
                ):
                    applicable = True
                    break
            if applicable:
                break

        if not applicable:
            continue

        # Collect KB numbers from Vendor Fix remediations
        kb_numbers: List[str] = []
        for r in vuln.get("Remediations", []) or []:
            if r.get("Type") == "Vendor Fix":
                kb = extract_kb_number(r.get("Description", {}).get("Value", ""))
                if kb:
                    kb_numbers.append(kb)

        if not kb_numbers:
            # Some CVEs might be serviced via rollups with no explicit KB text.
            # We skip those here since we cannot directly patch them.
            continue

        results.append({
            "cve_id": cve_id,
            "title": title,
            "severity": severity,
            "kb_numbers": kb_numbers,
        })

    return results

# ============================================================
# Stage 5 - Missing patch analysis
# ============================================================

def find_missing_patches(cves: List[Dict], installed_kbs: Set[str]) -> List[Dict]:
    """
    A CVE is considered missing when:
      - it has at least one KB number, and
      - none of those KBs are present locally.
    """

    if not installed_kbs:
        # Fully unpatched image; every CVE with KBs counts as missing.
        return [c for c in cves if c.get("kb_numbers")]

    missing: List[Dict] = []
    for c in cves:
        kb_set = set(c.get("kb_numbers") or [])
        if kb_set and not (kb_set & installed_kbs):
            missing.append(c)
    return missing

# ============================================================
# Stage 6 - Output and reporting
# ============================================================

def display_results(missing: List[Dict]) -> None:
    if not missing:
        console.print("[bold green]No missing patches detected for this OS in the scanned era.[/bold green]")
        return

    counts: Dict[str, int] = {}
    for c in missing:
        sev = c.get("severity", "Unknown")
        counts[sev] = counts.get(sev, 0) + 1

    console.print(f"\n[bold red]Found {len(missing)} missing patches[/bold red]")
    console.print(f"Severity breakdown: {counts}\n")

    table = Table(title="Missing Security Patches", show_header=True, header_style="bold magenta")
    table.add_column("CVE ID", style="cyan", width=20)
    table.add_column("Severity", width=15)
    table.add_column("Title", width=60)
    table.add_column("Required KB", width=18)

    severity_style_map = {
        "Critical": "bold red",
        "Important": "bold yellow",
        "Moderate": "bold blue",
        "Low": "dim",
    }

    for c in missing:
        sev = c.get("severity", "Unknown")
        style = severity_style_map.get(sev, "white")
        title = c.get("title", "N/A")
        if len(title) > 60:
            title = title[:57] + "..."
        kb_str = ", ".join(c.get("kb_numbers") or []) or "N/A"

        table.add_row(
            c.get("cve_id", "N/A"),
            f"[{style}]{sev}[/{style}]",
            title,
            kb_str
        )

    console.print(table)

# ============================================================
# Main orchestration
# ============================================================

def main() -> None:
    console.print("[bold cyan]WinShield - Windows Vulnerability Scanner[/bold cyan]\n")

    env = load_controller_env()
    if not env:
        return

    os_name = env.get("os_name", "Unknown")
    build = env.get("build", "Unknown")
    bitness = env.get("bitness", "Unknown")

    console.print(f"[dim]Controller OS: {os_name} (build {build}, {bitness})[/dim]\n")

    # Stage 1: local KBs
    installed_kbs, kb_source = get_installed_kbs()
    console.print(f"[dim]KB enumeration source: {kb_source}[/dim]")
    console.print(f"[dim]Installed KB count: {len(installed_kbs)}[/dim]\n")

    # Stage 2: era selection with EOL capping
    start_dt, end_dt = compute_era_window(env)
    console.print(
        f"[*] Scanning CVRF bulletins from {start_dt.strftime('%Y-%b')} "
        f"to {end_dt.strftime('%Y-%b')} (or until no-hit heuristic stops)...\n"
    )

    # Stage 3+4: fetch + parse bulletins
    all_cves: List[Dict] = []
    current = datetime(start_dt.year, start_dt.month, 1)
    months_scanned = 0
    no_hit_streak = 0

    while current <= end_dt and months_scanned < MAX_MONTHS_SCAN:
        year_month_label = current.strftime("%Y-%b")  # e.g. '2015-Jul'
        cvrf = get_msrc_bulletin(year_month_label)

        parsed_cves: List[Dict] = []
        if cvrf:
            parsed_cves = parse_cves_from_bulletin(cvrf, env)

        if parsed_cves:
            console.print(f"[+] {len(parsed_cves)} applicable CVEs found in {year_month_label}")
            all_cves.extend(parsed_cves)
            no_hit_streak = 0
        else:
            no_hit_streak += 1

        # Heuristic: if we see 12 consecutive months with no applicable CVEs,
        # assume we have passed the OS's active era and stop early.
        if no_hit_streak >= NO_HIT_STOP_MONTHS:
            console.print(
                f"[!] No applicable CVEs for {NO_HIT_STOP_MONTHS} consecutive months. "
                "Stopping era scan early."
            )
            break

        current += relativedelta(months=1)
        months_scanned += 1

    console.print(f"\n[+] Total applicable CVEs collected: {len(all_cves)}\n")

    # Stage 5: missing analysis
    missing = find_missing_patches(all_cves, installed_kbs)

    # Stage 6: display + save JSON
    display_results(missing)

    report = {
        "scan_date": datetime.now().isoformat(),
        "os_name": os_name,
        "build": build,
        "bitness": bitness,
        "total_cves": len(all_cves),
        "missing_cves_count": len(missing),
        "missing_cves": missing,
        "installed_kbs_sample": sorted(list(installed_kbs))[:50],
    }

    with open("scanner_results.json", "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)

    console.print(f"\n[dim]Results saved to scanner_results.json[/dim]")
    console.print(f"[dim]Log saved to {LOG_FILE_NAME}[/dim]")


if __name__ == "__main__":
    try:
        try:
            main()
        except Exception as e:
            # Make sure errors are visible before we prompt
            console.print(f"[bold red]Unhandled error in scanner: {e}[/bold red]")
        # Always wait for user input so the window does not auto close
        try:
            input("\nPress Enter to exit...")
        except Exception:
            pass
    finally:
        # Restore real stdout/stderr and close the log safely
        sys.stdout = sys.__stdout__
        sys.stderr = sys.__stderr__
        try:
            _log_file.flush()
            _log_file.close()
        except Exception:
            pass

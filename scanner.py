"""
WinShield - Windows Vulnerability Scanner
Scans for missing security patches by comparing installed updates against Microsoft's monthly CVE bulletins.
"""

# Standard libs
import json
import re
import subprocess
from datetime import datetime

# Typing kept 3.8+ friendly for Pylance
from typing import Optional, Set, List, Dict, Tuple

# Third-party libs
import requests
from rich.console import Console
from rich.table import Table
from dateutil.relativedelta import relativedelta

# Nice console
console = Console()


# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------

def _clean_json_stdout(s: Optional[str]) -> str:
    """
    PowerShell sometimes writes UTF-16-ish text with NULs and a BOM.
    I normalize that to tidy JSON text before json.loads.
    """
    if not s:
        return ""
    return s.replace("\x00", "").lstrip("\ufeff").strip()


def _run_powershell(ps_command: str, timeout: int = 30) -> Tuple[int, str, str]:
    """
    I run PowerShell with safe flags so profiles and policies cannot inject noise.
    Returns (returncode, stdout, stderr).
    """
    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_command],
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return proc.returncode, proc.stdout, proc.stderr
    except Exception as e:
        # I surface the exception text through stderr for a single return shape
        return 1, "", f"Exception: {e!r}"


def _extract_kb_number(s: str) -> Optional[str]:
    """
    I pull out just the numeric part of a KB reference.
    'KB5048667' or 'Install KB5048667' becomes '5048667'.
    """
    if not s:
        return None
    m = re.search(r"KB(\d+)", s, re.IGNORECASE)
    return m.group(1) if m else None


# ------------------------------------------------------------
# Installed KB discovery with several fallbacks
# ------------------------------------------------------------

def get_installed_kbs() -> Set[str]:
    """
    I enumerate installed KBs as a set of numeric strings (no 'KB' prefix).
    I try Get-HotFix, then CIM, then WMIC, then DISM. This order gives
    the best coverage on Win10 x86 and stripped lab images.
    """
    console.print("[*] Enumerating installed patches...")

    # Attempt 1: Get-HotFix
    ps1 = r"""
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$items = Get-HotFix | Select-Object HotFixID, InstalledOn
$items | ConvertTo-Json -Depth 3
"""
    rc, out, err = _run_powershell(ps1)
    if rc == 0:
        raw = _clean_json_stdout(out)
        if raw:
            try:
                data = json.loads(raw)
                if isinstance(data, dict):
                    data = [data]
                kbs: Set[str] = set()
                for item in data:
                    kbnum = _extract_kb_number(str(item.get("HotFixID", "")))
                    if kbnum:
                        kbs.add(kbnum)
                if kbs:
                    console.print(f"[+] Found {len(kbs)} installed patches via Get-HotFix")
                    return kbs
                else:
                    console.print("[!] Get-HotFix returned JSON but no KB entries")
            except json.JSONDecodeError:
                console.print("[!] Get-HotFix did not return valid JSON")
        else:
            console.print("[!] Get-HotFix returned empty stdout")
    else:
        console.print(f"[!] PowerShell Get-HotFix error: {err.strip() or 'unknown error'}")

    # Attempt 2: CIM
    ps2 = r"""
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$items = Get-CimInstance Win32_QuickFixEngineering | Select-Object HotFixID, InstalledOn
$items | ConvertTo-Json -Depth 3
"""
    rc, out, err = _run_powershell(ps2)
    if rc == 0:
        raw = _clean_json_stdout(out)
        if raw:
            try:
                data = json.loads(raw)
                if isinstance(data, dict):
                    data = [data]
                kbs: Set[str] = set()
                for item in data:
                    kbnum = _extract_kb_number(str(item.get("HotFixID", "")))
                    if kbnum:
                        kbs.add(kbnum)
                if kbs:
                    console.print(f"[+] Found {len(kbs)} installed patches via CIM")
                    return kbs
                else:
                    console.print("[!] CIM query returned JSON but no KB entries")
            except json.JSONDecodeError:
                console.print("[!] CIM query did not return valid JSON")
        else:
            console.print("[!] CIM query returned empty stdout")
    else:
        console.print(f"[!] PowerShell CIM error: {err.strip() or 'unknown error'}")

    # Attempt 3: WMIC (deprecated but still available on many Win10 images)
    try:
        wmic = subprocess.run(
            ["wmic", "qfe", "get", "HotFixID,InstalledOn", "/format:csv"],
            capture_output=True, text=True, timeout=30
        )
        if wmic.returncode == 0 and wmic.stdout:
            kbs: Set[str] = set()
            for line in wmic.stdout.splitlines():
                line = line.strip()
                if not line or line.startswith("Node"):
                    continue
                parts = [p.strip() for p in line.split(",")]
                # Expected format: Node,HotFixID,InstalledOn
                if len(parts) >= 3 and parts[1].upper().startswith("KB"):
                    kbnum = _extract_kb_number(parts[1])
                    if kbnum:
                        kbs.add(kbnum)
            if kbs:
                console.print(f"[+] Found {len(kbs)} installed patches via WMIC")
                return kbs
            else:
                console.print("[!] WMIC returned no KB entries")
        else:
            console.print(f"[!] WMIC error: {wmic.stderr.strip() or 'unknown error'}")
    except Exception as e:
        console.print(f"[!] WMIC attempt failed: {e!r}")

    # Attempt 4: DISM (very reliable on lean images, includes package identities)
    try:
        dism = subprocess.run(
            ["dism.exe", "/online", "/get-packages"],
            capture_output=True, text=True, timeout=90
        )
        if dism.returncode == 0 and dism.stdout:
            kbs: Set[str] = set()
            for line in dism.stdout.splitlines():
                m = re.search(r"KB(\d+)", line, re.IGNORECASE)
                if m:
                    kbs.add(m.group(1))
            if kbs:
                console.print(f"[+] Found {len(kbs)} installed patches via DISM")
                return kbs
            else:
                console.print("[!] DISM found no KBs")
        else:
            console.print(f"[!] DISM error: {dism.stderr.strip() or 'unknown error'}")
    except Exception as e:
        console.print(f"[!] DISM attempt failed: {e!r}")

    console.print("[!] Could not enumerate installed KBs on this system")
    return set()


# ------------------------------------------------------------
# MSRC bulletin retrieval
# ------------------------------------------------------------

def get_msrc_cves(year_month: str) -> Optional[Dict]:
    """
    I fetch the CVRF v2.0 bulletin for the given month (format 'YYYY-MMM', e.g. '2025-Nov').
    Returns a dict or None if the month is not published or the request fails.
    """
    console.print(f"[*] Querying MSRC API for {year_month}...")
    url = f"https://api.msrc.microsoft.com/cvrf/v2.0/cvrf/{year_month}"
    headers = {"Accept": "application/json"}
    try:
        resp = requests.get(url, headers=headers, timeout=30)
        if resp.status_code == 200:
            data = resp.json()
            console.print(f"[+] Retrieved bulletin data for {year_month}")
            return data
        if resp.status_code == 404:
            console.print(f"[!] Bulletin not found for {year_month}")
            return None
        console.print(f"[!] MSRC API returned status {resp.status_code}")
        return None
    except requests.RequestException as e:
        console.print(f"[!] Network error contacting MSRC: {e!r}")
        return None
    except json.JSONDecodeError:
        console.print("[!] MSRC API response was not valid JSON")
        return None


def get_latest_bulletin(max_months_back: int = 12) -> Tuple[Optional[str], Optional[Dict]]:
    """
    I walk back from the current month until I find a published bulletin.
    Returns (year_month, data) or (None, None) if nothing is available.
    """
    now = datetime.now()
    for back in range(0, max_months_back + 1):
        target = now - relativedelta(months=back)
        year_month = target.strftime("%Y-%b")
        data = get_msrc_cves(year_month)
        if data:
            if back > 0:
                console.print(f"[*] Using {year_month} bulletin")
            return year_month, data
    console.print("[!] Could not find any MSRC bulletin")
    return None, None


# ------------------------------------------------------------
# CVE parsing
# ------------------------------------------------------------

def parse_cves_from_msrc(msrc_data: Dict) -> List[Dict]:
    """
    I flatten the MSRC CVRF document to a list of dicts:
        { cve_id, title, severity, kb_numbers }
    I take only what I need for matching and display.
    """
    if not msrc_data:
        return []

    vulns: List[Dict] = []
    items = msrc_data.get("Vulnerability", []) or []
    for v in items:
        cve_id = v.get("CVE", "N/A")
        title = v.get("Title", {}).get("Value", "N/A")

        # Severity is declared in Threats with Type == 0
        severity = "Unknown"
        for t in v.get("Threats", []) or []:
            if t.get("Type") == 0:
                severity = t.get("Description", {}).get("Value", "Unknown")
                break

        # Collect KBs from Vendor Fix remediations
        kb_numbers: List[str] = []
        for rmd in v.get("Remediations", []) or []:
            if rmd.get("Type") == "Vendor Fix":
                desc = rmd.get("Description", {}).get("Value", "")
                kb = _extract_kb_number(desc)
                if kb:
                    kb_numbers.append(kb)

        vulns.append({
            "cve_id": cve_id,
            "title": title,
            "severity": severity,
            "kb_numbers": kb_numbers
        })

    console.print(f"[+] Parsed {len(vulns)} CVEs from bulletin")
    return vulns


# ------------------------------------------------------------
# Diff KBs against bulletin
# ------------------------------------------------------------

def find_missing_patches(cves, installed_kbs):
    """
    If the host has zero KBs (fresh/offline image), assume it's unpatched and
    mark CVEs as missing even when the bulletin didn't expose KB numbers.
    Heuristic: count it missing if it has any KBs OR the title mentions Windows.
    """
    # Fully unpatched host: be pessimistic on applicability
    if not installed_kbs:
        missing = []
        for cve in cves:
            title = (cve.get("title") or "").lower()
            kbs   = cve.get("kb_numbers") or []
            if kbs or "windows" in title:
                missing.append(cve)
        return missing

    # Normal case: only missing when none of its KBs are present
    missing = []
    for cve in cves:
        kb_set = set(cve.get("kb_numbers") or [])
        if kb_set and not (kb_set & installed_kbs):
            missing.append(cve)
    return missing


# ------------------------------------------------------------
# Output
# ------------------------------------------------------------

def display_results(missing_cves: List[Dict]) -> None:
    """
    I print a small summary and a color-coded table of missing CVEs.
    """
    if not missing_cves:
        console.print("[bold green]No missing patches found. System appears up to date.[/bold green]")
        return

    counts: Dict[str, int] = {}
    for c in missing_cves:
        sev = c.get("severity", "Unknown")
        counts[sev] = counts.get(sev, 0) + 1

    console.print(f"\n[bold red]Found {len(missing_cves)} missing patches[/bold red]")
    console.print(f"Severity breakdown: {counts}\n")

    table = Table(title="Missing Security Patches", show_header=True, header_style="bold magenta")
    table.add_column("CVE ID", style="cyan", width=18)
    table.add_column("Severity", width=12)
    table.add_column("Title", width=60)
    table.add_column("Required KB", width=18)

    for c in missing_cves:
        sev = c.get("severity", "Unknown")
        style = {
            "Critical": "bold red",
            "Important": "bold yellow",
            "Moderate": "bold blue",
            "Low": "dim"
        }.get(sev, "white")

        kb_str = ", ".join(c.get("kb_numbers") or []) or "N/A"
        title = c.get("title", "N/A")
        if len(title) > 60:
            title = title[:57] + "..."

        table.add_row(
            c.get("cve_id", "N/A"),
            f"[{style}]{sev}[/{style}]",
            title,
            kb_str
        )

    console.print(table)


# ------------------------------------------------------------
# Main
# ------------------------------------------------------------

def main() -> None:
    """
    I run the full scan:
      1) read installed KBs
      2) fetch the newest MSRC bulletin available
      3) parse CVEs and the KBs that fix them
      4) compare and print what is missing
      5) save a JSON report for later use
    """
    console.print("[bold cyan]WinShield - Windows Vulnerability Scanner[/bold cyan]\n")

    installed_kbs = get_installed_kbs()

    year_month, msrc_data = get_latest_bulletin(max_months_back=12)
    if not msrc_data:
        console.print("[bold red]Failed to retrieve MSRC data. Exiting.[/bold red]")
        return

    cves = parse_cves_from_msrc(msrc_data)
    missing = find_missing_patches(cves, installed_kbs)
    if not installed_kbs:
        console.print("[bold yellow]No installed KBs detected — treating Windows CVEs in the bulletin as missing (offline/unpatched image).[/bold yellow]")

    display_results(missing)

    report: Dict = {
        "product": "WinShield",
        "bulletin_month": year_month,
        "scan_date": datetime.now().isoformat(),
        "total_cves_in_bulletin": len(cves),
        "missing_cves_count": len(missing),
        "installed_kbs_sample": sorted(list(installed_kbs))[:50],
        "missing_cves": missing
    }
    with open("scan_results.json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    console.print(f"\n[dim]Results saved to scan_results.json[/dim]")
    if year_month:
        console.print(f"[dim]Scanned using {year_month} security bulletin[/dim]")


if __name__ == "__main__":
    main()
    # I keep the window open when you double-click the script
    input("\nPress Enter to exit...")

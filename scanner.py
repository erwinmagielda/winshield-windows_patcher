"""
WinShield - Windows Vulnerability Scanner
Purpose:
  - Enumerate locally installed Windows KB updates
  - Pull the latest Microsoft Security Response Center (MSRC) monthly bulletin
  - Parse CVEs and map them to KB updates
  - Compare local KBs vs bulletin to identify missing patches
  - Print a readable report and save a JSON file for downstream hotfixing

Notes:
  - This module is read-only. It does not install anything.
  - Designed to work on older x86 images where standard cmdlets may return nothing.
"""

# ----------------------------
# Standard library imports
# ----------------------------
import json
import re
import subprocess
from datetime import datetime
from typing import Optional, Set, List, Dict, Tuple

# ----------------------------
# Third party imports
# ----------------------------
import requests
from rich.console import Console
from rich.table import Table
from dateutil.relativedelta import relativedelta

# Console pretty printer
console = Console()


# ============================================================
# Helper utilities
# ============================================================

def normalize_ps_json_stdout(pipe_text: Optional[str]) -> str:
    """
    I normalize PowerShell JSON text before json.loads:
      - remove BOM and stray NULs that can appear from UTF-16 pipes
      - trim whitespace
    """
    if not pipe_text:
        return ""
    return pipe_text.replace("\x00", "").lstrip("\ufeff").strip()


def run_powershell(ps_command: str, timeout_seconds: int = 30) -> Tuple[int, str, str]:
    """
    I run a PowerShell command with safe flags:
      -NoProfile to avoid profile scripts polluting JSON
      -ExecutionPolicy Bypass to reduce policy prompts in labs
    Returns (exit_code, stdout_text, stderr_text).
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
    I extract only the numeric KB identifier from text.
    Examples:
      'KB5048667' -> '5048667'
      'Install KB5048667 to fix...' -> '5048667'
    """
    if not text:
        return None
    match = re.search(r"KB(\d+)", text, re.IGNORECASE)
    return match.group(1) if match else None


# ============================================================
# Stage 1 - Installed KB discovery with multiple fallbacks
# ============================================================

def get_installed_kbs() -> Set[str]:
    """
    I enumerate installed KBs as numeric strings without the KB prefix.
    I try several data sources to work across many Windows builds:
      1) Get-HotFix
      2) Get-CimInstance Win32_QuickFixEngineering
      3) WMIC QFE (legacy)
      4) DISM package listing
      5) systeminfo lines
    The first source that returns any KBs wins.
    """
    console.print("[*] Enumerating installed patches...")

    # Attempt 1 - Get-HotFix
    ps_get_hotfix = r"""
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$items = Get-HotFix | Select-Object HotFixID, InstalledOn
$items | ConvertTo-Json -Depth 3
"""
    exit_code, stdout_text, stderr_text = run_powershell(ps_get_hotfix)
    if exit_code == 0:
        raw_json = normalize_ps_json_stdout(stdout_text)
        if raw_json:
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
                    console.print(f"[+] Found {len(kb_numbers)} installed patches via Get-HotFix")
                    return kb_numbers
                else:
                    console.print("[!] Get-HotFix returned JSON but no KB entries")
            except json.JSONDecodeError:
                console.print("[!] Get-HotFix did not return valid JSON")
        else:
            console.print("[!] Get-HotFix returned empty stdout")
    else:
        console.print(f"[!] PowerShell Get-HotFix error: {stderr_text.strip() or 'unknown error'}")

    # Attempt 2 - CIM
    ps_cim = r"""
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$items = Get-CimInstance Win32_QuickFixEngineering | Select-Object HotFixID, InstalledOn
$items | ConvertTo-Json -Depth 3
"""
    exit_code, stdout_text, stderr_text = run_powershell(ps_cim)
    if exit_code == 0:
        raw_json = normalize_ps_json_stdout(stdout_text)
        if raw_json:
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
                    console.print(f"[+] Found {len(kb_numbers)} installed patches via CIM")
                    return kb_numbers
                else:
                    console.print("[!] CIM query returned JSON but no KB entries")
            except json.JSONDecodeError:
                console.print("[!] CIM query did not return valid JSON")
        else:
            console.print("[!] CIM query returned empty stdout")
    else:
        console.print(f"[!] PowerShell CIM error: {stderr_text.strip() or 'unknown error'}")

    # Attempt 3 - WMIC
    try:
        wmic_proc = subprocess.run(
            ["wmic", "qfe", "get", "HotFixID,InstalledOn", "/format:csv"],
            capture_output=True, text=True, timeout=30
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
                console.print(f"[+] Found {len(kb_numbers)} installed patches via WMIC")
                return kb_numbers
            else:
                console.print("[!] WMIC returned no KB entries")
        else:
            console.print(f"[!] WMIC error: {wmic_proc.stderr.strip() or 'unknown error'}")
    except Exception as exc:
        console.print(f"[!] WMIC attempt failed: {exc!r}")

    # Attempt 4 - DISM
    try:
        dism_proc = subprocess.run(
            ["dism.exe", "/online", "/get-packages", "/english"],
            capture_output=True, text=True, timeout=90
        )
        combined_text = (dism_proc.stdout or "") + (dism_proc.stderr or "")
        if combined_text:
            kb_numbers: Set[str] = set()
            for line in combined_text.splitlines():
                match = re.search(r"KB(\d+)", line, re.IGNORECASE)
                if match:
                    kb_numbers.add(match.group(1))
            if kb_numbers:
                console.print(f"[+] Found {len(kb_numbers)} installed patches via DISM")
                return kb_numbers
            else:
                console.print("[!] DISM found no KBs")
        else:
            console.print("[!] DISM returned no text output")
    except Exception as exc:
        console.print(f"[!] DISM attempt failed: {exc!r}")

    # Attempt 5 - systeminfo
    try:
        sysinfo_proc = subprocess.run(
            ["systeminfo"], capture_output=True, text=True, timeout=60
        )
        combined_text = (sysinfo_proc.stdout or "") + (sysinfo_proc.stderr or "")
        if combined_text:
            kb_numbers: Set[str] = set()
            for line in combined_text.splitlines():
                match = re.search(r"KB(\d+)", line, re.IGNORECASE)
                if match:
                    kb_numbers.add(match.group(1))
            if kb_numbers:
                console.print(f"[+] Found {len(kb_numbers)} installed patches via systeminfo")
                return kb_numbers
            else:
                console.print("[!] systeminfo listed no KBs")
    except Exception as exc:
        console.print(f"[!] systeminfo attempt failed: {exc!r}")

    console.print("[!] Could not enumerate installed KBs on this system")
    return set()


# ============================================================
# Stage 2 - MSRC bulletin retrieval
# ============================================================

def get_msrc_bulletin(year_month_label: str) -> Optional[Dict]:
    """
    I fetch the CVRF v2.0 bulletin for a given month.
    Format for year_month_label is 'YYYY-MMM' for example '2025-Nov'.
    On success I return a parsed JSON dict.
    """
    console.print(f"[*] Querying MSRC API for {year_month_label}...")
    api_url = f"https://api.msrc.microsoft.com/cvrf/v2.0/cvrf/{year_month_label}"
    http_headers = {"Accept": "application/json"}
    try:
        http_response = requests.get(api_url, headers=http_headers, timeout=30)
        if http_response.status_code == 200:
            bulletin_data = http_response.json()
            console.print(f"[+] Retrieved bulletin data for {year_month_label}")
            return bulletin_data
        if http_response.status_code == 404:
            console.print(f"[!] Bulletin not found for {year_month_label}")
            return None
        console.print(f"[!] MSRC API returned status {http_response.status_code}")
        return None
    except requests.RequestException as exc:
        console.print(f"[!] Network error contacting MSRC: {exc!r}")
        return None
    except json.JSONDecodeError:
        console.print("[!] MSRC API response was not valid JSON")
        return None


def get_latest_available_bulletin(max_months_back: int = 12) -> Tuple[Optional[str], Optional[Dict]]:
    """
    I walk back from the current month until I find a published bulletin.
    I return (year_month_label, bulletin_json) or (None, None) if nothing found.
    """
    current_dt = datetime.now()
    for months_back in range(0, max_months_back + 1):
        target_dt = current_dt - relativedelta(months=months_back)
        year_month_label = target_dt.strftime("%Y-%b")
        bulletin_json = get_msrc_bulletin(year_month_label)
        if bulletin_json:
            if months_back > 0:
                console.print(f"[*] Using {year_month_label} bulletin")
            return year_month_label, bulletin_json
    console.print("[!] Could not find any MSRC bulletin")
    return None, None


# ============================================================
# Stage 3 - Parse CVEs and KB mappings
# ============================================================

def parse_cves_from_bulletin(bulletin_json: Dict) -> List[Dict]:
    """
    I flatten MSRC CVRF JSON into a list of dicts:
      { cve_id, title, severity, kb_numbers }
    I only keep fields needed for comparison and reporting.
    """
    if not bulletin_json:
        return []

    parsed_cve_list: List[Dict] = []
    vuln_items = bulletin_json.get("Vulnerability", []) or []

    for vuln_obj in vuln_items:
        cve_id = vuln_obj.get("CVE", "N/A")
        title_text = vuln_obj.get("Title", {}).get("Value", "N/A")

        # Severity appears where Threats.Type == 0
        severity_label = "Unknown"
        for threat in vuln_obj.get("Threats", []) or []:
            if threat.get("Type") == 0:
                severity_label = threat.get("Description", {}).get("Value", "Unknown")
                break

        # Collect KBs from Remediations where Type == Vendor Fix
        kb_numbers: List[str] = []
        for remediation in vuln_obj.get("Remediations", []) or []:
            if remediation.get("Type") == "Vendor Fix":
                desc_text = remediation.get("Description", {}).get("Value", "")
                kb_numeric = extract_kb_number(desc_text)
                if kb_numeric:
                    kb_numbers.append(kb_numeric)

        parsed_cve_list.append({
            "cve_id": cve_id,
            "title": title_text,
            "severity": severity_label,
            "kb_numbers": kb_numbers
        })

    console.print(f"[+] Parsed {len(parsed_cve_list)} CVEs from bulletin")
    return parsed_cve_list


# ============================================================
# Stage 4 - Compare installed vs missing
# ============================================================

def find_missing_patches(parsed_cves: List[Dict], installed_kb_numbers: Set[str]) -> List[Dict]:
    """
    I identify missing patches on this host.
    Logic:
      - Normal case: a CVE is missing only if none of its KBs are installed
      - Offline or zero KB host: treat Windows CVEs as missing even without explicit KBs
    I return a list of CVEs considered missing.
    """
    # Edge case for fully unpatched images
    if not installed_kb_numbers:
        missing_for_unpatched: List[Dict] = []
        for cve_obj in parsed_cves:
            title_lower = (cve_obj.get("title") or "").lower()
            kb_list = cve_obj.get("kb_numbers") or []
            if kb_list or "windows" in title_lower:
                missing_for_unpatched.append(cve_obj)
        return missing_for_unpatched

    # Standard comparison when KBs exist locally
    missing_standard: List[Dict] = []
    for cve_obj in parsed_cves:
        kb_set = set(cve_obj.get("kb_numbers") or [])
        if kb_set and not (kb_set & installed_kb_numbers):
            missing_standard.append(cve_obj)
    return missing_standard


# ============================================================
# Stage 5 - Output and reporting
# ============================================================

def display_results(missing_cve_list: List[Dict]) -> None:
    """
    I print a summary table with severity coloring and readable columns.
    """
    if not missing_cve_list:
        console.print("[bold green]No missing patches found. System appears up to date.[/bold green]")
        return

    # Tally by severity for a quick risk view
    severity_counts: Dict[str, int] = {}
    for cve_obj in missing_cve_list:
        sev = cve_obj.get("severity", "Unknown")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    console.print(f"\n[bold red]Found {len(missing_cve_list)} missing patches[/bold red]")
    console.print(f"Severity breakdown: {severity_counts}\n")

    table = Table(title="Missing Security Patches", show_header=True, header_style="bold magenta")
    table.add_column("CVE ID", style="cyan", width=18)
    table.add_column("Severity", width=20)
    table.add_column("Title", width=60)
    table.add_column("Required KB", width=18)

    for cve_obj in missing_cve_list:
        sev = cve_obj.get("severity", "Unknown")
        style_map = {
            "Critical": "bold red",
            "Important": "bold yellow",
            "Moderate": "bold blue",
            "Low": "dim",
            # Some MSRC bulletins use categories like Elevation of Privilege
            "Elevation of Privilege": "bold yellow",
            "Remote Code Execution": "bold red",
            "Information Disclosure": "white",
            "Denial of Service": "white",
        }
        sev_style = style_map.get(sev, "white")

        kb_display = ", ".join(cve_obj.get("kb_numbers") or []) or "N/A"
        title_text = cve_obj.get("title", "N/A")
        if len(title_text) > 60:
            title_text = title_text[:57] + "..."

        table.add_row(
            cve_obj.get("cve_id", "N/A"),
            f"[{sev_style}]{sev}[/{sev_style}]",
            title_text,
            kb_display
        )

    console.print(table)


# ============================================================
# Main orchestration
# ============================================================

def main() -> None:
    """
    I orchestrate the scanner workflow:
      1) Enumerate installed KBs
      2) Retrieve the most recent MSRC bulletin available
      3) Parse CVEs and KB mappings
      4) Compare against local KBs to compute missing patches
      5) Display the table and write a JSON report for the hotfixer
    """
    console.print("[bold cyan]WinShield - Windows Vulnerability Scanner[/bold cyan]\n")

    installed_kb_numbers = get_installed_kbs()

    bulletin_label, bulletin_json = get_latest_available_bulletin(max_months_back=12)
    if not bulletin_json:
        console.print("[bold red]Failed to retrieve MSRC data. Exiting.[/bold red]")
        return

    parsed_cve_list = parse_cves_from_bulletin(bulletin_json)
    missing_cve_list = find_missing_patches(parsed_cve_list, installed_kb_numbers)

    if not installed_kb_numbers:
        console.print("[bold yellow]No installed KBs detected - treating Windows CVEs in the bulletin as missing (offline or unpatched image).[/bold yellow]")

    display_results(missing_cve_list)

    # Save a machine readable report for the hotfixer stage
    report_payload: Dict = {
        "tool": "WinShield",
        "bulletin_month": bulletin_label,
        "scan_date": datetime.now().isoformat(),
        "total_cves_in_bulletin": len(parsed_cve_list),
        "missing_cves_count": len(missing_cve_list),
        "installed_kbs_sample": sorted(list(installed_kb_numbers))[:50],
        "missing_cves": missing_cve_list
    }
    with open("scan_results.json", "w", encoding="utf-8") as file_handle:
        json.dump(report_payload, file_handle, indent=2, ensure_ascii=False)

    console.print(f"\n[dim]Results saved to scan_results.json[/dim]")
    if bulletin_label:
        console.print(f"[dim]Scanned using {bulletin_label} security bulletin[/dim]")


if __name__ == "__main__":
    main()
    # Keep the console open when double clicked
    input("\nPress Enter to exit...")

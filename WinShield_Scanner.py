"""
WinShield - Windows Vulnerability Scanner (KB→CVE Edition)

Pipeline:
  1) Read controller_results.json (OS name, build, bitness)
  2) Get installed KBs via PowerShell Get-HotFix
  3) Query Microsoft Update Catalog for this OS/bitness → list of KBs
  4) For each KB, fetch support.microsoft.com/help/<KB> and extract CVE IDs
  5) Compare installed vs catalog KBs
  6) Show table: ID | KB | Status | CVEs (fixed by this KB)
  7) Save scanner_results.json + kb_metadata.json
"""

import json
import os
import re
import subprocess
import sys
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple

import requests
from rich.console import Console
from rich.table import Table

# -------------------------------------------------------------------
# Config
# -------------------------------------------------------------------

POWERSHELL_TIMEOUT = 60
HTTP_TIMEOUT = 20

CONTROLLER_JSON = "controller_results.json"
SCANNER_RESULTS_JSON = "scanner_results.json"
KB_METADATA_JSON = "kb_metadata.json"

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/123.0.0.0 Safari/537.36"
)

console = Console()


# -------------------------------------------------------------------
# Helper functions
# -------------------------------------------------------------------

def load_controller_env(path: str = CONTROLLER_JSON) -> Dict:
    """
    Load controller_results.json written by WinShield_Controller.
    Accepts UTF-8 with or without BOM.
    """
    try:
        with open(path, "r", encoding="utf-8-sig") as fh:
            data = json.load(fh)
        return data
    except Exception as exc:
        console.print(
            f"[bold red]ERROR:[/bold red] Could not load {path} ({exc}). "
            "Run WinShield_Controller first."
        )
        sys.exit(1)


def normalize_ps_json(pipe_text: Optional[str]) -> str:
    if not pipe_text:
        return ""
    return pipe_text.replace("\x00", "").lstrip("\ufeff").strip()


def run_powershell(ps_command: str, timeout: int = POWERSHELL_TIMEOUT) -> Tuple[int, str, str]:
    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_command],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except Exception as exc:
        return 1, "", f"Exception: {exc!r}"


def get_installed_kbs() -> Tuple[Set[str], str]:
    """
    Enumerate installed KBs (numeric IDs, no 'KB' prefix).
    Uses Get-HotFix and falls back to WMIC if needed.
    """
    console.print("[*] Enumerating installed patches...")

    # --- Attempt 1: Get-HotFix via PowerShell ---
    ps_script = r"""
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$items = Get-HotFix | Select-Object HotFixID
$items | ConvertTo-Json -Depth 2
"""
    rc, out_text, err_text = run_powershell(ps_script)
    if rc == 0:
        raw = normalize_ps_json(out_text)
        if raw:
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, dict):
                    parsed = [parsed]
                kbs: Set[str] = set()
                for item in parsed:
                    hotfix_id = str(item.get("HotFixID", "")).upper()
                    m = re.search(r"KB(\d+)", hotfix_id)
                    if m:
                        kbs.add(m.group(1))
                if kbs:
                    console.print(f"[+] Found {len(kbs)} KBs via Get-HotFix")
                    return kbs, "Get-HotFix"
            except json.JSONDecodeError:
                console.print("[!] Get-HotFix JSON parse failed; falling back")
        else:
            console.print("[!] Get-HotFix returned empty output; falling back")
    else:
        console.print(f"[!] Get-HotFix error: {err_text.strip() or 'unknown'}")

    # --- Attempt 2: WMIC QFE ---
    try:
        proc = subprocess.run(
            ["wmic", "qfe", "get", "HotFixID", "/format:csv"],
            capture_output=True,
            text=True,
            timeout=POWERSHELL_TIMEOUT,
        )
        if proc.returncode == 0 and proc.stdout:
            kbs: Set[str] = set()
            for line in proc.stdout.splitlines():
                line = line.strip()
                if not line or line.startswith("Node"):
                    continue
                parts = [p.strip() for p in line.split(",")]
                if len(parts) >= 2 and parts[1].upper().startswith("KB"):
                    m = re.search(r"KB(\d+)", parts[1], re.IGNORECASE)
                    if m:
                        kbs.add(m.group(1))
            if kbs:
                console.print(f"[+] Found {len(kbs)} KBs via WMIC")
                return kbs, "WMIC QFE"
    except Exception as exc:
        console.print(f"[!] WMIC attempt failed: {exc!r}")

    console.print("[!] Could not enumerate installed KBs – treating system as unpatched.")
    return set(), "None"


def discover_catalog_kbs(os_name: str, bitness: str) -> List[str]:
    """
    Hit Microsoft Update Catalog search and scrape KB numbers.
    We keep this intentionally simple: search for
       '<os_name> for x64-based Systems'
    or
       '<os_name> for x86-based Systems'
    then regex KB\d+ from the HTML.
    """
    arch_str = "x64-based Systems" if "64" in bitness else "x86-based Systems"
    query = f"{os_name} for {arch_str}"

    console.print(
        "[*] Querying Microsoft Update Catalog for: "
        f"[bold green]'{query}'[/bold green]"
    )

    search_url = "https://www.catalog.update.microsoft.com/Search.aspx"
    params = {"q": query}
    headers = {"User-Agent": USER_AGENT}

    try:
        resp = requests.get(search_url, params=params, headers=headers, timeout=HTTP_TIMEOUT)
        resp.raise_for_status()
    except Exception as exc:
        console.print(f"[bold red]ERROR:[/bold red] Failed to query Update Catalog: {exc!r}")
        return []

    html = resp.text
    kb_matches = re.findall(r"KB(\d{6,})", html, re.IGNORECASE)
    unique_kbs = sorted(set(kb_matches), key=int)

    console.print(
        f"[+] Discovered {len(unique_kbs)} catalog KBs for this OS/bitness (before diff)"
    )
    return unique_kbs


def fetch_kb_cves(kb_id: str) -> List[str]:
    """
    Try to discover CVEs fixed by a given KB using support.microsoft.com/help/<KB>.
    We simply look for CVE-YYYY-NNNN patterns in the page content.
    """
    urls = [
        f"https://support.microsoft.com/help/{kb_id}",
        f"https://support.microsoft.com/en-us/help/{kb_id}",
    ]
    headers = {"User-Agent": USER_AGENT}
    cves: Set[str] = set()

    for url in urls:
        try:
            resp = requests.get(url, headers=headers, timeout=HTTP_TIMEOUT)
        except Exception:
            continue
        if resp.status_code != 200:
            continue

        # Extract CVE IDs
        matches = re.findall(r"CVE-\d{4}-\d{4,7}", resp.text, re.IGNORECASE)
        for m in matches:
            cves.add(m.upper())

        # If we found some, no need to try more URLs
        if cves:
            break

    return sorted(cves)


# -------------------------------------------------------------------
# Display
# -------------------------------------------------------------------

def display_kb_table(kb_details: List[Dict]) -> None:
    if not kb_details:
        console.print("[bold yellow]No catalog KBs to display.[/bold yellow]")
        return

    table = Table(
        title="Missing KBs (from Microsoft Update Catalog query)",
        show_header=True,
        header_style="bold magenta",
    )
    table.add_column("ID", style="dim", width=4)
    table.add_column("KB")
    table.add_column("Status", width=10)
    table.add_column("CVEs Fixed")

    for idx, kb_info in enumerate(kb_details, start=1):
        kb_str = f"KB{kb_info['kb']}"
        status = kb_info["status"]
        cves = kb_info.get("cves") or []

        status_style = "bold red" if status == "Missing" else "bold green"
        status_text = f"[{status_style}]{status}[/{status_style}]"

        if cves:
            # Join CVEs but avoid an absurdly long column
            cve_text = ", ".join(cves)
            if len(cve_text) > 80:
                cve_text = cve_text[:77] + "..."
        else:
            cve_text = "N/A"

        table.add_row(str(idx), kb_str, status_text, cve_text)

    console.print(table)


# -------------------------------------------------------------------
# Main
# -------------------------------------------------------------------

def main() -> None:
    console.print("[bold cyan]WinShield - Windows Vulnerability Scanner[/bold cyan]\n")

    # 1) Load environment from controller
    env = load_controller_env()
    os_name = env.get("os_name", "Unknown Windows")
    build = env.get("build", "Unknown")
    bitness = env.get("bitness", "Unknown")

    console.print(
        f"OS detected: [bold]{os_name}[/bold] "
        f"(build {build}, {bitness})\n"
    )

    # 2) Installed KBs
    installed_kbs, kb_source = get_installed_kbs()
    console.print(f"KB enumeration source: [italic]{kb_source}[/italic]")
    console.print(f"Installed KBs: {len(installed_kbs)}\n")

    # 3) Catalog KBs for this OS/bitness
    catalog_kbs = discover_catalog_kbs(os_name, bitness)
    if not catalog_kbs:
        console.print("[bold red]No catalog KBs discovered – cannot continue.[/bold red]")
        return

    # 4) Compute missing vs installed (relative to catalog)
    catalog_set = set(catalog_kbs)
    installed_in_catalog = sorted(catalog_set & installed_kbs, key=int)
    missing_kbs = sorted(catalog_set - installed_kbs, key=int)

    console.print(
        f"\nFound [bold]{len(missing_kbs)}[/bold] catalog KBs "
        f"not installed on this system."
    )

    # 5) For all catalog KBs, fetch CVEs
    kb_details: List[Dict] = []
    for kb in catalog_kbs:
        status = "Missing" if kb in missing_kbs else "Installed"
        console.print(f"[*] Resolving CVEs for KB{kb} ({status})...")
        cves = fetch_kb_cves(kb)
        kb_details.append(
            {
                "kb": kb,
                "status": status,
                "cves": cves,
            }
        )

    # 6) Display table
    console.print(
        f"\nOS: {os_name} ({bitness}), "
        f"Installed KBs: {len(installed_kbs)}\n"
    )
    display_kb_table(kb_details)

    # 7) Save JSON outputs
    results_payload = {
        "tool": "WinShield",
        "scan_date": datetime.now().isoformat(),
        "os_name": os_name,
        "build": build,
        "bitness": bitness,
        "kb_enumeration_source": kb_source,
        "installed_kbs": sorted(list(installed_kbs), key=int),
        "catalog_kbs": catalog_kbs,
        "missing_kbs": missing_kbs,
        "kb_details": kb_details,
    }

    with open(SCANNER_RESULTS_JSON, "w", encoding="utf-8") as fh:
        json.dump(results_payload, fh, indent=2, ensure_ascii=False)

    with open(KB_METADATA_JSON, "w", encoding="utf-8") as fh:
        json.dump(kb_details, fh, indent=2, ensure_ascii=False)

    console.print(f"\n[dim]Scanner results saved to {SCANNER_RESULTS_JSON}[/dim]")
    console.print(f"[dim]KB metadata saved to {KB_METADATA_JSON}[/dim]\n")


if __name__ == "__main__":
    main()
    input("Press Enter to exit...")

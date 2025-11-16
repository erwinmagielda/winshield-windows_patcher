# WinShield_Scanner.py
"""
WinShield - Windows Vulnerability Scanner (KB to CVE, Catalog based)

Pipeline:
  1) Read controller_results.json (OS name, build, bitness)
  2) Get installed KBs via PowerShell Get-HotFix
  3) Query Microsoft Update Catalog for this OS/bitness
  4) For each catalog KB, optionally fetch CVEs from support.microsoft.com/help/<KB>
  5) Compare installed vs catalog KBs
  6) Show table of catalog KBs with status
  7) Save scan snapshots:
     - scanner_results.json (last run)
     - kb_metadata.json
     - scans/scan_<system_tag>-<timestamp>.json (archived snapshot)
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

POWERSHELL_TIMEOUT = 60
HTTP_TIMEOUT = 20

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

CONTROLLER_JSON = os.path.join(SCRIPT_DIR, "controller_results.json")
SCANNER_RESULTS_JSON = os.path.join(SCRIPT_DIR, "scanner_results.json")
KB_METADATA_JSON = os.path.join(SCRIPT_DIR, "kb_metadata.json")
SCANS_DIR = os.path.join(SCRIPT_DIR, "scans")

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/123.0.0.0 Safari/537.36"
)

console = Console()


def load_controller_env(path: str = CONTROLLER_JSON) -> Dict:
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
    Uses Get-HotFix, falls back to WMIC if needed.
    """
    console.print("[*] Enumerating installed patches...")

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
                console.print("[!] Get-HotFix JSON parse failed, falling back")
        else:
            console.print("[!] Get-HotFix returned empty output, falling back")
    else:
        console.print(f"[!] Get-HotFix error: {err_text.strip() or 'unknown'}")

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

    console.print("[!] Could not enumerate installed KBs, treating system as unpatched.")
    return set(), "None"


def discover_catalog_kbs(os_name: str, bitness: str, build: str) -> List[str]:
    """
    Query Microsoft Update Catalog and scrape KB numbers for this OS platform.

    - Normalise Windows name (Windows 11, Windows 10, etc.)
    - Map build number to Version 24H2 / 23H2 / 22H2 / 21H2 where possible
    - Try a small sequence of search queries, stop on the first that returns KBs
    """

    def normalise_windows_name(name: str) -> str:
        name = name.replace("Microsoft", "").strip()
        if "Windows 11" in name:
            return "Windows 11"
        if "Windows 10" in name:
            return "Windows 10"
        if "Windows 8.1" in name:
            return "Windows 8.1"
        if "Windows 7" in name:
            return "Windows 7"
        return name

    def map_build_to_release(base_name: str, build_str: str) -> Optional[str]:
        try:
            b = int(build_str)
        except (TypeError, ValueError):
            return None

        if "Windows 11" in base_name:
            if b >= 26100:
                return "Version 24H2"
            if b >= 22631:
                return "Version 23H2"
            if b >= 22621:
                return "Version 22H2"
            if b >= 22000:
                return "Version 21H2"

        if "Windows 10" in base_name:
            if b >= 19045:
                return "Version 22H2"
            if b >= 19044:
                return "Version 21H2"
            if b >= 19043:
                return "Version 21H1"
            if b >= 19042:
                return "Version 20H2"
            if b >= 19041:
                return "Version 2004"

        return None

    base_name = normalise_windows_name(os_name)
    arch_str = "x64-based Systems" if "64" in bitness else "x86-based Systems"
    release_label = map_build_to_release(base_name, build)

    queries: List[str] = []
    if release_label:
        queries.append(f"{base_name} {release_label} for {arch_str}")
        queries.append(f"{base_name} {release_label}")
    queries.append(f"{base_name} for {arch_str}")
    queries.append(f"{base_name} {arch_str}")
    queries.append(base_name)

    search_url = "https://www.catalog.update.microsoft.com/Search.aspx"
    headers = {"User-Agent": USER_AGENT}

    all_kbs: Set[str] = set()
    used_query: Optional[str] = None

    for q in queries:
        console.print(
            "[*] Querying Microsoft Update Catalog for: "
            f"[bold green]'{q}'[/bold green]"
        )
        try:
            resp = requests.get(
                search_url,
                params={"q": q},
                headers=headers,
                timeout=HTTP_TIMEOUT,
            )
            resp.raise_for_status()
        except Exception as exc:
            console.print(
                f"[bold red]ERROR:[/bold red] Failed to query Update Catalog with '{q}': {exc!r}"
            )
            continue

        html = resp.text
        kb_matches = re.findall(r"KB(\d{5,7})", html, re.IGNORECASE)
        unique_kbs = sorted(set(kb_matches), key=int)
        console.print(f"    Found {len(unique_kbs)} KBs for query '{q}'")

        if unique_kbs:
            all_kbs.update(unique_kbs)
            used_query = q
            break

    if not all_kbs:
        console.print(
            "[bold red]No catalog KBs discovered for any query, cannot continue.[/bold red]"
        )
        return []

    console.print(
        f"[+] Discovered {len(all_kbs)} catalog KBs using query "
        f"[italic]'{used_query}'[/italic] (before diff)"
    )
    return sorted(all_kbs, key=int)


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

        matches = re.findall(r"CVE-\d{4}-\d{4,7}", resp.text, re.IGNORECASE)
        for m in matches:
            cves.add(m.upper())

        if cves:
            break

    return sorted(cves)


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
            cve_text = ", ".join(cves)
            if len(cve_text) > 80:
                cve_text = cve_text[:77] + "..."
        else:
            cve_text = "N/A"

        table.add_row(str(idx), kb_str, status_text, cve_text)

    console.print(table)


def make_system_tag(controller_env: Dict) -> str:
    os_name = str(controller_env.get("os_name", "windows")).lower()
    build = str(controller_env.get("build", "")).strip()
    bitness = str(controller_env.get("bitness", "")).lower().replace(" ", "")

    os_name = os_name.replace("microsoft", "")
    os_name = re.sub(r"[^a-z0-9]+", "_", os_name)
    os_name = re.sub(r"_+", "_", os_name).strip("_")

    parts = [os_name]
    if build:
        parts.append(build)
    if bitness:
        parts.append(bitness)

    return "_".join(parts) or "windows_unknown"


def main() -> None:
    console.print("[bold cyan]WinShield - Windows Vulnerability Scanner[/bold cyan]\n")

    env = load_controller_env()
    os_name = env.get("os_name", "Unknown Windows")
    build = env.get("build", "Unknown")
    bitness = env.get("bitness", "Unknown")

    console.print(
        f"OS detected: [bold]{os_name}[/bold] "
        f"(build {build}, {bitness})\n"
    )

    installed_kbs, kb_source = get_installed_kbs()
    console.print(f"KB enumeration source: [italic]{kb_source}[/italic]")
    console.print(f"Installed KBs (local): {len(installed_kbs)}\n")

    catalog_kbs = discover_catalog_kbs(os_name, bitness, build)
    if not catalog_kbs:
        return

    catalog_set = set(catalog_kbs)
    installed_in_catalog = sorted(catalog_set & installed_kbs, key=int)
    missing_kbs = sorted(catalog_set - installed_kbs, key=int)

    console.print(
        f"\nFound [bold]{len(missing_kbs)}[/bold] catalog KBs not installed on this system."
    )

    kb_details: List[Dict] = []
    for kb in catalog_kbs:
        status = "Missing" if kb in missing_kbs else "Installed"
        console.print(f"[*] Resolving CVEs for KB{kb} ({status})...")
        cves = fetch_kb_cves(kb)
        kb_details.append(
            {
                "kb": kb,
                "status": status,
                "in_local_hotfix": kb in installed_kbs,
                "in_catalog": True,
                "cves": cves,
                "notes": [],
            }
        )

    console.print(
        f"\nOS: {os_name} ({bitness}), Installed KBs (local): {len(installed_kbs)}\n"
    )
    display_kb_table(kb_details)

    scan_date = datetime.now().replace(microsecond=0).isoformat()
    system_tag = make_system_tag(env)
    scan_id = f"{system_tag}-{scan_date.replace(':', '-')}"

    summary = {
        "catalog_kbs_total": len(catalog_kbs),
        "installed_kbs_local_total": len(installed_kbs),
        "installed_kbs_in_catalog": len(installed_in_catalog),
        "missing_kbs_count": len(missing_kbs),
    }

    kb_sets = {
        "installed_kbs_local": sorted(list(installed_kbs), key=int),
        "catalog_kbs": catalog_kbs,
        "missing_kbs": missing_kbs,
        "installed_kbs_in_catalog": installed_in_catalog,
    }

    controller_env = {
        "os_name": env.get("os_name"),
        "os_version": env.get("os_version"),
        "build": env.get("build"),
        "bitness": env.get("bitness"),
        "powershell_version": env.get("powershell_version"),
        "python_ok": env.get("python_ok"),
        "deps_ok": env.get("deps_ok"),
    }

    scan_payload: Dict = {
        "tool": "WinShield",
        "schema_version": 2,
        "scan_id": scan_id,
        "scan_date": scan_date,
        "system_tag": system_tag,
        "controller_env": controller_env,
        "summary": summary,
        "kb_sets": kb_sets,
        "kb_details": kb_details,
        # Backwards compatible top level fields
        "os_name": os_name,
        "build": build,
        "bitness": bitness,
        "kb_enumeration_source": kb_source,
        "installed_kbs": kb_sets["installed_kbs_local"],
        "catalog_kbs": catalog_kbs,
        "missing_kbs": missing_kbs,
    }

    os.makedirs(SCANS_DIR, exist_ok=True)
    snapshot_name = f"scan_{scan_id}.json"
    snapshot_path = os.path.join(SCANS_DIR, snapshot_name)
    scan_payload["snapshot_file"] = snapshot_path

    with open(SCANNER_RESULTS_JSON, "w", encoding="utf-8") as fh:
        json.dump(scan_payload, fh, indent=2, ensure_ascii=False)

    with open(KB_METADATA_JSON, "w", encoding="utf-8") as fh:
        json.dump(kb_details, fh, indent=2, ensure_ascii=False)

    with open(snapshot_path, "w", encoding="utf-8") as fh:
        json.dump(scan_payload, fh, indent=2, ensure_ascii=False)

    console.print(f"\n[dim]Scanner results saved to {SCANNER_RESULTS_JSON}[/dim]")
    console.print(f"[dim]KB metadata saved to {KB_METADATA_JSON}[/dim]")
    console.print(f"[dim]Snapshot saved to {snapshot_path}[/dim]\n")

    input("Press Enter to exit...")


if __name__ == "__main__":
    main()

# WinShield_Scanner.py
"""
WinShield - Windows Vulnerability Scanner (KB to CVE, Catalog based)

Pipeline:
  1) Read controller_results.json (OS name, build, bitness)
  2) Get installed KBs via PowerShell Get-HotFix
  3) Query Microsoft Update Catalog for this OS/bitness (by product name + build)
         → get catalog entries: KB + optional update GUID + title
  4) For each catalog KB:
         - Fetch CVEs from support.microsoft.com/help/<KB>
         - Fetch approximate size from Search.aspx?q=KB<id> (Size column)
           using OS + architecture hints to pick the correct row.
  5) Compare installed vs catalog KBs
  6) Show table: ID | KB | Status | Size (MB) | CVEs Fixed
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
from typing import Any, Dict, List, Optional, Set, Tuple

import requests
from rich.console import Console
from rich.table import Table
from rich.progress import Progress

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


# -------------------------------------------------------------------
# Common helpers
# -------------------------------------------------------------------

def load_controller_env(path: str = CONTROLLER_JSON) -> Dict[str, Any]:
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


# -------------------------------------------------------------------
# KB enumeration (local) – Get-HotFix only
# -------------------------------------------------------------------

def get_installed_kbs() -> Tuple[Set[str], str]:
    """
    Enumerate installed KBs (numeric IDs, no 'KB' prefix) via Get-HotFix only.
    If it fails, we just treat the system as unpatched.
    """
    console.print("[*] Enumerating installed patches (Get-HotFix)...")

    ps_script = r"""
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$items = Get-HotFix | Select-Object HotFixID
$items | ConvertTo-Json -Depth 2
"""
    rc, out_text, err_text = run_powershell(ps_script)
    if rc != 0:
        console.print(f"[!] Get-HotFix error: {err_text.strip() or 'unknown'}")
        console.print("[!] Could not enumerate installed KBs, treating system as unpatched.")
        return set(), "Get-HotFix (failed)"

    raw = normalize_ps_json(out_text)
    if not raw:
        console.print("[!] Get-HotFix returned empty output, treating system as unpatched.")
        return set(), "Get-HotFix (empty)"

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        console.print("[!] Get-HotFix JSON parse failed, treating system as unpatched.")
        return set(), "Get-HotFix (parse error)"

    if isinstance(parsed, dict):
        parsed = [parsed]

    kbs: Set[str] = set()
    for item in parsed:
        hotfix_id = str(item.get("HotFixID", "")).upper()
        m = re.search(r"KB(\d+)", hotfix_id)
        if m:
            kbs.add(m.group(1))

    console.print(f"[+] Found {len(kbs)} KBs via Get-HotFix")
    return kbs, "Get-HotFix"


# -------------------------------------------------------------------
# OS / product normalisation
# -------------------------------------------------------------------

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


# -------------------------------------------------------------------
# Catalog discovery (per OS/build)
# -------------------------------------------------------------------

def discover_catalog_entries(os_name: str, bitness: str, build: str) -> List[Dict[str, Any]]:
    """
    Query Microsoft Update Catalog and scrape KB numbers + optional update IDs.

    Returns a list of dicts:
        {
          "kb": "5062660",
          "update_id": "GUID-or-None",
          "title": "Windows 11 ...",
        }
    """
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

    used_query: Optional[str] = None
    html: Optional[str] = None

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

        kb_matches = re.findall(r"KB(\d{5,7})", resp.text, re.IGNORECASE)
        if kb_matches:
            used_query = q
            html = resp.text
            break

    if not html or not used_query:
        console.print(
            "[bold red]No catalog KBs discovered for any query, cannot continue.[/bold red]"
        )
        return []

    entries: Dict[str, Dict[str, Any]] = {}

    pattern = re.compile(
        r"showDownloadDialog\('(?P<guid>[0-9a-fA-F\-]{36})'\).*?KB(?P<kb>\d{5,7}).*?(?P<title>Windows[^<\"]+)?",
        re.IGNORECASE | re.DOTALL,
    )

    for m in pattern.finditer(html):
        guid = m.group("guid")
        kb = m.group("kb")
        title = (m.group("title") or "").strip()
        if kb not in entries:
            entries[kb] = {
                "kb": kb,
                "update_id": guid,
                "title": title,
            }

    kb_matches = re.findall(r"KB(\d{5,7})", html, re.IGNORECASE)
    for kb in kb_matches:
        if kb not in entries:
            entries[kb] = {
                "kb": kb,
                "update_id": None,
                "title": "",
            }

    catalog_entries = sorted(entries.values(), key=lambda e: int(e["kb"]))
    console.print(
        f"[+] Discovered {len(catalog_entries)} catalog KBs using query "
        f"[italic]'{used_query}'[/italic]"
    )
    return catalog_entries


# -------------------------------------------------------------------
# Size + CVE scraping
# -------------------------------------------------------------------

def parse_size_to_mb(size_str: str) -> float:
    """
    Convert '614.3 MB' or '1.2 GB' or '123 KB' to MB.
    """
    m = re.search(r"([\d\.,]+)\s*(KB|MB|GB)", size_str, re.IGNORECASE)
    if not m:
        return 0.0
    value_str, unit = m.group(1), m.group(2).upper()
    try:
        value = float(value_str.replace(",", "."))
    except ValueError:
        return 0.0

    if unit == "KB":
        return value / 1024.0
    if unit == "GB":
        return value * 1024.0
    return value  # MB


def fetch_kb_size_from_catalog_search(
    kb_id: str,
    product_hint: str,
    arch_hint: str,
) -> float:
    """
    Query Search.aspx?q=KB<id> and try to parse the Size column for that KB.

    Strategy:
      1) Extract all <tr> rows containing KB<id>.
      2) Prefer row that contains both product_hint and arch_hint.
      3) If that row has no size, look at **all rows for that KB** and
         gather every size-like token; pick the largest value.
      4) Convert to MB.

    Returns: size in MB (float) or 0.0 if not found.
    """
    url = "https://www.catalog.update.microsoft.com/Search.aspx"
    params = {"q": f"KB{kb_id}"}
    headers = {"User-Agent": USER_AGENT}

    try:
        resp = requests.get(url, params=params, headers=headers, timeout=HTTP_TIMEOUT)
        resp.raise_for_status()
    except Exception:
        return 0.0

    html = resp.text

    # Extract <tr> rows that mention this KB
    row_pattern = re.compile(
        rf"<tr[^>]*>.*?KB{kb_id}.*?</tr>",
        re.IGNORECASE | re.DOTALL,
    )
    rows = row_pattern.findall(html)
    if not rows:
        return 0.0

    product_hint_l = product_hint.lower()
    arch_hint_l = arch_hint.lower()

    # Pick best row by product + arch match
    chosen_row: Optional[str] = None
    for r in rows:
        rl = r.lower()
        if product_hint_l in rl and arch_hint_l in rl:
            chosen_row = r
            break

    if chosen_row is None:
        chosen_row = rows[0]

    # First try sizes in the chosen row
    sizes = re.findall(
        r"([\d\.,]+\s*(?:KB|MB|GB))",
        chosen_row,
        re.IGNORECASE,
    )

    # If still nothing, fall back: collect all sizes from all rows for this KB
    if not sizes:
        for r in rows:
            sizes.extend(
                re.findall(
                    r"([\d\.,]+\s*(?:KB|MB|GB))",
                    r,
                    re.IGNORECASE,
                )
            )

    if not sizes:
        return 0.0

    # Convert all size candidates and take the largest (most conservative)
    mb_values = [parse_size_to_mb(s) for s in sizes]
    mb_values = [v for v in mb_values if v > 0]
    if not mb_values:
        return 0.0

    return round(max(mb_values), 2)


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


# -------------------------------------------------------------------
# Display helpers
# -------------------------------------------------------------------

def display_kb_table(kb_details: List[Dict[str, Any]], title: str) -> None:
    if not kb_details:
        console.print("[bold yellow]No catalog KBs to display.[/bold yellow]")
        return

    table = Table(
        title=title,
        show_header=True,
        header_style="bold magenta",
    )
    table.add_column("ID", style="dim", width=4)
    table.add_column("KB")
    table.add_column("Status", width=10)
    table.add_column("Size (MB)", justify="right")
    table.add_column("CVEs Fixed")

    for idx, kb_info in enumerate(kb_details, start=1):
        kb_str = f"KB{kb_info['kb']}"
        status = kb_info["status"]
        cves = kb_info.get("cves") or []
        size_mb = kb_info.get("file_size_mb") or 0.0

        status_style = "bold red" if status == "Missing" else "bold green"
        status_text = f"[{status_style}]{status}[/{status_style}]"

        size_text = f"{size_mb:.1f}" if size_mb > 0 else "N/A"

        if cves:
            cve_text = ", ".join(cves)
            if len(cve_text) > 80:
                cve_text = cve_text[:77] + "..."
        else:
            cve_text = "N/A"

        table.add_row(str(idx), kb_str, status_text, size_text, cve_text)

    console.print(table)


def make_system_tag(controller_env: Dict[str, Any]) -> str:
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


# -------------------------------------------------------------------
# Main
# -------------------------------------------------------------------

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

    # Normalised product / arch hints for size scraping
    base_name = normalise_windows_name(os_name)
    arch_hint = "x64-based Systems" if "64" in bitness else "x86-based Systems"

    # Prepare scan ID early so we can use it for table title + filenames
    scan_date = datetime.now().replace(microsecond=0).isoformat()
    system_tag = make_system_tag(env)
    scan_id = f"{system_tag}-{scan_date.replace(':', '-')}"

    # 1) Local KBs
    installed_kbs, kb_source = get_installed_kbs()

    # 2) Catalog entries (KB + optional update ID)
    catalog_entries = discover_catalog_entries(os_name, bitness, build)
    if not catalog_entries:
        return

    catalog_kbs = [e["kb"] for e in catalog_entries]
    catalog_set = set(catalog_kbs)
    installed_in_catalog = sorted(catalog_set & installed_kbs, key=int)
    missing_kbs = sorted(catalog_set - installed_kbs, key=int)

    console.print(
        f"\n[+] {len(missing_kbs)} catalog KBs are not installed on this system."
    )

    kb_details: List[Dict[str, Any]] = []
    total_catalog_size_mb = 0.0
    total_missing_size_mb = 0.0

    # Progress bar instead of spammy per-KB logs
    with Progress() as progress:
        task = progress.add_task(
            "[cyan]Resolving CVEs and sizes for catalog KBs...",
            total=len(catalog_entries),
        )
        for entry in catalog_entries:
            kb = entry["kb"]
            update_id = entry.get("update_id")

            status = "Missing" if kb in missing_kbs else "Installed"

            cves = fetch_kb_cves(kb)
            file_size_mb = fetch_kb_size_from_catalog_search(kb, base_name, arch_hint)

            total_catalog_size_mb += file_size_mb
            if status == "Missing":
                total_missing_size_mb += file_size_mb

            kb_details.append(
                {
                    "kb": kb,
                    "status": status,
                    "in_local_hotfix": kb in installed_kbs,
                    "in_catalog": True,
                    "cves": cves,
                    "notes": [],
                    "file_size_mb": file_size_mb,
                    "file_urls": [],          # reserved for future use
                    "update_id": update_id,
                    "title": entry.get("title", ""),
                }
            )
            progress.advance(task)

    # Table title = snapshot file name
    snapshot_name = f"scan_{scan_id}.json"
    console.print()
    display_kb_table(kb_details, title=snapshot_name)

    # Summary + sets for JSON
    summary = {
        "catalog_kbs_total": len(catalog_kbs),
        "installed_kbs_local_total": len(installed_kbs),
        "installed_kbs_in_catalog": len(installed_in_catalog),
        "missing_kbs_count": len(missing_kbs),
        "total_catalog_size_mb": round(total_catalog_size_mb, 2),
        "total_missing_size_mb": round(total_missing_size_mb, 2),
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

    scan_payload: Dict[str, Any] = {
        "tool": "WinShield",
        "schema_version": 3,
        "scan_id": scan_id,
        "scan_date": scan_date,
        "system_tag": system_tag,
        "controller_env": controller_env,
        "summary": summary,
        "kb_sets": kb_sets,
        "kb_details": kb_details,
        # Backwards-compatible fields
        "os_name": os_name,
        "build": build,
        "bitness": bitness,
        "kb_enumeration_source": kb_source,
        "installed_kbs": kb_sets["installed_kbs_local"],
        "catalog_kbs": catalog_kbs,
        "missing_kbs": missing_kbs,
    }

    os.makedirs(SCANS_DIR, exist_ok=True)
    snapshot_path = os.path.join(SCANS_DIR, snapshot_name)
    scan_payload["snapshot_file"] = snapshot_path

    with open(SCANNER_RESULTS_JSON, "w", encoding="utf-8") as fh:
        json.dump(scan_payload, fh, indent=2, ensure_ascii=False)

    with open(KB_METADATA_JSON, "w", encoding="utf-8") as fh:
        json.dump(kb_details, fh, indent=2, ensure_ascii=False)

    with open(snapshot_path, "w", encoding="utf-8") as fh:
        json.dump(scan_payload, fh, indent=2, ensure_ascii=False)

    console.print()
    console.print(f"Scanner results saved to {SCANNER_RESULTS_JSON}", style="dim")
    console.print(f"KB metadata saved to {KB_METADATA_JSON}", style="dim")
    console.print(f"Snapshot saved to {snapshot_path}", style="dim")
    console.print()
    input("Press Enter to exit...")


if __name__ == "__main__":
    main()

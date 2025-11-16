# WinShield_Manager.py
"""
WinShield Manager

- Takes a WinShield scan snapshot JSON (from WinShield_Scanner.py)
- Lets the user:
    1) Show KBs
    2) Install ALL missing KBs
    3) Install KBs by ID (using the table ID column from the snapshot)
    4) Verify snapshot (run fresh scan and compare)
    5) Exit

Verification:
  - Uses the current snapshot as BASELINE.
  - Runs WinShield_Scanner.py again (fresh scan).
  - Loads the new snapshot.
  - Compares baseline vs fresh by KB ID.
  - Prints a table with:
        ID | KB | Old Status | New Status | Verification
    where Verification ∈ {No Change, Now Installed, Now Missing,
                          Newly Installed, Newly Missing}.
  - The active snapshot for Manager is NOT changed, so IDs remain
    consistent with the baseline for this session.

Installation:
  - Uses the update GUID stored in snapshot["kb_details"][...]["update_id"].
  - Calls Microsoft Update Catalog DownloadDialog.aspx to resolve the
    download.windowsupdate.com URLs.
  - Downloads the MSU/CAB file into ./downloads.
  - Installs via wusa.exe <file> /quiet /norestart.

Note:
  - Run in an elevated shell (admin) if you actually want installs to work.
"""

import json
import os
import re
import subprocess
import sys
from typing import Any, Dict, List, Optional, Tuple

import requests
from rich.console import Console
from rich.table import Table
from rich.progress import Progress

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DOWNLOADS_DIR = os.path.join(SCRIPT_DIR, "downloads")
SCANNER_PATH = os.path.join(SCRIPT_DIR, "WinShield_Scanner.py")
SCANNER_RESULTS_JSON = os.path.join(SCRIPT_DIR, "scanner_results.json")

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/123.0.0.0 Safari/537.36"
)

console = Console()


# --------------------------------------------------------------
# Common helpers
# --------------------------------------------------------------

def Info(msg: str) -> None:
    console.print(f"[*] {msg}", style="cyan")


def Good(msg: str) -> None:
    console.print(f"[+] {msg}", style="green")


def Warn(msg: str) -> None:
    console.print(f"[!] {msg}", style="yellow")


def Fail(msg: str) -> None:
    console.print(f"[X] {msg}", style="red")
    sys.exit(1)


def load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8-sig") as fh:
        return json.load(fh)


def load_snapshot(path: str) -> Dict[str, Any]:
    try:
        return load_json(path)
    except Exception as exc:
        Fail(f"Could not load snapshot '{path}': {exc!r}")


def display_kb_table(kb_details: List[Dict[str, Any]], title: str) -> None:
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


def parse_id_list(text: str, max_id: int) -> List[int]:
    """
    Parse something like "1 2 5" or "1,2,5" or "1-3,5" into a list of IDs.
    Only returns IDs in [1, max_id].
    """
    ids: List[int] = []
    text = text.replace(",", " ")
    parts = text.split()
    for p in parts:
        if "-" in p:
            start_str, end_str = p.split("-", 1)
            if start_str.isdigit() and end_str.isdigit():
                start = int(start_str)
                end = int(end_str)
                if start <= end:
                    for i in range(start, end + 1):
                        if 1 <= i <= max_id:
                            ids.append(i)
        else:
            if p.isdigit():
                val = int(p)
                if 1 <= val <= max_id:
                    ids.append(val)
    # Deduplicate while preserving order
    seen = set()
    result: List[int] = []
    for i in ids:
        if i not in seen:
            seen.add(i)
            result.append(i)
    return result


# --------------------------------------------------------------
# Catalog download URL resolution
# --------------------------------------------------------------

def get_download_urls_from_update_id(update_id: str) -> List[str]:
    """
    Given an update GUID, call DownloadDialog.aspx and return all
    download.windowsupdate.com URLs found in the dialog.
    """
    base_url = "https://www.catalog.update.microsoft.com/DownloadDialog.aspx"
    headers = {"User-Agent": USER_AGENT}

    html = None
    for params in ({"updateid": update_id}, {"id": update_id}):
        try:
            resp = requests.get(
                base_url,
                params=params,
                headers=headers,
                timeout=30,
            )
            if resp.status_code == 200 and "Download" in resp.text:
                html = resp.text
                break
        except Exception:
            continue

    if not html:
        return []

    urls = re.findall(
        r'href="(https?://download\.windowsupdate\.com/[^"]+)"',
        html,
        re.IGNORECASE,
    )
    urls = sorted(set(urls))
    return urls


def choose_best_download_url(urls: List[str]) -> Optional[str]:
    """
    Prefer .msu, then .cab, otherwise first URL.
    """
    if not urls:
        return None
    msu = [u for u in urls if u.lower().endswith(".msu")]
    if msu:
        return msu[0]
    cab = [u for u in urls if u.lower().endswith(".cab")]
    if cab:
        return cab[0]
    return urls[0]


# --------------------------------------------------------------
# Download & install
# --------------------------------------------------------------

def download_file(url: str, dest_path: str) -> bool:
    """
    Download a file from URL to dest_path.
    Simple streaming download, no per-byte progress (we tick per KB).
    """
    headers = {"User-Agent": USER_AGENT}
    try:
        with requests.get(url, headers=headers, stream=True, timeout=60) as r:
            r.raise_for_status()
            os.makedirs(os.path.dirname(dest_path), exist_ok=True)
            with open(dest_path, "wb") as fh:
                for chunk in r.iter_content(chunk_size=1024 * 1024):
                    if chunk:
                        fh.write(chunk)
        return True
    except Exception as exc:
        Warn(f"Download failed for {url}: {exc!r}")
        return False


def run_wusa_install(path: str) -> int:
    """
    Run wusa.exe <path> /quiet /norestart
    Returns the exit code from wusa.
    """
    cmd = ["wusa.exe", path, "/quiet", "/norestart"]
    try:
        proc = subprocess.run(cmd)
        return proc.returncode
    except Exception as exc:
        Warn(f"Failed to launch wusa for {path}: {exc!r}")
        return -1


def install_kbs(kb_entries: List[Dict[str, Any]]) -> None:
    """
    Given a list of kb_details entries (all 'Missing'), download & install them.
    Uses two progress bars: one for downloads, one for installs.
    """
    if not kb_entries:
        Warn("No KBs selected for installation.")
        return

    # Resolve download URLs first (so we can bail early if GUID missing)
    resolved: List[Tuple[Dict[str, Any], str]] = []  # (entry, url)
    for entry in kb_entries:
        kb = entry["kb"]
        update_id = entry.get("update_id")
        if not update_id:
            Warn(f"KB{kb}: no update GUID in snapshot, cannot auto-download.")
            continue

        urls = get_download_urls_from_update_id(update_id)
        url = choose_best_download_url(urls)
        if not url:
            Warn(f"KB{kb}: could not resolve download URL from Catalog.")
            continue
        resolved.append((entry, url))

    if not resolved:
        Warn("No KBs had resolvable download URLs; nothing to install.")
        return

    # Download phase
    Good(f"Preparing to download {len(resolved)} KB package(s)...")
    downloads: List[Tuple[Dict[str, Any], str]] = []  # (entry, local_path)

    with Progress() as progress:
        task_dl = progress.add_task(
            "[cyan]Downloading KB packages...",
            total=len(resolved),
        )
        for entry, url in resolved:
            kb = entry["kb"]
            filename = os.path.basename(url.split("?")[0])
            local_path = os.path.join(DOWNLOADS_DIR, f"KB{kb}_{filename}")

            progress.console.print(f"[*] KB{kb}: {filename}")
            ok = download_file(url, local_path)
            if ok:
                downloads.append((entry, local_path))
            progress.advance(task_dl)

    if not downloads:
        Warn("All downloads failed; cannot install anything.")
        return

    # Install phase
    Good(f"Starting installation of {len(downloads)} KB package(s)...")
    results: List[Tuple[str, int]] = []  # (kb, exit_code)

    with Progress() as progress:
        task_inst = progress.add_task(
            "[cyan]Installing KB packages (wusa)...",
            total=len(downloads),
        )
        for entry, local_path in downloads:
            kb = entry["kb"]
            progress.console.print(f"[*] Installing KB{kb}...")
            exit_code = run_wusa_install(local_path)
            results.append((kb, exit_code))
            progress.advance(task_inst)

    # Summary
    Good("Installation summary:")
    for kb, code in results:
        if code == 0:
            console.print(f"  KB{kb}: [bold green]SUCCESS[/bold green] (wusa=0)")
        else:
            console.print(
                f"  KB{kb}: [bold red]FAILED[/bold red] (wusa={code}) "
                "[dim](may be superseded or not applicable)[/dim]"
            )


# --------------------------------------------------------------
# Verification / comparison
# --------------------------------------------------------------

def build_kb_index(kb_details: List[Dict[str, Any]]) -> Dict[str, int]:
    """
    Build mapping: kb_id (string) -> baseline ID (1-based index).
    """
    index: Dict[str, int] = {}
    for idx, d in enumerate(kb_details, start=1):
        kb = str(d.get("kb", ""))
        if kb:
            index[kb] = idx
    return index


def compare_snapshots(baseline: Dict[str, Any], fresh: Dict[str, Any]) -> None:
    """
    Compare two snapshots by KB ID and print a full table with verification column.
    Baseline determines the ID mapping.
    """
    base_details = baseline.get("kb_details") or []
    fresh_details = fresh.get("kb_details") or []

    base_index = build_kb_index(base_details)

    base_map = {str(d["kb"]): d for d in base_details if "kb" in d}
    fresh_map = {str(d["kb"]): d for d in fresh_details if "kb" in d}

    all_kbs = sorted(set(base_map.keys()) | set(fresh_map.keys()), key=int)

    table = Table(
        title="Snapshot verification – baseline vs fresh scan",
        show_header=True,
        header_style="bold magenta",
    )
    table.add_column("ID", style="dim", width=4)
    table.add_column("KB")
    table.add_column("Old Status")
    table.add_column("New Status")
    table.add_column("Verification")

    def style_status(s: str) -> str:
        if s == "Missing":
            return "[bold red]Missing[/bold red]"
        if s == "Installed":
            return "[bold green]Installed[/bold green]"
        if s == "N/A":
            return "N/A"
        return s

    for kb in all_kbs:
        base_entry = base_map.get(kb)
        fresh_entry = fresh_map.get(kb)

        old_status = (base_entry or {}).get("status", "N/A")
        new_status = (fresh_entry or {}).get("status", "N/A")

        # Determine verification label
        if old_status == new_status:
            verification = "No Change"
        elif old_status == "Missing" and new_status == "Installed":
            verification = "Now Installed"
        elif old_status == "Installed" and new_status == "Missing":
            verification = "Now Missing"
        elif old_status == "N/A" and new_status == "Installed":
            verification = "Newly Installed"
        elif old_status == "N/A" and new_status == "Missing":
            verification = "Newly Missing"
        else:
            verification = "Status changed"

        # ID comes from baseline index if present, otherwise "-"
        kb_id = base_index.get(kb)
        id_str = str(kb_id) if kb_id is not None else "-"

        table.add_row(
            id_str,
            f"KB{kb}",
            style_status(old_status),
            style_status(new_status),
            verification,
        )

    console.print(table)


def run_fresh_scan_and_load() -> Optional[Dict[str, Any]]:
    """
    Run WinShield_Scanner.py and return the new snapshot JSON (or None on failure).
    """
    if not os.path.isfile(SCANNER_PATH):
        Warn("Scanner script (WinShield_Scanner.py) not found in this directory.")
        return None

    Info("Running fresh WinShield scan for verification...")
    try:
        rc = subprocess.run([sys.executable, SCANNER_PATH]).returncode
    except Exception as exc:
        Warn(f"Failed to launch scanner: {exc!r}")
        return None

    if rc != 0:
        Warn(f"Scanner exited with code {rc}; verification may be incomplete.")

    if not os.path.isfile(SCANNER_RESULTS_JSON):
        Warn("scanner_results.json not found after scan; cannot verify.")
        return None

    scan_results = load_json(SCANNER_RESULTS_JSON)
    new_snapshot_path = scan_results.get("snapshot_file") or SCANNER_RESULTS_JSON
    if not os.path.isfile(new_snapshot_path):
        Warn(f"Snapshot file '{new_snapshot_path}' not found; using scanner_results.json only.")
        new_snapshot_path = SCANNER_RESULTS_JSON

    new_snapshot = load_snapshot(new_snapshot_path)
    Good(f"Verification scan snapshot loaded: {os.path.basename(new_snapshot_path)}")
    return new_snapshot


def verify_snapshot_once(baseline_snapshot: Dict[str, Any]) -> None:
    """
    Perform a single verification run against the current baseline snapshot.
    """
    fresh = run_fresh_scan_and_load()
    if not fresh:
        Warn("Verification failed; keeping existing snapshot active.")
        return

    compare_snapshots(baseline_snapshot, fresh)
    Good("Verification complete. Baseline snapshot remains active for this session.")


# --------------------------------------------------------------
# Menu driver
# --------------------------------------------------------------

def main() -> None:
    if len(sys.argv) < 2:
        Fail("Usage: WinShield_Manager.py <snapshot.json>")

    snapshot_path = sys.argv[1]
    snapshot = load_snapshot(snapshot_path)

    kb_details: List[Dict[str, Any]] = snapshot.get("kb_details") or []
    if not kb_details:
        Fail("Snapshot does not contain 'kb_details'; was it created by WinShield_Scanner v3?")

    system_tag = snapshot.get("system_tag", "unknown")
    scan_date = snapshot.get("scan_date", "unknown")

    # No screen clear on purpose – we want scrollback for accountability.
    console.print("========= WinShield Manager =========", style="bold cyan")
    console.print(
        f"[dim]Baseline snapshot:[/dim] {os.path.basename(snapshot_path)}  "
        f"[dim]System:[/dim] {system_tag}  [dim]Date:[/dim] {scan_date}\n"
    )

    while True:
        console.print("1) Show KBs")
        console.print("2) Install ALL missing KBs")
        console.print("3) Install KBs by ID")
        console.print("4) Verify snapshot (fresh scan & compare)")
        console.print("5) Exit")
        choice = input("> ").strip()

        if choice == "1":
            display_kb_table(kb_details, title=os.path.basename(snapshot_path))
            continue

        if choice == "2":
            missing = [e for e in kb_details if e.get("status") == "Missing"]
            if not missing:
                Good("There are no missing KBs in this snapshot.")
            else:
                install_kbs(missing)
            continue

        if choice == "3":
            max_id = len(kb_details)
            ids_text = input(
                f"Enter ID(s) to install (1-{max_id}, e.g. '1 3 5' or '2-4'): "
            ).strip()
            if not ids_text:
                continue

            ids = parse_id_list(ids_text, max_id)
            if not ids:
                Warn("No valid IDs entered.")
                continue

            selected: List[Dict[str, Any]] = []
            for i in ids:
                entry = kb_details[i - 1]
                if entry.get("status") != "Missing":
                    Warn(f"ID {i} (KB{entry['kb']}) is not marked Missing; skipping.")
                    continue
                selected.append(entry)

            if not selected:
                Warn("No Missing KBs selected, nothing to install.")
            else:
                install_kbs(selected)
            continue

        if choice == "4":
            verify_snapshot_once(snapshot)
            continue

        if choice == "5":
            Good("Exiting WinShield Manager.")
            break

        Warn("Please choose a valid option (1-5).")


if __name__ == "__main__":
    main()

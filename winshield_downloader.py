# WinShield_Manager.py
"""
WinShield Manager (Download only mode)

- Takes a WinShield scan snapshot JSON (from WinShield_Scanner.py)
- Lets the user:
    1) Show KBs
    2) Download ALL missing KBs (no install)
    3) Download KBs by ID (no install)
    4) Verify snapshot (run fresh scan and compare)
    5) Exit

Download:
  - For each selected KB:
        * Query Microsoft Update Catalog: Search.aspx?q=KB<id>
        * Choose the row that best matches current OS (Windows 11 24H2 x64 etc.)
        * Extract GUID candidates from that row/page (36 char UUIDs)
        * For each GUID, POST a proper "updateIDs" JSON body to DownloadDialog.aspx
        * From that dialog, collect URLs from downloadInformation[x].files[y].url
        * Choose the best URL:
              - Prefer URLs containing "kb<id>"
              - Prefer URLs matching arch (x64/x86)
              - Prefer .msu over .cab if both exist
        * Download into ./downloads as KB<id>_<filename>
  - No wusa/dism install is performed in this mode.
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
# Catalog resolution
# --------------------------------------------------------------

def http_get(url: str, params: Dict[str, str] | None = None, timeout: int = 30) -> Optional[requests.Response]:
    headers = {"User-Agent": USER_AGENT}
    try:
        resp = requests.get(url, params=params, headers=headers, timeout=timeout)
        return resp
    except Exception as exc:
        Warn(f"HTTP GET failed for {url}: {exc!r}")
        return None


def http_post_form(url: str, form_data: Dict[str, str], timeout: int = 30) -> Optional[requests.Response]:
    """
    HTTP POST with form data.
    """
    headers = {
        "User-Agent": USER_AGENT,
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "DNT": "1",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    }
    try:
        resp = requests.post(url, data=form_data, headers=headers, timeout=timeout)
        return resp
    except Exception as exc:
        Warn(f"HTTP POST failed for {url}: {exc!r}")
        return None


def derive_product_hints(os_name: str, build: str, bitness: str) -> Tuple[str, str, str]:
    """
    Derive base OS name, version label and arch hint for matching Catalog rows.
    """
    base = "Windows"
    name = os_name or ""

    if "Windows 11" in name:
        base = "Windows 11"
    elif "Windows 10" in name:
        base = "Windows 10"
    else:
        base = name or "Windows"

    version = ""
    try:
        b = int(str(build))
    except Exception:
        b = 0

    if "Windows 11" in base:
        if b >= 26100:
            version = "Version 24H2"
        else:
            version = "Version 23H2"
    elif "Windows 10" in base:
        if b >= 19045:
            version = "Version 22H2"

    arch = "x64-based Systems" if "64" in bitness else "x86-based Systems"
    return base, version, arch


def choose_catalog_row_for_kb(kb: str, html: str, os_name: str, build: str, bitness: str) -> Optional[str]:
    """
    Given the HTML of Search.aspx?q=KB<id>, choose the <tr> block that best matches
    the current OS (base + version + arch).
    Returns the HTML of that row (as a string) or None.
    """
    base, version, arch = derive_product_hints(os_name, build, bitness)
    Info(f"KB{kb}: Looking for OS hints: {base}, {version}, {arch}")

    rows = re.split(r"(?i)<tr[^>]*>", html)
    candidate_rows: List[str] = []
    for row in rows:
        if f"KB{kb}" not in row:
            continue
        candidate_rows.append(row)

    if not candidate_rows:
        Info(f"KB{kb}: No table rows containing KB{kb} found")
        return None

    Info(f"KB{kb}: Found {len(candidate_rows)} candidate rows containing KB{kb}")

    def score(row: str) -> int:
        s = 0
        rl = row.lower()
        if base.lower() in rl:
            s += 2
        if version and version.lower() in rl:
            s += 2
        if arch.lower() in rl:
            s += 2
        if "server" in rl:
            s -= 2
        return s

    scored_rows = [(score(row), i, row) for i, row in enumerate(candidate_rows)]
    scored_rows.sort(reverse=True, key=lambda x: x[0])

    best_score, best_idx, best_row = scored_rows[0]
    Info(f"KB{kb}: Selected row {best_idx+1}/{len(candidate_rows)} with score {best_score}")

    best_lower = best_row.lower()
    found_hints = []
    if base.lower() in best_lower:
        found_hints.append(base)
    if version and version.lower() in best_lower:
        found_hints.append(version)
    if arch.lower() in best_lower:
        found_hints.append(arch)
    if "server" in best_lower:
        found_hints.append("Server (penalty)")

    Info(f"KB{kb}: Row contains: {', '.join(found_hints) if found_hints else 'no OS hints'}")

    return best_row


def extract_guids(text: str) -> List[str]:
    """
    Extract GUIDs from Download button IDs and other GUID like strings.
    Prioritizes Download button IDs as they are the correct UpdateIDs.
    """
    download_button_guids = re.findall(
        r'<input[^>]+id="([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"[^>]*class="[^"]*flatBlueButtonDownload[^"]*"',
        text,
        re.IGNORECASE
    )

    if not download_button_guids:
        download_button_guids = re.findall(
            r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
            text,
        )

    seen = set()
    result: List[str] = []
    for g in download_button_guids:
        if g not in seen:
            seen.add(g)
            result.append(g)
    return result


def post_download_dialog_for_guid(guid: str) -> Optional[requests.Response]:
    """
    Use the Catalog API pattern:

      POST https://www.catalog.update.microsoft.com/DownloadDialog.aspx
      Body: updateIDs = "[{\"size\":0,\"updateID\":\"GUID\",\"uidInfo\":\"GUID\"}]"
    """
    base_url = "https://www.catalog.update.microsoft.com/DownloadDialog.aspx"
    post_obj = {"size": 0, "updateID": guid, "uidInfo": guid}
    body = {"updateIDs": f"[{json.dumps(post_obj, separators=(',', ':'))}]"}
    return http_post_form(base_url, body)


def resolve_dialog_for_kb(kb: str, search_html: str, os_name: str, build: str, bitness: str) -> Optional[str]:
    """
    From Search.aspx?q=KB<id> HTML, choose the correct row, then try GUIDs
    from that row (and as fallback from entire page) against DownloadDialog.aspx
    using the updateIDs POST trick, until one returns a dialog that has
    downloadInformation[...] entries.
    """
    row = choose_catalog_row_for_kb(kb, search_html, os_name, build, bitness)
    guid_candidates = extract_guids(row or "")
    if not guid_candidates:
        guid_candidates = extract_guids(search_html)
        Info(f"KB{kb}: Using fallback - found {len(guid_candidates)} GUIDs from entire page")

    if not guid_candidates:
        Warn(f"KB{kb}: no GUIDs found on Catalog page.")
        return None

    Info(f"KB{kb}: Trying {len(guid_candidates)} GUID candidates for download dialog...")
    if len(guid_candidates) <= 5:
        Info(f"KB{kb}: GUID candidates: {', '.join(guid_candidates)}")

    for i, guid in enumerate(guid_candidates, 1):
        Info(f"KB{kb}: Attempting GUID {i}/{len(guid_candidates)}: {guid}")

        resp = post_download_dialog_for_guid(guid)
        if not resp:
            Info(f"KB{kb}: No POST response for GUID {guid}")
            continue
        if resp.status_code != 200:
            Info(f"KB{kb}: POST HTTP {resp.status_code} for GUID {guid}")
            continue

        html = resp.text

        if not re.search(r"downloadInformation\[\d+\]\.files\[\d+\]\.url\s*=", html):
            Info(f"KB{kb}: GUID {guid} POST response has no downloadInformation[] entries")
            continue

        kb_in_text = f"KB{kb}" in html
        kb_in_filename = bool(re.search(rf'kb{kb}[_-]', html, re.IGNORECASE))

        Info(
            f"KB{kb}: GUID {guid} POST response seems valid, "
            f"KB in text: {kb_in_text}, KB in filename: {kb_in_filename}"
        )

        return html

    Warn(f"KB{kb}: no valid DownloadDialog.aspx response found for GUID candidates.")
    return None


def choose_file_from_dialog(kb: str, dialog_html: str, bitness: str) -> Optional[str]:
    """
    From DownloadDialog.aspx HTML, pick the best URL for this KB.
    Source:
      downloadInformation[x].files[y].url = 'https://...cab or .msu'
    Preference:
      - URLs containing "kb<id>"
      - URLs matching target arch (x64/x86)
      - .msu over .cab
    """
    js_pattern = r"downloadInformation\[\d+\]\.files\[\d+\]\.url\s*=\s*'([^']+)'"
    urls = re.findall(js_pattern, dialog_html)

    if not urls:
        href_urls = re.findall(
            r'href="(https?://[^"]+\.(?:cab|msu))"',
            dialog_html,
            re.IGNORECASE,
        )
        extra_urls = re.findall(
            r'(https?://[^\s"\'>]+\.(?:cab|msu))',
            dialog_html,
            re.IGNORECASE,
        )
        urls = list(set(href_urls + extra_urls))

    urls = list(dict.fromkeys(urls))

    if not urls:
        Info(f"KB{kb}: Dialog contained no .cab/.msu URLs")
        return None

    Info(f"KB{kb}: Found {len(urls)} potential download URLs in dialog")

    kb_lower = f"kb{kb}".lower()
    arch_token = "x64" if "64" in bitness else "x86"

    def classify(u: str) -> Tuple[int, int, int]:
        u_lower = u.lower()
        score_kb = 1 if kb_lower in u_lower else 0
        score_arch = 1 if arch_token in u_lower else 0
        score_ext = 2 if u_lower.endswith(".msu") else 1
        return (score_kb, score_arch, score_ext)

    best_url = max(urls, key=classify)
    Info(f"KB{kb}: Selected URL: {best_url}")
    return best_url


def resolve_download_for_kb(kb: str, os_name: str, build: str, bitness: str) -> Optional[str]:
    """
    High level helper: given KB and system info, return a single URL for the
    .cab/.msu file that should apply to this system, or None.
    """
    search_url = "https://www.catalog.update.microsoft.com/Search.aspx"
    resp = http_get(search_url, params={"q": f"KB{kb}"}, timeout=30)
    if not resp or resp.status_code != 200:
        Warn(f"KB{kb}: Catalog search failed.")
        return None

    dialog_html = resolve_dialog_for_kb(kb, resp.text, os_name, build, bitness)
    if not dialog_html:
        return None

    file_url = choose_file_from_dialog(kb, dialog_html, bitness)
    if not file_url:
        Warn(f"KB{kb}: could not find any .cab/.msu URLs in download dialog.")
        return None

    return file_url


# --------------------------------------------------------------
# Download (no install)
# --------------------------------------------------------------

def download_file(url: str, dest_path: str) -> Optional[int]:
    """
    Download a file from URL to dest_path.
    Returns file size in bytes, or None on error.
    """
    headers = {"User-Agent": USER_AGENT}
    try:
        with requests.get(url, headers=headers, stream=True, timeout=120) as r:
            r.raise_for_status()
            os.makedirs(os.path.dirname(dest_path), exist_ok=True)
            total_bytes = 0
            with open(dest_path, "wb") as fh:
                for chunk in r.iter_content(chunk_size=1024 * 1024):
                    if chunk:
                        fh.write(chunk)
                        total_bytes += len(chunk)
        return total_bytes
    except Exception as exc:
        Warn(f"Download failed for {url}: {exc!r}")
        return None


def download_kbs(kb_entries, os_name, build, bitness):
    if not kb_entries:
        Warn("No KBs selected for download.")
        return

    Good(f"Preparing to download {len(kb_entries)} KB package(s)...")

    for entry in kb_entries:
        kb = entry["kb"]
        Info(f"Resolving download URL for KB{kb}...")
        url = resolve_download_for_kb(kb, os_name, build, bitness)
        if not url:
            Warn(f"KB{kb}: could not resolve download URL.")
            continue

        filename = os.path.basename(url.split("?")[0])
        local_path = os.path.join(DOWNLOADS_DIR, f"KB{kb}_{filename}")

        Info(f"KB{kb}: {filename}")
        size_bytes = download_file(url, local_path)
        if size_bytes is not None:
            size_mb = size_bytes / (1024 * 1024)
            Good(f"KB{kb}: downloaded to {local_path} ({size_mb:.1f} MB)")
        else:
            Warn(f"KB{kb}: download failed.")

    Good("Download only operation complete. No installation was performed.")

# --------------------------------------------------------------
# Verification / comparison
# --------------------------------------------------------------

def build_kb_index(kb_details: List[Dict[str, Any]]) -> Dict[str, int]:
    """
    Build mapping: kb_id (string) -> baseline ID (1 based index).
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

    os_name = snapshot.get("os_name", "Unknown Windows")
    build = snapshot.get("build", "Unknown")
    bitness = snapshot.get("bitness", "Unknown")

    console.print("========= WinShield Manager (Download only) =========", style="bold cyan")
    console.print(
        f"[dim]Baseline snapshot:[/dim] {os.path.basename(snapshot_path)}  "
        f"[dim]System:[/dim] {system_tag}  [dim]Date:[/dim] {scan_date}\n"
    )

    while True:
        console.print("1) Show KBs")
        console.print("2) Download ALL missing KBs (no install)")
        console.print("3) Download KBs by ID (no install)")
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
                download_kbs(missing, os_name, build, bitness)
            continue

        if choice == "3":
            max_id = len(kb_details)
            ids_text = input(
                f"Enter ID(s) to download (1-{max_id}, e.g. '1 3 5' or '2-4'): "
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
                Warn("No Missing KBs selected, nothing to download.")
            else:
                download_kbs(selected, os_name, build, bitness)
            continue

        if choice == "4":
            verify_snapshot_once(snapshot)
            continue

        if choice == "5":
            Good("Exiting WinShield Manager (download only mode).")
            break

        Warn("Please choose a valid option (1-5).")


if __name__ == "__main__":
    main()

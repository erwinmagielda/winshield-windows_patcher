# WinShield_Downloader.py

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

script_directory = os.path.dirname(os.path.abspath(__file__))
downloads_directory = os.path.join(script_directory, "downloads")

user_agent_string = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/123.0.0.0 Safari/537.36"
)

console = Console()


def info(message: str) -> None:
    console.print(f"[*] {message}", style="cyan")


def good(message: str) -> None:
    console.print(f"[+] {message}", style="green")


def warn(message: str) -> None:
    console.print(f"[!] {message}", style="yellow")


def fail(message: str) -> None:
    console.print(f"[X] {message}", style="red")
    sys.exit(1)


def load_json_file(file_path: str) -> Dict[str, Any]:
    with open(file_path, "r", encoding="utf-8-sig") as file_handle:
        return json.load(file_handle)


def load_snapshot(snapshot_path: str) -> Dict[str, Any]:
    try:
        return load_json_file(snapshot_path)
    except Exception as exception:
        fail(f"Could not load snapshot '{snapshot_path}': {exception!r}")
        raise


def display_kb_table(kb_entries: List[Dict[str, Any]], title: str) -> None:
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

    for index, kb_entry in enumerate(kb_entries, start=1):
        kb_string = f"KB{kb_entry['kb']}"
        kb_status = kb_entry["status"]
        kb_cve_list = kb_entry.get("cves") or []
        kb_size_mb = kb_entry.get("file_size_mb") or 0.0

        status_style = "bold red" if kb_status == "Missing" else "bold green"
        status_text = f"[{status_style}]{kb_status}[/{status_style}]"
        size_text = f"{kb_size_mb:.1f}" if kb_size_mb > 0 else "N/A"

        if kb_cve_list:
            cve_text = ", ".join(kb_cve_list)
            if len(cve_text) > 80:
                cve_text = cve_text[:77] + "..."
        else:
            cve_text = "N/A"

        table.add_row(str(index), kb_string, status_text, size_text, cve_text)

    console.print(table)


def parse_id_list(text: str, maximum_id: int) -> List[int]:
    cleaned_text = text.replace(",", " ")
    text_parts = cleaned_text.split()
    collected_ids: List[int] = []

    for text_part in text_parts:
        if "-" in text_part:
            start_text, end_text = text_part.split("-", 1)
            if start_text.isdigit() and end_text.isdigit():
                start_id = int(start_text)
                end_id = int(end_text)
                if start_id <= end_id:
                    for current_id in range(start_id, end_id + 1):
                        if 1 <= current_id <= maximum_id:
                            collected_ids.append(current_id)
        else:
            if text_part.isdigit():
                value = int(text_part)
                if 1 <= value <= maximum_id:
                    collected_ids.append(value)

    seen_ids = set()
    final_ids: List[int] = []
    for current_id in collected_ids:
        if current_id not in seen_ids:
            seen_ids.add(current_id)
            final_ids.append(current_id)
    return final_ids


def http_get(url: str, params: Dict[str, str] | None = None, timeout: int = 30) -> Optional[requests.Response]:
    headers = {"User-Agent": user_agent_string}
    try:
        response = requests.get(url, params=params, headers=headers, timeout=timeout)
        return response
    except Exception as exception:
        warn(f"HTTP GET failed for {url}: {exception!r}")
        return None


def http_post_form(url: str, form_data: Dict[str, str], timeout: int = 30) -> Optional[requests.Response]:
    headers = {
        "User-Agent": user_agent_string,
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "DNT": "1",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    }
    try:
        response = requests.post(url, data=form_data, headers=headers, timeout=timeout)
        return response
    except Exception as exception:
        warn(f"HTTP POST failed for {url}: {exception!r}")
        return None


def derive_product_hints(os_name: str, os_build: str, os_bitness: str) -> Tuple[str, str, str]:
    base_name = "Windows"
    full_name = os_name or ""

    if "Windows 11" in full_name:
        base_name = "Windows 11"
    elif "Windows 10" in full_name:
        base_name = "Windows 10"
    else:
        base_name = full_name or "Windows"

    version_label = ""
    try:
        build_number = int(str(os_build))
    except Exception:
        build_number = 0

    if "Windows 11" in base_name:
        if build_number >= 26100:
            version_label = "Version 24H2"
        else:
            version_label = "Version 23H2"
    elif "Windows 10" in base_name:
        if build_number >= 19045:
            version_label = "Version 22H2"

    architecture_label = "x64-based Systems" if "64" in os_bitness else "x86-based Systems"
    return base_name, version_label, architecture_label


def choose_catalog_row_for_kb(
    kb_number: str,
    search_html: str,
    os_name: str,
    os_build: str,
    os_bitness: str,
) -> Optional[str]:
    base_name, version_label, architecture_label = derive_product_hints(os_name, os_build, os_bitness)
    info(f"KB{kb_number}: Looking for OS hints: {base_name}, {version_label}, {architecture_label}")

    table_rows = re.split(r"(?i)<tr[^>]*>", search_html)
    candidate_rows: List[str] = []

    for row_html in table_rows:
        if f"KB{kb_number}" not in row_html:
            continue
        candidate_rows.append(row_html)

    if not candidate_rows:
        info(f"KB{kb_number}: No table rows containing KB{kb_number} found")
        return None

    info(f"KB{kb_number}: Found {len(candidate_rows)} candidate rows containing KB{kb_number}")

    def score_row(row_html: str) -> int:
        score_value = 0
        row_lower = row_html.lower()
        if base_name.lower() in row_lower:
            score_value += 2
        if version_label and version_label.lower() in row_lower:
            score_value += 2
        if architecture_label.lower() in row_lower:
            score_value += 2
        if "server" in row_lower:
            score_value -= 2
        return score_value

    scored_rows = [(score_row(row_html), index, row_html) for index, row_html in enumerate(candidate_rows)]
    scored_rows.sort(reverse=True, key=lambda item: item[0])

    best_score, best_index, best_row_html = scored_rows[0]
    info(f"KB{kb_number}: Selected row {best_index + 1}/{len(candidate_rows)} with score {best_score}")

    best_lower = best_row_html.lower()
    found_hints: List[str] = []
    if base_name.lower() in best_lower:
        found_hints.append(base_name)
    if version_label and version_label.lower() in best_lower:
        found_hints.append(version_label)
    if architecture_label.lower() in best_lower:
        found_hints.append(architecture_label)
    if "server" in best_lower:
        found_hints.append("Server (penalty)")

    info(f"KB{kb_number}: Row contains: {', '.join(found_hints) if found_hints else 'no OS hints'}")

    return best_row_html


def extract_guid_values(html_text: str) -> List[str]:
    download_button_guids = re.findall(
        r'<input[^>]+id="([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"[^>]*class="[^"]*flatBlueButtonDownload[^"]*"',
        html_text,
        re.IGNORECASE,
    )

    if not download_button_guids:
        download_button_guids = re.findall(
            r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
            html_text,
        )

    seen_guids = set()
    final_guid_list: List[str] = []
    for guid_value in download_button_guids:
        if guid_value not in seen_guids:
            seen_guids.add(guid_value)
            final_guid_list.append(guid_value)
    return final_guid_list


def post_download_dialog_for_guid(guid_value: str) -> Optional[requests.Response]:
    download_dialog_url = "https://www.catalog.update.microsoft.com/DownloadDialog.aspx"
    update_object = {"size": 0, "updateID": guid_value, "uidInfo": guid_value}
    body_value = {"updateIDs": f"[{json.dumps(update_object, separators=(',', ':'))}]"}
    return http_post_form(download_dialog_url, body_value)


def resolve_dialog_for_kb(
    kb_number: str,
    search_html: str,
    os_name: str,
    os_build: str,
    os_bitness: str,
) -> Optional[str]:
    selected_row_html = choose_catalog_row_for_kb(kb_number, search_html, os_name, os_build, os_bitness)
    guid_candidates = extract_guid_values(selected_row_html or "")
    if not guid_candidates:
        guid_candidates = extract_guid_values(search_html)
        info(f"KB{kb_number}: Using fallback - found {len(guid_candidates)} GUIDs from entire page")

    if not guid_candidates:
        warn(f"KB{kb_number}: no GUIDs found on Catalog page.")
        return None

    info(f"KB{kb_number}: Trying {len(guid_candidates)} GUID candidates for download dialog...")
    if len(guid_candidates) <= 5:
        info(f"KB{kb_number}: GUID candidates: {', '.join(guid_candidates)}")

    for index, guid_value in enumerate(guid_candidates, 1):
        info(f"KB{kb_number}: Attempting GUID {index}/{len(guid_candidates)}: {guid_value}")

        response = post_download_dialog_for_guid(guid_value)
        if not response:
            info(f"KB{kb_number}: No POST response for GUID {guid_value}")
            continue
        if response.status_code != 200:
            info(f"KB{kb_number}: POST HTTP {response.status_code} for GUID {guid_value}")
            continue

        dialog_html = response.text

        has_download_information = re.search(
            r"downloadInformation\[\d+\]\.files\[\d+\]\.url\s*=",
            dialog_html,
        )
        if not has_download_information:
            info(f"KB{kb_number}: GUID {guid_value} POST response has no downloadInformation[] entries")
            continue

        kb_in_text = f"KB{kb_number}" in dialog_html
        kb_in_filename = bool(re.search(rf'kb{kb_number}[_-]', dialog_html, re.IGNORECASE))

        info(
            f"KB{kb_number}: GUID {guid_value} POST response seems valid, "
            f"KB in text: {kb_in_text}, KB in filename: {kb_in_filename}"
        )

        return dialog_html

    warn(f"KB{kb_number}: no valid DownloadDialog.aspx response found for GUID candidates.")
    return None


def choose_file_from_dialog(kb_number: str, dialog_html: str, os_bitness: str) -> Optional[str]:
    javascript_pattern = r"downloadInformation\[\d+\]\.files\[\d+\]\.url\s*=\s*'([^']+)'"
    download_urls = re.findall(javascript_pattern, dialog_html)

    if not download_urls:
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
        combined_urls = href_urls + extra_urls
        download_urls = list(set(combined_urls))

    download_urls = list(dict.fromkeys(download_urls))

    if not download_urls:
        info(f"KB{kb_number}: Dialog contained no .cab/.msu URLs")
        return None

    info(f"KB{kb_number}: Found {len(download_urls)} potential download URLs in dialog")

    kb_token = f"kb{kb_number}".lower()
    architecture_token = "x64" if "64" in os_bitness else "x86"

    def classify_url(url: str) -> Tuple[int, int, int]:
        url_lower = url.lower()
        score_kb = 1 if kb_token in url_lower else 0
        score_architecture = 1 if architecture_token in url_lower else 0
        score_extension = 2 if url_lower.endswith(".msu") else 1
        return score_kb, score_architecture, score_extension

    best_url = max(download_urls, key=classify_url)
    info(f"KB{kb_number}: Selected URL: {best_url}")
    return best_url


def resolve_download_url_for_kb(
    kb_number: str,
    os_name: str,
    os_build: str,
    os_bitness: str,
) -> Optional[str]:
    search_url = "https://www.catalog.update.microsoft.com/Search.aspx"
    response = http_get(search_url, params={"q": f"KB{kb_number}"}, timeout=30)
    if not response or response.status_code != 200:
        warn(f"KB{kb_number}: Catalog search failed.")
        return None

    dialog_html = resolve_dialog_for_kb(kb_number, response.text, os_name, os_build, os_bitness)
    if not dialog_html:
        return None

    file_url = choose_file_from_dialog(kb_number, dialog_html, os_bitness)
    if not file_url:
        warn(f"KB{kb_number}: could not find any .cab/.msu URLs in download dialog.")
        return None

    return file_url


def download_file(download_url: str, destination_path: str) -> Optional[int]:
    headers = {"User-Agent": user_agent_string}
    try:
        with requests.get(download_url, headers=headers, stream=True, timeout=120) as response:
            response.raise_for_status()
            os.makedirs(os.path.dirname(destination_path), exist_ok=True)
            total_bytes = 0
            with open(destination_path, "wb") as file_handle:
                for chunk in response.iter_content(chunk_size=1024 * 1024):
                    if chunk:
                        file_handle.write(chunk)
                        total_bytes += len(chunk)
        return total_bytes
    except Exception as exception:
        warn(f"Download failed for {download_url}: {exception!r}")
        return None


def download_kb_entries(
    kb_entries: List[Dict[str, Any]],
    os_name: str,
    os_build: str,
    os_bitness: str,
) -> None:
    if not kb_entries:
        warn("No KBs selected for download.")
        return

    good(f"Preparing to download {len(kb_entries)} KB package(s)...")

    with Progress() as progress:
        progress_task = progress.add_task(
            "[cyan]Downloading KB packages (no install)...",
            total=len(kb_entries),
        )

        for kb_entry in kb_entries:
            kb_number = kb_entry["kb"]
            progress.console.print(f"[*] Resolving download URL for KB{kb_number}...")
            download_url = resolve_download_url_for_kb(kb_number, os_name, os_build, os_bitness)
            if not download_url:
                progress.console.print(f"[!] KB{kb_number}: could not resolve download URL.")
                progress.advance(progress_task)
                continue

            file_name = os.path.basename(download_url.split("?")[0])
            destination_path = os.path.join(downloads_directory, f"KB{kb_number}_{file_name}")

            progress.console.print(f"[*] KB{kb_number}: {file_name}")
            downloaded_bytes = download_file(download_url, destination_path)
            if downloaded_bytes is not None:
                downloaded_mb = downloaded_bytes / (1024 * 1024)
                progress.console.print(
                    f"[+] KB{kb_number}: downloaded to {destination_path} ({downloaded_mb:.1f} MB)"
                )
            else:
                progress.console.print(f"[!] KB{kb_number}: download failed.")
            progress.advance(progress_task)

    good("Download only operation complete. No installation was performed.")


def main() -> None:
    if len(sys.argv) < 2:
        fail("Usage: WinShield_Downloader.py <snapshot.json>")

    snapshot_path = sys.argv[1]
    snapshot_data = load_snapshot(snapshot_path)

    kb_entries: List[Dict[str, Any]] = snapshot_data.get("kb_details") or []
    if not kb_entries:
        fail("Snapshot does not contain 'kb_details'; was it created by WinShield_Scanner v3?")

    system_tag = snapshot_data.get("system_tag", "unknown")
    scan_date = snapshot_data.get("scan_date", "unknown")

    os_name = snapshot_data.get("os_name", "Unknown Windows")
    os_build = snapshot_data.get("build", "Unknown")
    os_bitness = snapshot_data.get("bitness", "Unknown")

    console.print("========= WinShield Downloader =========", style="bold cyan")
    console.print(
        f"[dim]Snapshot:[/dim] {os.path.basename(snapshot_path)}  "
        f"[dim]System:[/dim] {system_tag}  [dim]Scan date:[/dim] {scan_date}\n"
    )

    while True:
        console.print("1) Show KBs")
        console.print("2) Download ALL missing KBs (no install)")
        console.print("3) Download KBs by ID (no install)")
        console.print("4) Exit")
        menu_choice = input("> ").strip()

        if menu_choice == "1":
            display_kb_table(kb_entries, title=os.path.basename(snapshot_path))
            continue

        if menu_choice == "2":
            missing_entries = [entry for entry in kb_entries if entry.get("status") == "Missing"]
            if not missing_entries:
                good("There are no missing KBs in this snapshot.")
            else:
                download_kb_entries(missing_entries, os_name, os_build, os_bitness)
            continue

        if menu_choice == "3":
            maximum_id = len(kb_entries)
            id_text = input(
                f"Enter ID(s) to download (1-{maximum_id}, e.g. '1 3 5' or '2-4'): "
            ).strip()
            if not id_text:
                continue

            selected_ids = parse_id_list(id_text, maximum_id)
            if not selected_ids:
                warn("No valid IDs entered. Cancelling selection.")
                continue

            selected_entries: List[Dict[str, Any]] = []
            for current_id in selected_ids:
                kb_entry = kb_entries[current_id - 1]
                if kb_entry.get("status") != "Missing":
                    warn(f"ID {current_id} (KB{kb_entry['kb']}) is not marked Missing; skipping.")
                    continue
                selected_entries.append(kb_entry)

            if not selected_entries:
                warn("No Missing KBs selected, nothing to download.")
            else:
                download_kb_entries(selected_entries, os_name, os_build, os_bitness)
            continue

        if menu_choice == "4":
            good("Exiting WinShield Downloader.")
            break

        break


if __name__ == "__main__":
    main()

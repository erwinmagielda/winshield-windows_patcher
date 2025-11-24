"""
WinShield Downloader (download-only, JSON summary)

- Loads winshield_scan_result.json produced by winshield_scanner.py.
- For each missing KB:
      → Resolve Microsoft Update Catalog download URL.
      → Download .msu/.cab file into ./downloads/.
      → Record status: Downloaded / Unavailable / Failed.
- Writes winshield_download_result.json with a detailed summary.

Future extension:
- Present missing KBs with numeric IDs.
- Allow the user to select subsets and ranges (eg "1-3,5,7").
- Integrate simple type hints (LCU-like vs other) once classification is in place.
"""

import json
import os
import re
import sys
from typing import Optional, Dict, Any, List

import requests

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DOWNLOADS_DIR = os.path.join(SCRIPT_DIR, "downloads")
SCAN_RESULT_PATH = os.path.join(SCRIPT_DIR, "winshield_scan_result.json")
DOWNLOAD_RESULT_PATH = os.path.join(SCRIPT_DIR, "winshield_download_result.json")

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/123.0.0.0 Safari/537.36"
)


def http_get(url: str, params: Dict[str, str] | None = None, timeout: int = 30) -> Optional[requests.Response]:
    """
    Perform an HTTP GET with a fixed User-Agent and optional query parameters.
    Returns the Response object or None when the request fails.
    """
    try:
        return requests.get(
            url,
            params=params,
            headers={"User-Agent": USER_AGENT},
            timeout=timeout,
        )
    except Exception as exc:
        print(f"[!] HTTP GET failed for {url}: {exc}")
        return None


def http_post_form(url: str, body: Dict[str, str], timeout: int = 30) -> Optional[requests.Response]:
    """
    Perform an HTTP POST with form-encoded data.
    Returns the Response object or None when the request fails.
    """
    try:
        return requests.post(
            url,
            data=body,
            headers={
                "User-Agent": USER_AGENT,
                "Content-Type": "application/x-www-form-urlencoded",
            },
            timeout=timeout,
        )
    except Exception as exc:
        print(f"[!] HTTP POST failed for {url}: {exc}")
        return None


def extract_guids(html: str) -> List[str]:
    """
    Extract GUIDs from the Microsoft Update Catalog search results page.

    The GUID format is:
      8-4-4-4-12 hex digits, eg: 01234567-89ab-cdef-0123-456789abcdef
    """
    guids = re.findall(
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        html,
    )
    unique: List[str] = []
    seen: set[str] = set()
    for guid in guids:
        if guid not in seen:
            seen.add(guid)
            unique.append(guid)
    return unique


def post_download_dialog(guid: str) -> Optional[str]:
    """
    Call the DownloadDialog.aspx endpoint for a specific catalog GUID and return the HTML.

    The HTML is expected to contain the "downloadInformation" data structure.
    """
    url = "https://www.catalog.update.microsoft.com/DownloadDialog.aspx"
    payload = {
        "updateIDs": f'[{{"size":0,"updateID":"{guid}","uidInfo":"{guid}"}}]'
    }

    response = http_post_form(url, payload)
    if not response or response.status_code != 200:
        return None

    html = response.text
    if "downloadInformation" not in html:
        return None

    return html


def choose_file_url(dialog_html: str, kb_digits: str, bitness: str) -> Optional[str]:
    """
    Select the best candidate MSU or CAB file URL from the DownloadDialog markup.

    The scoring favours:
      - URLs containing the KB token (eg "kb5026361")
      - URLs matching architecture (x64 vs x86)
      - MSU files over CAB when multiple are present
    """
    urls = re.findall(
        r"downloadInformation\[\d+\]\.files\[\d+\]\.url\s*=\s*'([^']+)'",
        dialog_html,
    )

    if not urls:
        urls = re.findall(
            r'(https?://[^\s"]+\.(?:cab|msu))',
            dialog_html,
            flags=re.IGNORECASE,
        )

    if not urls:
        return None

    kb_token = f"kb{kb_digits}".lower()
    arch_token = "x64" if "64" in bitness else "x86"

    def score(url: str) -> tuple[int, int, int]:
        lower = url.lower()
        return (
            1 if kb_token in lower else 0,
            1 if arch_token in lower else 0,
            2 if lower.endswith(".msu") else 1,
        )

    return max(urls, key=score)


def resolve_download_for_kb(kb_digits: str, os_name: str, build: str, bitness: str) -> Optional[str]:
    """
    Resolve a Microsoft Update Catalog download URL for a given KB number.

    Steps:
      - Submit a catalog search for "KB<digits>".
      - Extract candidate GUIDs from the result page.
      - Query each GUID's DownloadDialog.aspx endpoint.
      - Select the best matching file URL from the dialog HTML.

    Returns the URL string or None when resolution fails.
    """
    search_url = "https://www.catalog.update.microsoft.com/Search.aspx"
    response = http_get(search_url, params={"q": f"KB{kb_digits}"})
    if not response or response.status_code != 200:
        print(f"[!] Catalog search for KB{kb_digits} failed (HTTP {getattr(response, 'status_code', '???')})")
        return None

    page_html = response.text
    guids = extract_guids(page_html)

    if not guids:
        print(f"[!] KB{kb_digits}: no GUIDs found on search page")
        return None

    for guid in guids:
        dialog_html = post_download_dialog(guid)
        if not dialog_html:
            continue

        url = choose_file_url(dialog_html, kb_digits, bitness)
        if url:
            return url

    return None


def download_file(url: str, dest: str) -> Optional[int]:
    """
    Download a file from the given URL to the destination path.

    The download is streamed in 1 MB chunks to limit memory usage.
    Returns the number of bytes written, or None when the download fails.
    """
    try:
        with requests.get(url, stream=True, timeout=120) as response:
            response.raise_for_status()
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            total_bytes = 0
            with open(dest, "wb") as handle:
                for chunk in response.iter_content(1024 * 1024):
                    if chunk:
                        handle.write(chunk)
                        total_bytes += len(chunk)
        return total_bytes
    except Exception as exc:
        print(f"[!] Download failed for {url}: {exc}")
        return None


def main() -> None:
    if not os.path.isfile(SCAN_RESULT_PATH):
        print("[X] winshield_scan_result.json not found. Run winshield_scanner.py first.")
        sys.exit(1)

    with open(SCAN_RESULT_PATH, "r", encoding="utf-8") as handle:
        scan = json.load(handle)

    baseline = scan.get("baseline") or {}
    missing_kbs: List[str] = scan.get("missing_kbs") or []

    if not missing_kbs:
        print("[+] No missing KBs according to the last WinShield scan. System is up to date for the scanned MSRC window.")
        return

    os_name = baseline.get("OSName", "Unknown Windows")
    build = str(baseline.get("Build") or baseline.get("FullBuild") or "0")
    architecture = baseline.get("Architecture", "x64")
    bitness = "64" if "64" in architecture else "32"

    print(f"[*] OS: {os_name} | Build: {build} | Architecture: {architecture}")
    print(f"[*] Missing KBs reported by scanner: {', '.join(missing_kbs)}")
    print("============================================================")

    results: List[Dict[str, Any]] = []

    for kb in missing_kbs:
        kb_digits = re.sub(r"[^0-9]", "", kb)

        if not kb_digits:
            print(f"[!] Cannot extract digits from {kb}, marking as Unavailable.")
            results.append(
                {
                    "kb": kb,
                    "digits": None,
                    "status": "Unavailable",
                    "reason": "No numeric KB ID",
                    "url": None,
                    "local_path": None,
                    "size_bytes": None,
                }
            )
            continue

        print(f"\n[*] Resolving Microsoft Update Catalog entry for {kb} ...")
        url = resolve_download_for_kb(kb_digits, os_name, build, bitness)

        if not url:
            print(f"[!] KB{kb_digits}: No valid catalog URL found. Marking as Unavailable.")
            results.append(
                {
                    "kb": kb,
                    "digits": kb_digits,
                    "status": "Unavailable",
                    "reason": "No Catalog URL found",
                    "url": None,
                    "local_path": None,
                    "size_bytes": None,
                }
            )
            continue

        filename = os.path.basename(url.split("?", 1)[0])
        dest_path = os.path.join(DOWNLOADS_DIR, f"{kb}_{filename}")

        print(f"[+] Downloading {filename} to {dest_path} ...")
        size_bytes = download_file(url, dest_path)

        if size_bytes is not None:
            size_mb = size_bytes / (1024 * 1024)
            print(f"[+] Saved {size_mb:.1f} MB to {dest_path}")
            results.append(
                {
                    "kb": kb,
                    "digits": kb_digits,
                    "status": "Downloaded",
                    "reason": None,
                    "url": url,
                    "local_path": dest_path,
                    "size_bytes": size_bytes,
                }
            )
        else:
            print(f"[!] Download failed for {kb}")
            results.append(
                {
                    "kb": kb,
                    "digits": kb_digits,
                    "status": "Failed",
                    "reason": "HTTP or I/O error",
                    "url": url,
                    "local_path": dest_path,
                    "size_bytes": None,
                }
            )

    summary = {
        "baseline": {
            "OSName": os_name,
            "Build": build,
            "Architecture": architecture,
        },
        "missing_kbs": missing_kbs,
        "results": results,
    }

    with open(DOWNLOAD_RESULT_PATH, "w", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=2)

    print("\n[+] Download results saved to winshield_download_result.json")
    print("[*] Download-only run complete.")


if __name__ == "__main__":
    main()

# winshield_downloader.py
"""
WinShield Downloader (Download-only, JSON summary)

- Loads winshield_scan_result.json (from winshield_scanner.py)
- For each missing KB:
      → Resolve Microsoft Update Catalog download URL
      → Download .msu/.cab file into ./downloads/
      → Mark as Downloaded / Unavailable / Failed
- Saves: winshield_download_result.json
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

# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def http_get(url: str, params: Dict[str, str] | None = None, timeout: int = 30) -> Optional[requests.Response]:
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

# ---------------------------------------------------------------------------
# Catalog scraping
# ---------------------------------------------------------------------------

def extract_guids(html: str) -> list[str]:
    """Extract GUIDs from the catalog search page."""
    guids = re.findall(
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        html,
    )
    seen = set()
    out: list[str] = []
    for g in guids:
        if g not in seen:
            seen.add(g)
            out.append(g)
    return out


def post_download_dialog(guid: str) -> Optional[str]:
    """POST to DownloadDialog.aspx → return HTML if it looks valid."""
    url = "https://www.catalog.update.microsoft.com/DownloadDialog.aspx"
    payload = {
        "updateIDs": f'[{{"size":0,"updateID":"{guid}","uidInfo":"{guid}"}}]'
    }

    r = http_post_form(url, payload)
    if not r or r.status_code != 200:
        return None

    html = r.text
    if "downloadInformation" not in html:
        return None

    return html


def choose_file_url(dialog_html: str, kb: str, bitness: str) -> Optional[str]:
    """Pick the best .msu/.cab URL from DownloadDialog markup."""
    urls = re.findall(
        r"downloadInformation\[\d+\]\.files\[\d+\]\.url\s*=\s*'([^']+)'",
        dialog_html,
    )

    if not urls:
        urls = re.findall(r'(https?://[^\s"]+\.(?:cab|msu))', dialog_html, flags=re.IGNORECASE)

    if not urls:
        return None

    kb_token = f"kb{kb}".lower()
    arch_token = "x64" if "64" in bitness else "x86"

    def score(u: str):
        u_low = u.lower()
        return (
            1 if kb_token in u_low else 0,
            1 if arch_token in u_low else 0,
            2 if u_low.endswith(".msu") else 1,
        )

    return max(urls, key=score)


def resolve_download_for_kb(kb_digits: str, os_name: str, build: str, bitness: str) -> Optional[str]:
    """
    Search Microsoft Update Catalog → extract GUIDs → POST dialogs → select a file URL.
    kb_digits: just the numeric part, e.g. "5068861".
    """
    search_url = "https://www.catalog.update.microsoft.com/Search.aspx"
    r = http_get(search_url, params={"q": f"KB{kb_digits}"})
    if not r or r.status_code != 200:
        print(f"[!] Catalog search for KB{kb_digits} failed (HTTP {getattr(r, 'status_code', '???')})")
        return None

    page_html = r.text
    guids = extract_guids(page_html)

    if not guids:
        print(f"[!] KB{kb_digits}: no GUIDs found on search page")
        return None

    for guid in guids:
        dialog = post_download_dialog(guid)
        if not dialog:
            continue

        url = choose_file_url(dialog, kb_digits, bitness)
        if url:
            return url

    return None

# ---------------------------------------------------------------------------
# Download helper
# ---------------------------------------------------------------------------

def download_file(url: str, dest: str) -> Optional[int]:
    try:
        with requests.get(url, stream=True, timeout=120) as r:
            r.raise_for_status()
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            total = 0
            with open(dest, "wb") as f:
                for chunk in r.iter_content(1024 * 1024):
                    if chunk:
                        f.write(chunk)
                        total += len(chunk)
        return total
    except Exception as exc:
        print(f"[!] Download failed: {exc}")
        return None

# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------

def main():
    if not os.path.isfile(SCAN_RESULT_PATH):
        print("[X] winshield_scan_result.json not found. Run scanner first.")
        sys.exit(1)

    with open(SCAN_RESULT_PATH, "r", encoding="utf-8") as f:
        scan = json.load(f)

    baseline = scan.get("baseline") or {}
    missing_kbs: List[str] = scan.get("missing_kbs") or []

    if not missing_kbs:
        print("[+] No missing KBs — system is up to date.")
        return

    os_name = baseline.get("OSName", "Unknown Windows")
    build = str(baseline.get("Build") or baseline.get("FullBuild") or "0")
    arch = baseline.get("Architecture", "x64")
    bitness = "64" if "64" in arch else "32"

    print(f"[*] OS: {os_name} | Build: {build} | Arch: {arch}")
    print(f"[*] Missing KBs: {', '.join(missing_kbs)}")
    print("============================================================")

    results: List[Dict[str, Any]] = []

    for kb in missing_kbs:
        kb_digits = re.sub(r"[^0-9]", "", kb)

        if not kb_digits:
            print(f"[!] Cannot extract digits from {kb}, marking Unavailable.")
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

        print(f"\n[*] Resolving Catalog for {kb} ...")
        url = resolve_download_for_kb(kb_digits, os_name, build, bitness)

        if not url:
            print(f"[!] KB{kb_digits}: No valid Catalog URL. Marking Unavailable.")
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

        print(f"[+] Downloading {filename} ...")
        size = download_file(url, dest_path)

        if size is not None:
            size_mb = size / (1024 * 1024)
            print(f"[+] Saved {size_mb:.1f} MB to {dest_path}")
            results.append(
                {
                    "kb": kb,
                    "digits": kb_digits,
                    "status": "Downloaded",
                    "reason": None,
                    "url": url,
                    "local_path": dest_path,
                    "size_bytes": size,
                }
            )
        else:
            print(f"[!] Download failed for {kb}")
            results.append(
                {
                    "kb": kb,
                    "digits": kb_digits,
                    "status": "Failed",
                    "reason": "HTTP / IO error",
                    "url": url,
                    "local_path": dest_path,
                    "size_bytes": None,
                }
            )

    summary = {
        "baseline": {
            "OSName": os_name,
            "Build": build,
            "Architecture": arch,
        },
        "missing_kbs": missing_kbs,
        "results": results,
    }

    with open(DOWNLOAD_RESULT_PATH, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print("\n[+] Download results saved to winshield_download_result.json")
    print("[*] Download-only run complete.")


if __name__ == "__main__":
    main()

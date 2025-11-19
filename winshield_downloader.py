import json
import os
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

import requests

# ----------------------------------------------------------------------
# Paths / constants
# ----------------------------------------------------------------------

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DOWNLOADS_DIR = os.path.join(SCRIPT_DIR, "downloads")
SCAN_RESULT_JSON = os.path.join(SCRIPT_DIR, "winshield_scan_result.json")

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/123.0.0.0 Safari/537.36"
)


# ----------------------------------------------------------------------
# Simple console helpers
# ----------------------------------------------------------------------

def Info(msg: str) -> None:
    print(f"[*] {msg}")


def Good(msg: str) -> None:
    print(f"[+] {msg}")


def Warn(msg: str) -> None:
    print(f"[!] {msg}")


def Fail(msg: str) -> None:
    print(f"[X] {msg}")
    sys.exit(1)


# ----------------------------------------------------------------------
# HTTP helpers
# ----------------------------------------------------------------------

def http_get(url: str, params: Optional[Dict[str, str]] = None, timeout: int = 30) -> Optional[requests.Response]:
    headers = {"User-Agent": USER_AGENT}
    try:
        resp = requests.get(url, params=params, headers=headers, timeout=timeout)
        return resp
    except Exception as exc:
        Warn(f"HTTP GET failed for {url}: {exc!r}")
        return None


def http_post_form(url: str, form_data: Dict[str, str], timeout: int = 30) -> Optional[requests.Response]:
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


# ----------------------------------------------------------------------
# Catalog row / GUID / dialog logic (from your Manager)
# ----------------------------------------------------------------------

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
    Extract GUIDs from Download button IDs and other GUID-like strings.
    Prefer Download button IDs (flatBlueButtonDownload).
    """
    download_button_guids = re.findall(
        r'<input[^>]+id="([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"[^>]*class="[^"]*flatBlueButtonDownload[^"]*"',
        text,
        re.IGNORECASE,
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
    POST DownloadDialog.aspx with updateIDs body containing the GUID.
    """
    base_url = "https://www.catalog.update.microsoft.com/DownloadDialog.aspx"
    post_obj = {"size": 0, "updateID": guid, "uidInfo": guid}
    body = {"updateIDs": f"[{json.dumps(post_obj, separators=(',', ':'))}]"}
    return http_post_form(base_url, body)


def resolve_dialog_for_kb(kb: str, search_html: str, os_name: str, build: str, bitness: str) -> Optional[str]:
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
    Preference:
      - URLs containing "kb<id>"
      - URLs matching arch (x64/x86)
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
    Given KB ID (digits only), return a single URL for the .msu/.cab.
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


# ----------------------------------------------------------------------
# Download
# ----------------------------------------------------------------------

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


def main() -> None:
    # 1) Load scan result
    if not os.path.isfile(SCAN_RESULT_JSON):
        Fail(f"Scan result file not found: {SCAN_RESULT_JSON}\n"
             "Run winshield_scanner.py first.")

    with open(SCAN_RESULT_JSON, "r", encoding="utf-8") as f:
        scan = json.load(f)

    baseline = scan.get("baseline") or {}
    missing_kbs: List[str] = scan.get("missing_kbs") or []

    if not missing_kbs:
        Good("No missing KBs found in scan result – nothing to download.")
        return

    os_name = baseline.get("OSName", "Unknown Windows")
    build = str(baseline.get("Build") or baseline.get("FullBuild") or "0")
    arch = baseline.get("Architecture", "x64")
    # Make a bitness hint string that contains "64" or not
    bitness = "64-bit" if "64" in arch else "32-bit"

    Good(f"Loaded scan result for {os_name} ({build}, {arch})")
    Good(f"Missing KBs to download: {', '.join(missing_kbs)}")

    # 2) Download each missing KB
    for kb_full in missing_kbs:
        # kb_full is like "KB5066835" or "KB5068966"
        kb_digits = re.sub(r"[^0-9]", "", kb_full)
        if not kb_digits:
            Warn(f"Could not extract digits from KB ID '{kb_full}', skipping.")
            continue

        Info(f"Resolving download URL for {kb_full} (digits: {kb_digits})...")
        url = resolve_download_for_kb(kb_digits, os_name, build, bitness)
        if not url:
            Warn(f"{kb_full}: could not resolve download URL.")
            continue

        filename = os.path.basename(url.split("?", 1)[0])
        local_path = os.path.join(DOWNLOADS_DIR, f"{kb_full}_{filename}")

        Info(f"{kb_full}: downloading {filename} ...")
        size_bytes = download_file(url, local_path)
        if size_bytes is not None:
            size_mb = size_bytes / (1024 * 1024)
            Good(f"{kb_full}: downloaded to {local_path} ({size_mb:.1f} MB)")
        else:
            Warn(f"{kb_full}: download failed.")

    Good("Download phase complete. No installation was performed.")


if __name__ == "__main__":
    main()

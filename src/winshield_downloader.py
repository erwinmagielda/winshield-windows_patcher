"""
WinShield Downloader

Resolves and downloads a selected missing Windows update package
from the Microsoft Update Catalog based on baseline constraints.
"""

import json
import os
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import requests
from bs4 import BeautifulSoup


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(SCRIPT_DIR)

RESULTS_DIR = os.path.join(ROOT_DIR, "results")
DOWNLOADS_DIR = os.path.join(ROOT_DIR, "downloads")

SCAN_RESULT_PATH = os.path.join(RESULTS_DIR, "winshield_scan_result.json")

os.makedirs(RESULTS_DIR, exist_ok=True)
os.makedirs(DOWNLOADS_DIR, exist_ok=True)


CATALOG_BASE = "https://www.catalog.update.microsoft.com"
SEARCH_URL = f"{CATALOG_BASE}/Search.aspx"
DOWNLOAD_DIALOG_URL = f"{CATALOG_BASE}/DownloadDialog.aspx"

DEFAULT_TIMEOUT = 30


@dataclass(frozen=True)
class MissingKbItem:
    kb_id: str
    update_type: str


@dataclass(frozen=True)
class CatalogCandidate:
    update_id: str
    title: str
    products: str
    classification: str
    last_updated: str
    version: str
    size: str


@dataclass(frozen=True)
class BaselineConstraints:
    windows_gen: str
    display_version: str
    build_major: str
    catalog_arch: str


def load_scan_result(path: str) -> dict:
    """Load scanner output JSON from disk."""
    if not os.path.isfile(path):
        raise RuntimeError("Scan result not found. Run winshield_scanner.py first.")

    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def safe_input(prompt: str) -> str:
    """Read operator input without raising EOF errors."""
    try:
        return input(prompt)
    except EOFError:
        return ""


def build_constraints(baseline: dict) -> BaselineConstraints:
    """Derive catalog matching constraints from baseline metadata."""

    os_name = str(baseline.get("OsName") or "").lower()
    display_version = str(baseline.get("DisplayVersion") or "").strip()
    arch = str(baseline.get("Architecture") or "").lower()
    build = str(baseline.get("Build") or "")

    build_major = build.split(".", 1)[0] if build else ""

    if "windows 11" in os_name:
        windows_gen = "windows 11"
    elif "windows 10" in os_name:
        windows_gen = "windows 10"
    else:
        windows_gen = ""

    if arch in ("x64", "amd64"):
        catalog_arch = "x64"
    elif "arm64" in arch:
        catalog_arch = "arm64"
    elif arch in ("x86", "32-bit"):
        catalog_arch = "x86"
    else:
        catalog_arch = "x64"

    return BaselineConstraints(
        windows_gen=windows_gen,
        display_version=display_version,
        build_major=build_major,
        catalog_arch=catalog_arch,
    )


def build_session() -> requests.Session:
    """Create an HTTP session with stable headers."""
    s = requests.Session()
    s.headers.update(
        {
            "User-Agent": "winshield-downloader",
            "Accept-Language": "en-GB,en;q=0.9",
        }
    )
    return s


def fetch_text(session: requests.Session, url: str, params: dict | None = None) -> str:
    """Fetch HTML content and raise on HTTP errors."""
    r = session.get(url, params=params, timeout=DEFAULT_TIMEOUT)
    r.raise_for_status()
    return r.text


def build_missing_list(scan_result: dict) -> List[MissingKbItem]:
    """Build a display list of missing KBs with update type labels."""

    missing_kbs: List[str] = scan_result.get("MissingKbs") or []
    kb_entries: List[dict] = scan_result.get("KbEntries") or []

    kb_index: Dict[str, dict] = {
        str(e.get("KB")).upper(): e for e in kb_entries if e.get("KB")
    }

    out: List[MissingKbItem] = []
    for kb in missing_kbs:
        kb_id = str(kb).strip().upper()
        if not kb_id:
            continue

        update_type = str(kb_index.get(kb_id, {}).get("UpdateType") or "Unknown")
        out.append(MissingKbItem(kb_id=kb_id, update_type=update_type))

    return out


def parse_search_candidates(html: str) -> List[CatalogCandidate]:
    """Parse Microsoft Update Catalog search results into structured candidates."""

    soup = BeautifulSoup(html, "html.parser")
    table = soup.find("table", id="ctl00_catalogBody_updateMatches")
    if not table:
        return []

    candidates: List[CatalogCandidate] = []

    for tr in table.find_all("tr"):
        tr_id = (tr.get("id") or "").strip()
        if "_R" not in tr_id:
            continue

        update_id = tr_id.split("_R", 1)[0]
        if not re.fullmatch(r"[0-9a-fA-F-]{36}", update_id):
            continue

        tds = tr.find_all("td")
        if len(tds) < 8:
            continue

        candidates.append(
            CatalogCandidate(
                update_id=update_id,
                title=tds[1].get_text(" ", strip=True),
                products=tds[2].get_text(" ", strip=True),
                classification=tds[3].get_text(" ", strip=True),
                last_updated=tds[4].get_text(" ", strip=True),
                version=tds[5].get_text(" ", strip=True),
                size=tds[6].get_text(" ", strip=True),
            )
        )

    return candidates


def score_candidate(candidate: CatalogCandidate, kb_id: str, c: BaselineConstraints) -> int:
    """Score a catalog candidate against baseline constraints."""

    title = candidate.title.lower()
    score = 0

    if kb_id.lower() not in title:
        return -10_000
    score += 50

    if c.windows_gen:
        if c.windows_gen in title:
            score += 40
        if c.windows_gen == "windows 10" and "windows 11" in title:
            return -10_000
        if c.windows_gen == "windows 11" and "windows 10" in title:
            return -10_000

    if c.windows_gen.startswith("windows") and "server" in title:
        return -10_000

    if c.catalog_arch == "x64":
        if any(x in title for x in ("arm64-based", "x86-based", "32-bit")):
            return -10_000
        if "x64-based" in title:
            score += 25

    elif c.catalog_arch == "arm64":
        if any(x in title for x in ("x64-based", "x86-based", "32-bit")):
            return -10_000
        if "arm64-based" in title:
            score += 25

    elif c.catalog_arch == "x86":
        if any(x in title for x in ("x64-based", "arm64-based")):
            return -10_000
        if "x86-based" in title or "32-bit" in title:
            score += 25

    dv = c.display_version.lower()
    if dv:
        if dv in title:
            score += 25
        if re.search(r"\b\d{2}h[12]\b", title) and dv not in title:
            score -= 15

    if c.build_major:
        m = re.search(r"\(\s*(\d{5})\.", title)
        if m:
            score += 10 if m.group(1) == c.build_major else -5

    return score


def choose_best_candidate(
    candidates: List[CatalogCandidate],
    kb_id: str,
    constraints: BaselineConstraints,
) -> Tuple[Optional[CatalogCandidate], Optional[str]]:
    """Select the highest confidence candidate or return a reason for failure."""

    scored = [(score_candidate(c, kb_id, constraints), c) for c in candidates]
    scored = [(s, c) for s, c in scored if s >= 0]

    if not scored:
        return None, "No candidate matched baseline constraints."

    scored.sort(key=lambda x: x[0], reverse=True)
    best_score, best = scored[0]

    if best_score < 90:
        return None, f"Ambiguous match below confidence threshold ({best_score})."

    return best, None


def build_dialog_params(update_id: str) -> dict:
    """Build parameters for the Update Catalog download dialog."""
    payload = f'[{{"size":0,"languages":"all","uidInfo":"{update_id}","updateID":"{update_id}"}}]'
    return {"updateIDs": payload}


def extract_download_urls(html: str) -> List[str]:
    """Extract direct .msu or .cab URLs from download dialog HTML."""

    urls = re.findall(
        r"https?://[^\"]+\.(?:msu|cab)(?:\?[^\"]*)?",
        html,
        flags=re.IGNORECASE,
    )

    seen: set[str] = set()
    out: List[str] = []

    for u in urls:
        if u not in seen:
            seen.add(u)
            out.append(u)

    return out


def download_file(session: requests.Session, url: str, out_dir: str) -> str:
    """Download a resolved update package to disk."""

    filename = url.split("/")[-1].split("?", 1)[0]
    out_path = os.path.join(out_dir, filename)

    with session.get(url, stream=True, timeout=DEFAULT_TIMEOUT) as r:
        r.raise_for_status()
        with open(out_path, "wb") as h:
            for chunk in r.iter_content(chunk_size=1024 * 256):
                if chunk:
                    h.write(chunk)

    return out_path


def main() -> int:
    print("[*] Running WinShield downloader")

    scan_result = load_scan_result(SCAN_RESULT_PATH)
    constraints = build_constraints(scan_result.get("Baseline") or {})

    missing_items = build_missing_list(scan_result)
    if not missing_items:
        print("[+] No missing KBs")
        return 0

    print("=== Missing KBs ===")
    for i, item in enumerate(missing_items, start=1):
        print(f"{i}) {item.kb_id} [{item.update_type}]")
    print()

    raw = safe_input("Select KB: ").strip()
    if not raw.isdigit():
        print("[!] Invalid selection")
        return 1

    idx = int(raw)
    if idx < 1 or idx > len(missing_items):
        print("[!] Selection out of range")
        return 1

    kb_id = missing_items[idx - 1].kb_id
    session = build_session()

    print(f"[*] Searching catalog for {kb_id}")
    html = fetch_text(session, SEARCH_URL, params={"q": kb_id})

    candidates = parse_search_candidates(html)
    best, reason = choose_best_candidate(candidates, kb_id, constraints)

    if not best:
        print(f"[!] {reason}")
        return 1

    print(f"[+] Selected: {best.title}")
    dialog_html = fetch_text(session, DOWNLOAD_DIALOG_URL, params=build_dialog_params(best.update_id))
    urls = extract_download_urls(dialog_html)

    if not urls:
        print("[!] No download URL found")
        return 1

    out_path = download_file(session, urls[0], DOWNLOADS_DIR)
    print(f"[+] Downloaded to {out_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

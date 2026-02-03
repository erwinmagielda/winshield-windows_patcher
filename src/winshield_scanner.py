"""
WinShield Scanner

Core engine that correlates installed Windows updates with MSRC CVRF data.
Executes PowerShell collectors, resolves expected KBs, and determines patch posture.
"""

import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from typing import Dict, List, Set, Tuple


BASELINE_SCRIPT = "winshield_baseline.ps1"
INVENTORY_SCRIPT = "winshield_inventory.ps1"
ADAPTER_SCRIPT = "winshield_adapter.ps1"


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(SCRIPT_DIR)

RESULTS_DIR = os.path.join(ROOT_DIR, "results")
DOWNLOADS_DIR = os.path.join(ROOT_DIR, "downloads")

SCAN_RESULT_PATH = os.path.join(RESULTS_DIR, "winshield_scan_result.json")

os.makedirs(RESULTS_DIR, exist_ok=True)
os.makedirs(DOWNLOADS_DIR, exist_ok=True)


def run_powershell_script(script_name: str, extra_args: List[str] | None = None) -> dict:
    """Execute a PowerShell script and parse its JSON output."""

    args = extra_args or []
    script_path = os.path.join(SCRIPT_DIR, script_name)

    cmd = [
        "powershell.exe",
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", script_path,
        *args,
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        raise RuntimeError(f"{script_name} execution failed")

    stdout = result.stdout.strip()
    if not stdout:
        raise RuntimeError(f"{script_name} returned no output")

    try:
        return json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{script_name} returned invalid JSON") from exc


def build_month_ids_from_lcu(baseline: dict, max_months: int = 48) -> List[str]:
    """Build a MonthId range from installed LCU up to the latest MSRC month."""

    if not baseline.get("IsAdmin"):
        raise RuntimeError("Baseline collected without administrative privileges")

    start_id = baseline.get("LcuMonthId")
    if not start_id:
        raise RuntimeError("Baseline did not provide LcuMonthId")

    end_id = baseline.get("MsrcLatestMonthId")
    end = (
        datetime.strptime(end_id, "%Y-%b").replace(day=1, tzinfo=UTC)
        if end_id
        else datetime.now(UTC).replace(day=1)
    )

    start = datetime.strptime(start_id, "%Y-%b").replace(day=1, tzinfo=UTC)
    if start > end:
        start = end

    month_ids: List[str] = []
    year, month = start.year, start.month

    while True:
        current = datetime(year, month, 1, tzinfo=UTC)
        if current > end or len(month_ids) >= max_months:
            break

        month_ids.append(current.strftime("%Y-%b"))

        if current == end:
            break

        month += 1
        if month == 13:
            month = 1
            year += 1

    return month_ids


def chunk_list(items: List[str], size: int) -> List[List[str]]:
    return [items[i:i + size] for i in range(0, len(items), size)]


def merge_kb_entries(existing: Dict[str, dict], incoming: List[dict]) -> None:
    """Merge adapter KB entries into an indexed structure."""

    for entry in incoming:
        kb_id = entry.get("KB")
        if not kb_id:
            continue

        target = existing.setdefault(
            kb_id,
            {"KB": kb_id, "Months": [], "Cves": [], "Supersedes": []},
        )

        for field in ("Months", "Cves", "Supersedes"):
            for value in entry.get(field) or []:
                if value and value not in target[field]:
                    target[field].append(value)


def compute_supersedence(
    kb_entries: List[dict], installed_kbs: Set[str]
) -> Tuple[Set[str], Dict[str, List[str]]]:
    """Expand logical KB presence using supersedence relationships."""

    supersedes_map: Dict[str, Set[str]] = {}

    for entry in kb_entries:
        kb_id = entry.get("KB")
        for old in entry.get("Supersedes") or []:
            supersedes_map.setdefault(kb_id, set()).add(old)

    logical_present = set(installed_kbs)
    superseded_by: Dict[str, Set[str]] = {}

    for root in installed_kbs:
        stack = [root]
        seen = {root}

        while stack:
            current = stack.pop()
            for old in supersedes_map.get(current, set()):
                logical_present.add(old)
                superseded_by.setdefault(old, set()).add(root)
                if old not in seen:
                    seen.add(old)
                    stack.append(old)

    return logical_present, {k: sorted(v) for k, v in superseded_by.items()}


def print_kb_table(
    kb_entries: List[dict],
    installed_kbs: Set[str],
    logical_present_kbs: Set[str],
    superseded_by: Dict[str, List[str]],
) -> None:



    kb_index: Dict[str, dict] = {}
    for entry in kb_entries:
        if entry.get("KB"):
            kb_index[entry["KB"]] = entry


    all_kbs = sorted(set(kb_index.keys()) | set(installed_kbs) | set(logical_present_kbs))

    col_kb_width = 11
    col_type_width = 12
    col_status_width = 40
    col_months_width = 20

    print("=== Correlation ===")
    print(
        f"{'KB':<{col_kb_width}} "
        f"{'Type':<{col_type_width}} "
        f"{'Status':<{col_status_width}} "
        f"{'Months':<{col_months_width}} "
        f"CVEs"
    )
    print("-" * 110)

    for kb_id in all_kbs:
        entry = kb_index.get(kb_id)
        if entry is None:
            entry = {
                "KB": kb_id,
                "Months": [],
                "Cves": [],
                "Supersedes": [],
                "UpdateType": "Unmapped",
            }

        months = list(entry.get("Months") or [])
        cves = list(entry.get("Cves") or [])
        update_type = entry.get("UpdateType", "")

        if kb_id in installed_kbs:
            status = "Installed"
        elif kb_id in logical_present_kbs:
            by = superseded_by.get(kb_id, [])
            status = f"Superseded ({', '.join(by)})" if by else "Superseded"
        else:
            status = "Missing"

        if not months:
            months = [""]
        if not cves:
            cves = [""]

        height = max(len(months), len(cves))

        for i in range(height):
            kb_cell = kb_id if i == 0 else ""
            type_cell = update_type if i == 0 else ""
            status_cell = status if i == 0 else ""
            month_cell = months[i] if i < len(months) else ""
            cve_cell = cves[i] if i < len(cves) else ""

            print(
                f"{kb_cell:<{col_kb_width}} "
                f"{type_cell:<{col_type_width}} "
                f"{status_cell:<{col_status_width}} "
                f"{month_cell:<{col_months_width}} "
                f"{cve_cell}"
            )

        print("-" * 110)


def main() -> None:
    print("[*] Collecting baseline...")
    baseline = run_powershell_script(BASELINE_SCRIPT)

    product_name_hint = baseline.get("ProductNameHint")
    if not product_name_hint:
        print("[!] Failed to resolve ProductNameHint")
        sys.exit(1)

    print(f"[+] {baseline.get('OsName')} {baseline.get('DisplayVersion')} ({baseline.get('Build')})")
    print(f"[+] Product: {product_name_hint}")
    print()

    print("[*] Collecting inventory...")
    inventory = run_powershell_script(INVENTORY_SCRIPT)
    installed_kbs = set(inventory.get("AllInstalledKbs") or [])
    print(f"[+] Installed KBs: {len(installed_kbs)}")
    print()

    print("[*] Building MonthId range...")
    month_ids = build_month_ids_from_lcu(baseline)
    print(f"[+] Months: {', '.join(month_ids)}")
    print()

    merged: Dict[str, dict] = {}
    months_with_entries: List[str] = []

    print("[*] Querying MSRC...")
    for chunk in chunk_list(month_ids, 3):
        msrc_data = run_powershell_script(
            ADAPTER_SCRIPT,
            extra_args=[
                "-MonthIds", ",".join(chunk),
                "-ProductNameHint", product_name_hint,
            ],
        )

        entries = msrc_data.get("KbEntries") or []
        if entries:
            months_with_entries.extend(chunk)
            merge_kb_entries(merged, entries)

    if not merged:
        print("[!] No KB data returned")
        sys.exit(0)

    kb_entries = list(merged.values())

    for e in kb_entries:
        e["Months"] = sorted(set(e.get("Months") or []))
        e["Cves"] = sorted(set(e.get("Cves") or []))
        e["Supersedes"] = sorted(set(e.get("Supersedes") or []))
        e["UpdateType"] = "Superseding" if e["Supersedes"] else "Standalone"

    logical_present, superseded_by = compute_supersedence(kb_entries, installed_kbs)

    expected = {e["KB"] for e in kb_entries}
    missing = sorted(expected - logical_present)

    print()
    print("=== Summary ===")
    print(f"Expected KBs: {len(expected)}")
    print(f"Missing KBs:  {len(missing)}")
    print()

    print_kb_table(
        kb_entries=kb_entries,
        installed_kbs=installed_kbs,
        logical_present_kbs=logical_present,
        superseded_by=superseded_by,
    )

    print()
    print("=== Missing ===")
    if not missing:
        print("None")
    else:
        for kb in missing:
            entry = next((e for e in kb_entries if e.get("KB") == kb), {})
            months = ", ".join(entry.get("Months") or [])
            cve_count = len(entry.get("Cves") or [])
            print(f"- {kb} | Months: {months}, CVEs: {cve_count}")

    result = {
        "Baseline": baseline,
        "InstalledKbs": sorted(installed_kbs),
        "MonthsRequested": month_ids,
        "MonthsWithEntries": sorted(set(months_with_entries)),
        "KbEntries": sorted(kb_entries, key=lambda x: x["KB"]),
        "MissingKbs": missing,
    }

    with open(SCAN_RESULT_PATH, "w", encoding="utf-8") as h:
        json.dump(result, h, indent=2)

    print()
    print(f"[+] Saved scan result to {SCAN_RESULT_PATH}")


if __name__ == "__main__":
    raise SystemExit(main())

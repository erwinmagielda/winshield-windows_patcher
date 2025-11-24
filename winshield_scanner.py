import json
import os
import subprocess
import sys
from datetime import datetime, UTC
from typing import Dict, List, Set

# PowerShell scripts used by the scanner
BASELINE_SCRIPT = "winshield_baseline.ps1"
INVENTORY_SCRIPT = "winshield_inventory.ps1"
ADAPTER_SCRIPT = "winshield_adapter.ps1"

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# Directory for all JSON result artefacts
RESULTS_DIR = os.path.join(SCRIPT_DIR, "results")
os.makedirs(RESULTS_DIR, exist_ok=True)

SCAN_RESULT_PATH = os.path.join(RESULTS_DIR, "winshield_scan_result.json")


def run_powershell_script(script_name: str, extra_args: List[str] | None = None) -> dict:
    """
    Execute a PowerShell script located in SCRIPT_DIR and parse JSON from stdout.

    :param script_name: Name of the PowerShell script file.
    :param extra_args:  Additional command line arguments to pass to PowerShell.
    :return: Parsed JSON object as a Python dict.
    :raises RuntimeError: if the script returns non-zero exit code or invalid JSON.
    """
    if extra_args is None:
        extra_args = []

    script_path = os.path.join(SCRIPT_DIR, script_name)

    cmd = [
        "powershell.exe",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        script_path,
        *extra_args,
    ]

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"Script {script_name} failed with code {result.returncode}\n"
            f"STDOUT:\n{result.stdout}\n\nSTDERR:\n{result.stderr}"
        )

    stdout = result.stdout.strip()
    if not stdout:
        raise RuntimeError(f"Script {script_name} returned empty stdout")

    try:
        return json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"Failed to parse JSON from {script_name}: {exc}\nRaw output:\n{stdout}"
        ) from exc


def build_month_ids_from_lcu(
    baseline: dict,
    max_months: int = 48,
) -> List[str]:
    """
    Build a chronological list of month identifiers starting from the LCU month.

    The list is inclusive of the LCU month and continues forward until the current
    calendar month (UTC), or until max_months is reached.

    Requirements:
      - Baseline must indicate that it was collected as Administrator.
      - Baseline must contain a valid LCU_MonthId in 'YYYY-MMM' format.

    :param baseline: Baseline dictionary produced by winshield_baseline.ps1.
    :param max_months: Safety limit for the number of months to include.
    :return: A list of month identifiers in 'YYYY-MMM' format.
    """
    if not baseline.get("IsAdmin"):
        raise RuntimeError(
            "WinShield baseline was collected without administrative privileges.\n"
            "LCU detection relies on Get-WindowsPackage, which only returns data in an elevated session.\n"
            "Please rerun winshield_scanner.py from an elevated PowerShell window."
        )

    lcu_month_id = baseline.get("LCU_MonthId")
    if not lcu_month_id:
        raise RuntimeError(
            "Baseline did not provide LCU_MonthId.\n"
            "This indicates that winshield_baseline.ps1 did not map the latest cumulative update.\n"
            "Run winshield_lcu_debug.ps1 as Administrator and adjust LCU detection in winshield_baseline.ps1."
        )

    now = datetime.now(UTC).replace(day=1)

    try:
        start = datetime.strptime(lcu_month_id, "%Y-%b").replace(day=1, tzinfo=UTC)
    except ValueError as exc:
        raise RuntimeError(
            f"LCU_MonthId '{lcu_month_id}' is not in 'YYYY-MMM' format: {exc}.\n"
            "Fix LCU_MonthId formatting in winshield_baseline.ps1."
        ) from exc

    if start > now:
        raise RuntimeError(
            f"LCU_MonthId '{lcu_month_id}' is in the future compared to the current month.\n"
            "This is likely a bug in winshield_baseline.ps1 LCU handling."
        )

    year = start.year
    month = start.month
    month_ids: List[str] = []

    while True:
        current = datetime(year, month, 1, tzinfo=UTC)
        if current > now:
            break

        month_ids.append(current.strftime("%Y-%b"))

        if current == now or len(month_ids) >= max_months:
            break

        month += 1
        if month == 13:
            month = 1
            year += 1

    return month_ids


def print_kb_table(
    kb_entries: List[dict],
    installed_kbs: Set[str],
    logical_present_kbs: Set[str],
) -> None:
    """
    Print a text based KB table with four logical columns:

        KB | Status | Months | CVEs

    - Months and CVEs are printed over multiple lines when necessary.
    - All CVEs are printed (no truncation).
    """
    kb_index: Dict[str, dict] = {entry["KB"]: entry for entry in kb_entries if "KB" in entry}

    header_kb = "KB"
    header_status = "Status"
    header_months = "Months"
    header_cves = "CVEs"

    col_kb_width = 10
    col_status_width = 10
    col_months_width = 18

    print("=== KB status (per MSRC, for these months) ===")
    print(
        f"{header_kb:<{col_kb_width}} "
        f"{header_status:<{col_status_width}} "
        f"{header_months:<{col_months_width}} "
        f"{header_cves}"
    )
    print("-" * 80)

    for kb in sorted(kb_index.keys()):
        entry = kb_index[kb]
        months_list = list(entry.get("Months") or [])
        cve_list = list(entry.get("Cves") or [])

        if kb in installed_kbs:
            status = "Installed"
        elif kb in logical_present_kbs:
            status = "Superseded"
        else:
            status = "Missing"

        if not months_list:
            months_list = [""]
        if not cve_list:
            cve_list = [""]

        row_height = max(len(months_list), len(cve_list))

        for i in range(row_height):
            kb_cell = kb if i == 0 else ""
            status_cell = status if i == 0 else ""
            month_cell = months_list[i] if i < len(months_list) else ""
            cve_cell = cve_list[i] if i < len(cve_list) else ""

            print(
                f"{kb_cell:<{col_kb_width}} "
                f"{status_cell:<{col_status_width}} "
                f"{month_cell:<{col_months_width}} "
                f"{cve_cell}"
            )

        print("-" * 80)


def main() -> None:
    # ------------------------------------------------------------------
    # Baseline
    # ------------------------------------------------------------------
    print("[*] Running baseline script...")
    baseline = run_powershell_script(BASELINE_SCRIPT)

    os_name = baseline.get("OSName")
    os_version = baseline.get("DisplayVersion")
    full_build = baseline.get("FullBuild")
    product_hint = baseline.get("ProductNameHint")
    lcu_month_id = baseline.get("LCU_MonthId")
    lcu_kb_id = baseline.get("LCU_KB")

    if not product_hint:
        print("[-] Baseline did not provide ProductNameHint, cannot query MSRC.")
        sys.exit(1)

    print(f"[+] OS: {os_name} {os_version} ({full_build})")
    print(f"[+] ProductNameHint: {product_hint}")
    print(f"[+] LCU month: {lcu_month_id or 'None'}")
    if lcu_kb_id:
        print(f"[+] LCU KB: {lcu_kb_id}")
    else:
        print("[-] LCU KB could not be parsed from package metadata.")
    print(f"[+] Baseline collected as admin: {baseline.get('IsAdmin')}")
    print()

    # ------------------------------------------------------------------
    # Inventory (installed KBs)
    # ------------------------------------------------------------------
    print("[*] Running inventory script...")
    inventory = run_powershell_script(INVENTORY_SCRIPT)
    installed_kb_set: Set[str] = set(inventory.get("AllInstalledKbs") or [])
    print(f"[+] Installed KBs ({len(installed_kb_set)}): {', '.join(sorted(installed_kb_set))}")
    print()

    # ------------------------------------------------------------------
    # MSRC month range: strictly LCU -> current month
    # ------------------------------------------------------------------
    month_ids = build_month_ids_from_lcu(baseline)
    print("[*] Building MSRC month range from LCU to now:")
    print(f"    {', '.join(month_ids)}")
    print()

    extra_args = ["-MonthIds", *month_ids, "-ProductNameHint", product_hint]
    print("[*] Querying adapter for aggregated KB data...")
    msrc_data = run_powershell_script(ADAPTER_SCRIPT, extra_args=extra_args)

    msrc_kb_entries: List[dict] = msrc_data.get("KbEntries") or []
    if not msrc_kb_entries:
        print("[-] Adapter returned no KB entries for the selected months and product. Nothing to compare.")
        sys.exit(0)

    print(f"[+] Adapter returned {len(msrc_kb_entries)} KB entries for this product.")
    print()

    # ------------------------------------------------------------------
    # Supersedence map: KB -> set of KBs it supersedes
    # ------------------------------------------------------------------
    supersedes_map: Dict[str, Set[str]] = {}
    for entry in msrc_kb_entries:
        kb_id = entry.get("KB")
        if not kb_id:
            continue
        for superseded in (entry.get("Supersedes") or []):
            supersedes_map.setdefault(kb_id, set()).add(superseded)

    expected_security_kbs: Set[str] = {entry["KB"] for entry in msrc_kb_entries if "KB" in entry}

    logical_present_kbs: Set[str] = set(installed_kb_set)

    changed = True
    while changed:
        changed = False
        for kb_id in list(logical_present_kbs):
            for superseded in supersedes_map.get(kb_id, set()):
                if superseded not in logical_present_kbs:
                    logical_present_kbs.add(superseded)
                    changed = True

    present_kbs_sorted = sorted(expected_security_kbs & logical_present_kbs)
    missing_kbs_sorted = sorted(expected_security_kbs - logical_present_kbs)

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    print()
    print("=== Summary ===")
    print(f"Total security KBs from adapter for {product_hint}: {len(expected_security_kbs)}")
    print(f"Installed or superseded (logical present): {len(present_kbs_sorted)}")
    print(f"Missing from MSRC set: {len(missing_kbs_sorted)}")
    print()

    # ------------------------------------------------------------------
    # Detailed KB table (4 columns, multi-line months and CVEs)
    # ------------------------------------------------------------------
    print_kb_table(
        kb_entries=msrc_kb_entries,
        installed_kbs=installed_kb_set,
        logical_present_kbs=logical_present_kbs,
    )

    # ------------------------------------------------------------------
    # Missing KBs list (high level view)
    # ------------------------------------------------------------------
    print()
    print("=== Missing KBs that WinShield could download or inspect next ===")
    if not missing_kbs_sorted:
        print("No missing KBs from the MSRC set for the selected months.")
    else:
        kb_index: Dict[str, dict] = {entry["KB"]: entry for entry in msrc_kb_entries if "KB" in entry}
        for kb_id in missing_kbs_sorted:
            entry = kb_index.get(kb_id, {})
            months = ",".join(entry.get("Months") or [])
            cves = entry.get("Cves") or []
            print(f"- {kb_id} (months: {months}, CVEs: {len(set(cves))})")

    # ------------------------------------------------------------------
    # Export machine readable result for downloader / installer
    # ------------------------------------------------------------------
    scan_result = {
        "baseline": baseline,
        "installed_kbs": sorted(installed_kb_set),
        "months": month_ids,
        "kb_entries": msrc_kb_entries,
        "missing_kbs": missing_kbs_sorted,
    }

    with open(SCAN_RESULT_PATH, "w", encoding="utf-8") as handle:
        json.dump(scan_result, handle, indent=2)

    print()
    print(f"[+] Saved detailed scan result to {SCAN_RESULT_PATH}")


if __name__ == "__main__":
    try:
        main()
        exit_code = 0
    except Exception as exc:
        print(f"[X] Fatal error: {exc}")
        exit_code = 1

    sys.exit(exit_code)

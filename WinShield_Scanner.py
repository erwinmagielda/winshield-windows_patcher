import json
import os
import subprocess
import sys
from datetime import datetime, UTC

# PowerShell scripts – USE EXACT FILENAMES YOU ACTUALLY RUN
BASELINE_SCRIPT = "winshield_baseline.ps1"
INVENTORY_SCRIPT = "winshield_inventory.ps1"
MSRC_ADAPTER_SCRIPT = "winshield_msrc_adapter.ps1"

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def run_powershell_script(script_name: str, extra_args=None) -> dict:
    """
    Run a PowerShell script (from SCRIPT_DIR) and return parsed JSON from stdout.
    Raises RuntimeError on non-zero exit or invalid JSON.
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
    except json.JSONDecodeError as e:
        raise RuntimeError(
            f"Failed to parse JSON from {script_name}: {e}\nRaw output:\n{stdout}"
        )


def _fallback_month_ids(num_months: int = 6) -> list[str]:
    """
    Fallback: generate MonthIds (YYYY-MMM) going backwards one REAL month
    at a time from the current month. Only used if LCU info is broken/missing.
    """
    now = datetime.now(UTC).replace(day=1)
    year = now.year
    month = now.month
    month_ids: list[str] = []

    for _ in range(num_months):
        dt = datetime(year, month, 1, tzinfo=UTC)
        month_ids.append(dt.strftime("%Y-%b"))

        month -= 1
        if month == 0:
            month = 12
            year -= 1

    return month_ids


def build_month_ids_from_lcu(
    baseline: dict,
    fallback_months: int = 6,
    max_months: int = 18,
) -> list[str]:

    """
    Correct LCU→Now month range generator.

    - Start at LCU month.
    - Walk FORWARD month-by-month until *REAL CURRENT MONTH*.
    - NEVER produce a future month (prevents 2025-Dec issue).
    """

    lcu_month_id = baseline.get("LCU_MonthId")
    now = datetime.now(UTC).replace(day=1)

    if not lcu_month_id:
        return _fallback_month_ids(num_months=fallback_months)

    try:
        start = datetime.strptime(lcu_month_id, "%Y-%b").replace(day=1, tzinfo=UTC)
    except ValueError:
        return _fallback_month_ids(num_months=fallback_months)

    # Fix: if start is in the future → fallback
    if start > now:
        return _fallback_month_ids(num_months=fallback_months)

    year = start.year
    month = start.month
    month_ids: list[str] = []

    while True:
        dt = datetime(year, month, 1, tzinfo=UTC)

        # Don't allow future months
        if dt > now:
            break

        month_ids.append(dt.strftime("%Y-%b"))

        # Stop if we reached current month or hit safety cap
        if dt == now or len(month_ids) >= max_months:
            break

        # next month
        month += 1
        if month == 13:
            month = 1
            year += 1

    return month_ids


def main():
    # ------------------------------------------------------------------
    # Baseline
    # ------------------------------------------------------------------
    print("[*] Running baseline script...")
    baseline = run_powershell_script(BASELINE_SCRIPT)
    product_hint = baseline.get("ProductNameHint")

    if not product_hint:
        print("[-] Baseline did not provide ProductNameHint, cannot query MSRC.")
        sys.exit(1)

    print(f"[+] Product hint: {product_hint}")
    print(
        f"[+] OS: {baseline.get('OSName')} "
        f"{baseline.get('DisplayVersion')} "
        f"({baseline.get('FullBuild')})"
    )
    print(f"[+] LCU_MonthId: {baseline.get('LCU_MonthId')}")
    print()

    # ------------------------------------------------------------------
    # Inventory (installed KBs)
    # ------------------------------------------------------------------
    print("[*] Running inventory script...")
    inventory = run_powershell_script(INVENTORY_SCRIPT)
    installed_kbs = set(inventory.get("AllInstalledKbs") or [])
    print(f"[+] Installed KBs ({len(installed_kbs)}): {', '.join(sorted(installed_kbs))}")
    print()

    # ------------------------------------------------------------------
    # MSRC month range: strictly LCU → now (with small safety fallback)
    # ------------------------------------------------------------------
    month_ids = build_month_ids_from_lcu(baseline, fallback_months=6)
    print(f"[*] Querying MSRC for months: {', '.join(month_ids)}")

    extra_args = ["-MonthIds", *month_ids, "-ProductNameHint", product_hint]
    msrc_data = run_powershell_script(MSRC_ADAPTER_SCRIPT, extra_args=extra_args)

    kb_entries = msrc_data.get("KbEntries") or []
    if not kb_entries:
        print("[-] MSRC adapter returned no KB entries. Nothing to compare.")
        sys.exit(0)

    # ------------------------------------------------------------------
    # Supersedence map: KB -> set of KBs it supersedes
    # ------------------------------------------------------------------
    supersedes_map: dict[str, set[str]] = {}
    for entry in kb_entries:
        kb = entry.get("KB")
        if not kb:
            continue
        for sup in (entry.get("Supersedes") or []):
            supersedes_map.setdefault(kb, set()).add(sup)

    expected_kbs = {entry["KB"] for entry in kb_entries if "KB" in entry}

    # logical_present = installed KBs + anything they supersede (transitively)
    logical_present = set(installed_kbs)

    changed = True
    while changed:
        changed = False
        for kb in list(logical_present):
            for superseded in supersedes_map.get(kb, set()):
                if superseded not in logical_present:
                    logical_present.add(superseded)
                    changed = True

    present_kbs = sorted(expected_kbs & logical_present)
    missing_kbs = sorted(expected_kbs - logical_present)

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    print()
    print("=== Summary ===")
    print(f"Total expected KBs from MSRC for {product_hint}: {len(expected_kbs)}")
    print(f"Installed (from that set): {len(present_kbs)}")
    print(f"Missing   (from that set): {len(missing_kbs)}")
    print()

    kb_index = {entry["KB"]: entry for entry in kb_entries if "KB" in entry}

    def format_cve_list(cves, max_show=5) -> str:
        if not cves:
            return "0"
        cves = sorted(set(cves))
        if len(cves) <= max_show:
            return f"{len(cves)} ({', '.join(cves)})"
        head = ", ".join(cves[:max_show])
        return f"{len(cves)} ({head}, ...)"

    print("=== KB status (per MSRC, for these months) ===")
    print(f"{'KB':<10} {'Status':<10} {'Months':<15} {'CVEs'}")
    print("-" * 80)

    for kb in sorted(expected_kbs):
        entry = kb_index.get(kb, {})
        months = ",".join(entry.get("Months") or [])
        cves = entry.get("Cves") or []

        if kb in installed_kbs:
            status = "Installed"
        elif kb in logical_present:
            status = "Superseded"
        else:
            status = "Missing"

        cve_display = format_cve_list(cves, max_show=3)
        print(f"{kb:<10} {status:<10} {months:<15} {cve_display}")

    # ------------------------------------------------------------------
    # Missing KBs list (for downloader)
    # ------------------------------------------------------------------
    print()
    print("=== Missing KBs that WinShield could download/patch next ===")
    if not missing_kbs:
        print("No missing KBs from the MSRC set for selected months. 🎉")
    else:
        for kb in missing_kbs:
            entry = kb_index.get(kb, {})
            months = ",".join(entry.get("Months") or [])
            cves = entry.get("Cves") or []
            print(f"- {kb} (months: {months}, CVEs: {len(set(cves))})")

    # ------------------------------------------------------------------
    # Export machine-readable result for downloader / installer
    # ------------------------------------------------------------------
    result = {
        "baseline": baseline,
        "installed_kbs": sorted(installed_kbs),
        "months": month_ids,
        "kb_entries": kb_entries,
        "missing_kbs": missing_kbs,
    }

    out_path = os.path.join(SCRIPT_DIR, "winshield_scan_result.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    print()
    print(f"[+] Saved detailed scan result to {out_path}")


if __name__ == "__main__":
    try:
        main()
        exit_code = 0
    except Exception as e:
        print(f"[!] Fatal error: {e}")
        exit_code = 1
    finally:
        # Always pause so you can read the output
        try:
            input("\nPress Enter to close this window...")
        except EOFError:
            # In case input is not available (called from another script)
            pass
        sys.exit(exit_code)

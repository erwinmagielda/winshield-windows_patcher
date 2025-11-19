import json
import subprocess
import sys
from datetime import datetime, timedelta, UTC


# Adjust these if your script names differ
BASELINE_SCRIPT = "WinShield_Baseline.ps1"
INVENTORY_SCRIPT = "winshield_inventory.ps1"
MSRC_ADAPTER_SCRIPT = "winshield_msrc_adapter.ps1"


def run_powershell_script(script_name, extra_args=None):
    """
    Run a PowerShell script and return parsed JSON from stdout.
    Raises RuntimeError on non zero exit or invalid JSON.
    """
    if extra_args is None:
        extra_args = []

    cmd = [
        "powershell.exe",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        script_name,
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


def generate_month_ids(num_months=1):
    """
    Generate MSRC month IDs like '2025-Nov', going backwards from current month.
    """
    now = datetime.now(UTC).replace(day=1)
    month_ids = []

    for i in range(num_months):
        dt = now - timedelta(days=31 * i)
        # Normalize back to first of month
        dt = dt.replace(day=1)
        month_id = dt.strftime("%Y-%b")  # example: 2025-Nov
        month_ids.append(month_id)

    # Remove duplicates in case timedelta produced same month twice
    seen = set()
    ordered = []
    for mid in month_ids:
        if mid not in seen:
            seen.add(mid)
            ordered.append(mid)

    return ordered

def main():
    print("[*] Running baseline script...")
    baseline = run_powershell_script(BASELINE_SCRIPT)
    product_hint = baseline.get("ProductNameHint")

    if not product_hint:
        print("[-] Baseline did not provide ProductNameHint, cannot query MSRC.")
        sys.exit(1)

    print(f"[+] Product hint: {product_hint}")
    print(f"[+] OS: {baseline.get('OSName')} {baseline.get('DisplayVersion')} ({baseline.get('FullBuild')})")
    print()

    print("[*] Running inventory script...")
    inventory = run_powershell_script(INVENTORY_SCRIPT)
    installed_kbs = set(inventory.get("AllInstalledKbs") or [])
    print(f"[+] Installed KBs ({len(installed_kbs)}): {', '.join(sorted(installed_kbs))}")
    print()

    # For now, look at last 1 month of MSRC bulletins
    month_ids = generate_month_ids(num_months=1)
    print(f"[*] Querying MSRC for months: {', '.join(month_ids)}")

    extra_args = ["-MonthIds", *month_ids, "-ProductNameHint", product_hint]
    msrc_data = run_powershell_script(MSRC_ADAPTER_SCRIPT, extra_args=extra_args)

    kb_entries = msrc_data.get("KbEntries") or []
    if not kb_entries:
        print("[-] MSRC adapter returned no KB entries. Nothing to compare.")
        sys.exit(0)

    # --- build supersedence map: KB -> set of KBs it supersedes ---
    supersedes_map: dict[str, set[str]] = {}
    for entry in kb_entries:
        kb = entry.get("KB")
        if not kb:
            continue
        for sup in (entry.get("Supersedes") or []):
            supersedes_map.setdefault(kb, set()).add(sup)

    # --- build sets ---
    expected_kbs = {entry["KB"] for entry in kb_entries if "KB" in entry}

    # Logical presence: installed KBs + any KBs they supersede (transitively)
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

    print()
    print("=== Summary ===")
    print(f"Total expected KBs from MSRC for {product_hint}: {len(expected_kbs)}")
    print(f"Installed (from that set): {len(present_kbs)}")
    print(f"Missing (from that set):   {len(missing_kbs)}")
    print()

    # Build easy lookup for KB -> entry data
    kb_index = {entry["KB"]: entry for entry in kb_entries if "KB" in entry}

    def format_cve_list(cves, max_show=5):
        if not cves:
            return "0"
        cves = sorted(set(cves))
        if len(cves) <= max_show:
            return f"{len(cves)} ({', '.join(cves)})"
        else:
            head = ", ".join(cves[:max_show])
            return f"{len(cves)} ({head}, ...)"

    # Pretty print table
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
            # Not physically installed, but superseded by an installed CU
            status = "Superseded"
        else:
            status = "Missing"

        cve_display = format_cve_list(cves, max_show=3)
        print(f"{kb:<10} {status:<10} {months:<15} {cve_display}")

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

    out_path = "winshield_scan_result.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    print()
    print(f"[+] Saved detailed scan result to {out_path}")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"[!] Fatal error: {e}")
        sys.exit(1)

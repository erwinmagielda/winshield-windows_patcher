# WinShield_Manager.py
"""
WinShield Manager (skeleton)

This script will eventually:
- Work off a single scan snapshot (one .json file)
- Present table with KB entries and an ID column
- Allow operations by ID (not by raw KB number)
- Provide verification (fresh scan vs snapshot), install, uninstall

For now it:
- Loads the given snapshot
- Prints a short summary and the KB table with IDs
"""

import json
import os
import sys
from typing import Any, Dict, List

try:
    from rich.console import Console
    from rich.table import Table

    console = Console()
    RICH_AVAILABLE = True
except Exception:
    RICH_AVAILABLE = False

    class DummyConsole:
        def print(self, *args, **kwargs):
            text = " ".join(str(a) for a in args)
            print(text)

    console = DummyConsole()


def Fail(msg: str) -> None:
    if RICH_AVAILABLE:
        console.print(f"[X] {msg}", style="red")
    else:
        print(f"[X] {msg}")
    sys.exit(1)


def load_snapshot(path: str) -> Dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8-sig") as fh:
            return json.load(fh)
    except Exception as exc:
        Fail(f"Failed to load snapshot '{path}': {exc!r}")


def display_summary(snapshot: Dict[str, Any]) -> None:
    system_tag = snapshot.get("system_tag", "unknown")
    scan_date = snapshot.get("scan_date", "unknown date")
    summary = snapshot.get("summary", {})
    catalog_total = summary.get("catalog_kbs_total", "n/a")
    installed_local = summary.get("installed_kbs_local_total", "n/a")
    installed_in_catalog = summary.get("installed_kbs_in_catalog", "n/a")
    missing_count = summary.get("missing_kbs_count", "n/a")

    if RICH_AVAILABLE:
        console.print(f"WinShield Manager - snapshot [{system_tag}] ({scan_date})", style="bold cyan")
        console.print(
            f"Catalog KBs: {catalog_total} | "
            f"Installed (local): {installed_local} | "
            f"Installed in catalog: {installed_in_catalog} | "
            f"Missing: {missing_count}"
        )
    else:
        print(f"WinShield Manager - snapshot [{system_tag}] ({scan_date})")
        print(
            f"Catalog KBs: {catalog_total} | "
            f"Installed (local): {installed_local} | "
            f"Installed in catalog: {installed_in_catalog} | "
            f"Missing: {missing_count}"
        )


def display_kb_table(snapshot: Dict[str, Any]) -> None:
    kb_details: List[Dict[str, Any]] = snapshot.get("kb_details") or []
    if not kb_details:
        console.print("No KB entries in this snapshot.")
        return

    table = Table(
        title="KB entries (ID based selection will use this table)",
        show_header=True,
        header_style="bold magenta",
    )
    table.add_column("ID", style="dim", width=4)
    table.add_column("KB")
    table.add_column("Status", width=10)
    table.add_column("CVEs (first few)")

    for idx, kb in enumerate(kb_details, start=1):
        kb_str = f"KB{kb.get('kb')}"
        status = kb.get("status", "Unknown")
        cves = kb.get("cves") or []

        status_style = "bold red" if status == "Missing" else "bold green"
        status_text = f"[{status_style}]{status}[/{status_style}]"

        if cves:
            cve_text = ", ".join(cves[:3])
            if len(cves) > 3:
                cve_text += " ..."
        else:
            cve_text = "N/A"

        table.add_row(str(idx), kb_str, status_text, cve_text)

    console.print(table)


def main() -> None:
    if len(sys.argv) < 2:
        Fail("WinShield_Manager requires a snapshot path argument.")

    snapshot_path = sys.argv[1]
    if not os.path.isfile(snapshot_path):
        Fail(f"Snapshot file not found: {snapshot_path}")

    snapshot = load_snapshot(snapshot_path)
    display_summary(snapshot)
    print()
    display_kb_table(snapshot)

    # Placeholder: future interactive manager menu will go here.
    # It will:
    #   - let the user pick an option (verify, view missing, view installed, patch operations)
    #   - operate by ID (table index) rather than forcing them to type KB numbers

    if RICH_AVAILABLE:
        console.print("\n[dim]Manager skeleton complete. Interactive features will be added later.[/dim]")
    else:
        print("\nManager skeleton complete. Interactive features will be added later.")


if __name__ == "__main__":
    main()

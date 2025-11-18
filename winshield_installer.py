# WinShield_Installer.py

import json
import os
import re
import subprocess
import sys
from typing import Any, Dict, List

from rich.console import Console
from rich.table import Table

script_directory = os.path.dirname(os.path.abspath(__file__))
downloads_directory = os.path.join(script_directory, "downloads")

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


def discover_downloaded_packages(kb_entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not os.path.isdir(downloads_directory):
        warn(f"Downloads directory not found: {downloads_directory}")
        return []

    kb_status_map = {
        str(entry.get("kb")): entry.get("status", "Unknown")
        for entry in kb_entries
    }

    discovered_packages: List[Dict[str, Any]] = []

    for file_name in os.listdir(downloads_directory):
        full_path = os.path.join(downloads_directory, file_name)
        if not os.path.isfile(full_path):
            continue

        match = re.match(r"KB(\d+)_", file_name, re.IGNORECASE)
        if not match:
            continue

        kb_number = match.group(1)
        file_extension = os.path.splitext(file_name)[1].lower()
        if file_extension not in (".cab", ".msu"):
            continue

        package_entry = {
            "kb": kb_number,
            "path": full_path,
            "ext": file_extension,
            "snapshot_status": kb_status_map.get(kb_number, "Unknown"),
        }
        discovered_packages.append(package_entry)

    for index, package_entry in enumerate(discovered_packages, start=1):
        package_entry["id"] = index

    return discovered_packages


def display_packages_table(package_entries: List[Dict[str, Any]]) -> None:
    if not package_entries:
        warn("No downloaded KB packages found in ./downloads.")
        return

    table = Table(
        title="Downloaded KB packages",
        show_header=True,
        header_style="bold magenta",
    )
    table.add_column("ID", style="dim", width=4)
    table.add_column("KB")
    table.add_column("File")
    table.add_column("Type", width=6)
    table.add_column("Snapshot status", width=12)

    for package_entry in package_entries:
        table.add_row(
            str(package_entry["id"]),
            f"KB{package_entry['kb']}",
            os.path.basename(package_entry["path"]),
            package_entry["ext"].lstrip(".").upper(),
            package_entry["snapshot_status"],
        )

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


def install_single_package(package_entry: Dict[str, Any]) -> bool:
    package_path = package_entry["path"]
    file_extension = package_entry["ext"]

    if file_extension == ".msu":
        command_arguments = ["wusa.exe", package_path, "/quiet", "/norestart"]
        info(f"KB{package_entry['kb']}: running wusa.exe on {os.path.basename(package_path)}")
    elif file_extension == ".cab":
        command_arguments = [
            "dism.exe",
            "/online",
            "/add-package",
            f"/packagepath:{package_path}",
            "/quiet",
            "/norestart",
        ]
        info(f"KB{package_entry['kb']}: running DISM on {os.path.basename(package_path)}")
    else:
        warn(f"KB{package_entry['kb']}: unsupported file type '{file_extension}', skipping.")
        return False

    try:
        process_result = subprocess.run(command_arguments)
        return_code = process_result.returncode
    except Exception as exception:
        warn(f"KB{package_entry['kb']}: installation failed to start: {exception!r}")
        return False

    if return_code == 0:
        good(f"KB{package_entry['kb']}: installation completed successfully.")
        return True

    warn(f"KB{package_entry['kb']}: installer exited with code {return_code}.")
    return False


def install_package_list(package_entries: List[Dict[str, Any]]) -> None:
    if not package_entries:
        warn("No packages selected for installation.")
        return

    good(f"Preparing to install {len(package_entries)} package(s)...")
    warn("Make sure this script is running in an elevated (Administrator) command prompt.")

    successful_count = 0
    total_count = len(package_entries)

    for package_entry in package_entries:
        installation_result = install_single_package(package_entry)
        if installation_result:
            successful_count += 1

    good(f"Installation run complete. {successful_count}/{total_count} packages reported success.")


def main() -> None:
    if len(sys.argv) < 2:
        fail("Usage: WinShield_Installer.py <snapshot.json>")

    snapshot_path = sys.argv[1]
    snapshot_data = load_snapshot(snapshot_path)

    kb_entries: List[Dict[str, Any]] = snapshot_data.get("kb_details") or []
    if not kb_entries:
        fail("Snapshot does not contain 'kb_details'; was it created by WinShield_Scanner v3?")

    system_tag = snapshot_data.get("system_tag", "unknown")
    scan_date = snapshot_data.get("scan_date", "unknown")

    console.print("========= WinShield Installer =========", style="bold cyan")
    console.print(
        f"[dim]Snapshot:[/dim] {os.path.basename(snapshot_path)}  "
        f"[dim]System:[/dim] {system_tag}  [dim]Scan date:[/dim] {scan_date}\n"
    )

    while True:
        package_entries = discover_downloaded_packages(kb_entries)

        console.print("1) Show downloaded packages")
        console.print("2) Install ALL downloaded packages")
        console.print("3) Install packages by ID")
        console.print("4) Exit")
        menu_choice = input("> ").strip()

        if menu_choice == "1":
            display_packages_table(package_entries)
            continue

        if menu_choice == "2":
            if not package_entries:
                warn("No downloaded packages found.")
            else:
                display_packages_table(package_entries)
                confirmation = input("Install ALL listed packages? (y/n): ").strip().lower()
                if confirmation == "y":
                    install_package_list(package_entries)
            continue

        if menu_choice == "3":
            if not package_entries:
                warn("No downloaded packages found.")
                continue

            display_packages_table(package_entries)
            maximum_id = len(package_entries)
            id_text = input(
                f"Enter ID(s) to install (1-{maximum_id}, e.g. '1 3 5' or '2-4'): "
            ).strip()
            if not id_text:
                continue

            selected_ids = parse_id_list(id_text, maximum_id)
            if not selected_ids:
                warn("No valid IDs entered. Cancelling selection.")
                continue

            selected_packages = [entry for entry in package_entries if entry["id"] in selected_ids]
            if not selected_packages:
                warn("No packages matched the selected IDs.")
            else:
                install_package_list(selected_packages)
            continue

        if menu_choice == "4":
            good("Exiting WinShield Installer.")
            break

        break


if __name__ == "__main__":
    main()

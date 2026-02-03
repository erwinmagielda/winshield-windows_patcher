# WinShield

Windows patch posture and update correlation tool built around MSRC CVRF data and the Microsoft Update Catalog.

## What It Is
WinShield is a local analysis tool that inspects installed Windows updates, correlates them against official Microsoft Security Response Center data, and identifies missing, installed, and superseded KBs for a specific system.

It is designed as an operator facing tool rather than a background scanner.

## Why It Exists
Patch state visibility on Windows systems is often fragmented across multiple tools and interfaces.  
WinShield provides a deterministic, auditable view of patch posture by:

- grounding expected updates in MSRC CVRF data
- anchoring analysis to the installed LCU
- resolving supersedence chains explicitly
- keeping all logic local and transparent

## How It Works
WinShield follows a simple, staged workflow:

1. **Baseline**  
   Collects OS version, build, architecture, LCU anchor, and resolves the MSRC product name.

2. **Inventory**  
   Enumerates installed KBs using Get-HotFix and Get-WindowsPackage.

3. **Correlation**  
   Pulls CVRF data from MSRC for the relevant month range and aggregates expected KBs.

4. **Analysis**  
   Expands supersedence relationships to determine logical presence and missing updates.

5. **Remediation**  
   Optionally downloads and installs selected missing updates from the Microsoft Update Catalog.

## Usage

Run the interactive entry point:

```bash
python winshield_master.py

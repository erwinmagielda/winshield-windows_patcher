# WinShield

WinShield is a Windows patch posture analysis tool that correlates installed updates with official MSRC CVRF data to identify installed, superseded, and missing KBs on a local system.

It is designed as an operator facing utility rather than a background or enterprise scale scanner.

## Overview
Windows patch state is often fragmented across multiple interfaces and tools.
WinShield provides a deterministic and auditable view of patch posture by anchoring analysis to the installed LCU and resolving expected updates directly from MSRC data.

The goal is clarity and trust in what the system should have installed versus what is actually present.

## Workflow
WinShield operates in a fixed, staged pipeline:

1. **Baseline collection**  
   Identifies OS version, build, architecture, LCU anchor, and resolves the MSRC product name.

2. **Inventory collection**  
   Enumerates installed KBs using Get-HotFix and Get-WindowsPackage.

3. **MSRC correlation**  
   Pulls CVRF data for the relevant month range and aggregates expected KBs.

4. **Supersedence analysis**  
   Expands supersedence chains to determine logical presence of older updates.

5. **Remediation support**  
   Allows optional download and installation of selected missing updates.

## Usage
Run the interactive entry point:

```bash
python winshield_master.py
```

The menu allows you to:
- scan the system
- download missing updates
- install downloaded updates

Administrator privileges are required for full functionality.

## Output
The primary output is a terminal table showing correlated patch state, including:

- KB identifier
- update type
- installation status (Installed, Superseded, Missing)
- applicable months
- associated CVEs

A full machine readable result is also written to:

```
results/winshield_scan_result.json
```

This file contains baseline data, inventory, correlation results, and missing KBs.

## Scope and Safety
- Intended for authorised systems only
- No exploit code or active vulnerability probing
- All data sources are official Microsoft endpoints
- Update installation is explicit and operator controlled

## Implementation
- Python is used for orchestration and correlation logic
- PowerShell is used for Windows native data collection
- MSRC CVRF data and the Microsoft Update Catalog are treated as authoritative sources

## Project Status
WinShield is maintained as a portfolio and research project.

The implementation prioritises clarity, determinism, and auditability over automation at scale.

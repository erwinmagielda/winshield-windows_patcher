# WinShield

Windows patch posture and update correlation tool for local security analysis.

## What It Is
WinShield is a local inspection tool that analyses installed Windows updates and correlates them against Microsoft Security Response Center data. It identifies missing, installed, and superseded updates for a specific system in a deterministic and auditable way.

## Why It Exists
Patch visibility on Windows systems is fragmented across multiple tools. WinShield exists to provide a single, transparent view of patch posture by grounding expectations in authoritative security data rather than opaque update states.

## Pipeline Overview
1. System baseline collection  
2. Installed update inventory enumeration  
3. Security advisory correlation  
4. Supersedence resolution logic  
5. Optional update retrieval and installation  

## Project Structure
```
winshield/
├── src/
│   ├── winshield_master.py
│   ├── baseline.py
│   ├── inventory.py
│   ├── downloader.py
│   ├── installer.py
│   └── adapter.py
│
├── results/       # Scan output files
├── downloads/     # Retrieved updates (ignored)
├── README.md
└── .gitignore
```

## Usage
Run the interactive entry point:

```bash
python src/winshield_master.py
```

The menu allows you to:
- Scan system patch state  
- Download missing updates  
- Install selected updates  

## Data Sources
WinShield relies on:
- Microsoft Security Response Center CVRF data  
- Microsoft Update Catalog metadata  

All correlation logic is performed locally.

## Security Notes
WinShield performs system inspection and update handling locally. No data is transmitted externally beyond official Microsoft endpoints.

## Status
Active development tool.

## Licence
MIT

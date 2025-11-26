<#
.SYNOPSIS
    WinShield MSRC adapter

.DESCRIPTION
    Bridges the MSRC PowerShell module and the Python scanner.

    - Accepts:
        -MonthIds <list or comma-separated string>
        -ProductNameHint "<string from baseline>"

    - For each MonthId:
        * Loads the CVRF document
        * Extracts affected software rows for the given ProductNameHint
        * Aggregates KB entries with:
            - KB ID
            - Months (list of MonthIds where this KB appears)
            - Cves  (list of CVE/ADV IDs)
            - Supersedes (list of KB IDs it supersedes, derived from Supercedence field)

    - Emits a single JSON object to stdout:

        {
          "ProductName": "<ProductNameHint>",
          "MonthIds": [ "2023-May", "2023-Jun", ... ],
          "KbEntries": [
            {
              "KB": "KB5026361",
              "Months": [ "2023-May" ],
              "Cves": [ "CVE-2023-24900", ... ],
              "Supersedes": [ "KB5014032", ... ]
            },
            ...
          ]
        }
#>

# --------------------------------------------------------------------
# Manual argument parsing to avoid quoting quirks
# --------------------------------------------------------------------

$MonthIds = @()
$ProductNameHint = $null

for ($i = 0; $i -lt $args.Count; $i++) {
    switch -Regex ($args[$i]) {

        '^-MonthIds$' {
            # Collect all subsequent non-flag arguments as MonthIds
            $i++
            while ($i -lt $args.Count -and $args[$i] -notmatch '^-') {
                $MonthIds += $args[$i]
                $i++
            }
            $i--
            continue
        }

        '^-ProductNameHint$' {
            $i++
            if ($i -lt $args.Count) {
                $ProductNameHint = $args[$i]
            }
            continue
        }

        default { }
    }
}

if (-not $MonthIds -or -not $ProductNameHint) {
    [pscustomobject]@{
        Error   = "Usage: winshield_adapter.ps1 -MonthIds <list> -ProductNameHint <name>"
        RawArgs = $args
    } | ConvertTo-Json -Depth 5
    exit 1
}

# Normalise MonthIds:
#  - Support separate arguments: 2023-May 2023-Jun
#  - Support comma separated:   "2023-May,2023-Jun"
$normMonths = @()
foreach ($m in $MonthIds) {
    if (-not $m) { continue }
    $parts = $m -split ","
    foreach ($p in $parts) {
        $val = $p.Trim()
        if ($val) {
            $normMonths += $val
        }
    }
}

$MonthIds = $normMonths | Sort-Object -Unique

# --------------------------------------------------------------------
# Load MSRC module
# --------------------------------------------------------------------
try {
    Import-Module -Name MsrcSecurityUpdates -ErrorAction Stop
} catch {
    [pscustomobject]@{
        Error   = "Failed to load MsrcSecurityUpdates"
        Details = $_.Exception.Message
    } | ConvertTo-Json -Depth 5
    exit 1
}

# --------------------------------------------------------------------
# Aggregate KB entries across all months
# --------------------------------------------------------------------
$kbMap = @{}

foreach ($month in $MonthIds) {

    try {
        $doc = Get-MsrcCvrfDocument -ID $month -ErrorAction Stop
        $aff = Get-MsrcCvrfAffectedSoftware -Vulnerability $doc.Vulnerability -ProductTree $doc.ProductTree
    } catch {
        # If MSRC has no document for the given ID, or retrieval fails, skip this month.
        continue
    }

    # Only rows that match our product hint
    $rows = $aff | Where-Object { $_.FullProductName -like "*$ProductNameHint*" }
    if (-not $rows) { continue }

    foreach ($row in $rows) {

        # CVE list normalisation
        $cveList = @()
        if ($row.CVE) {
            if ($row.CVE -is [System.Collections.IEnumerable] -and -not ($row.CVE -is [string])) {
                $cveList = @($row.CVE)
            } else {
                $cveList = @($row.CVE)
            }
        }

        # Supersedence normalisation
        $supers = @()
        if ($row.Supercedence) {
            foreach ($s in $row.Supercedence) {
                if ($null -ne $s) {
                    $str = [string]$s
                    if ($str -match '(\d{4,7})') {
                        $supers += "KB$($Matches[1])"
                    }
                }
            }
        }

        # KB Article processing
        if ($row.KBArticle) {
            foreach ($kbObj in $row.KBArticle) {
                if (-not $kbObj.ID) { continue }

                $kb = if ($kbObj.ID -like "KB*") { $kbObj.ID } else { "KB$($kbObj.ID)" }

                if (-not $kbMap.ContainsKey($kb)) {
                    $kbMap[$kb] = [pscustomobject]@{
                        KB         = $kb
                        Months     = @()
                        Cves       = @()
                        Supersedes = @()
                    }
                }

                # Track all months where this KB appears
                if ($kbMap[$kb].Months -notcontains $month) {
                    $kbMap[$kb].Months += $month
                }

                # Aggregate CVEs
                foreach ($c in $cveList) {
                    if ($kbMap[$kb].Cves -notcontains $c) {
                        $kbMap[$kb].Cves += $c
                    }
                }

                # Aggregate superseded KBs
                foreach ($s in $supers) {
                    if ($kbMap[$kb].Supersedes -notcontains $s) {
                        $kbMap[$kb].Supersedes += $s
                    }
                }
            }
        }
    }
}

[pscustomobject]@{
    ProductName = $ProductNameHint
    MonthIds    = $MonthIds
    KbEntries   = ($kbMap.GetEnumerator() | ForEach-Object { $_.Value } | Sort-Object KB)
} | ConvertTo-Json -Depth 10

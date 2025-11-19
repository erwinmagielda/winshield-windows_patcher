<#
.SYNOPSIS
WinShield MSRC adapter (multi month, CVEs from affected software rows)

- Requires MsrcSecurityUpdates module (MSRC API client)
- For given MonthIds and ProductNameHint, returns:
  - KBs for that product across those months
  - per KB list of CVEs (taken directly from Get-MsrcCvrfAffectedSoftware rows)
- Emits JSON for WinShield (Python) to consume
#>

param(
    [Parameter(Mandatory = $true)]
    [string[]]$MonthIds,        # e.g. '2025-Nov','2025-Oct'

    [Parameter(Mandatory = $true)]
    [string]$ProductNameHint    # e.g. 'Windows 11 Version 25H2 for x64-based Systems'
)

# --- Load MSRC module ---
try {
    Import-Module -Name MsrcSecurityUpdates -ErrorAction Stop
} catch {
    [pscustomobject]@{
        Error           = "Failed to load MsrcSecurityUpdates module"
        ProductNameHint = $ProductNameHint
        MonthIds        = $MonthIds
        Details         = $_.Exception.Message
    } | ConvertTo-Json -Depth 4
    exit 1
}

# Map: KB -> object { KB, Months[], Cves[] }
$kbMap = @{}

foreach ($month in $MonthIds) {

    try {
        $doc = Get-MsrcCvrfDocument -ID $month -ErrorAction Stop
        $aff = Get-MsrcCvrfAffectedSoftware -Vulnerability $doc.Vulnerability -ProductTree $doc.ProductTree
    } catch {
        $kbMap["__ERROR__$month"] = [pscustomobject]@{
            KB     = $null
            Months = @($month)
            Cves   = @()
            Error  = "Failed to query MSRC for month ${month}: $($_.Exception.Message)"
        }
        continue
    }

    # Only rows for our product
    $rows = $aff | Where-Object {
        $_.FullProductName -like "*$ProductNameHint*"
    }

    if (-not $rows) { continue }

    foreach ($row in $rows) {

        # Normalise CVE to an array
        $cveList = @()
        if ($row.CVE) {
            if ($row.CVE -is [System.Collections.IEnumerable] -and -not ($row.CVE -is [string])) {
                $cveList = @($row.CVE)
            } else {
                $cveList = @($row.CVE)
            }
        }

        # For each KB in KBArticle, attach those CVEs
        if ($row.KBArticle) {
            foreach ($kbObj in $row.KBArticle) {
                if (-not $kbObj.ID) { continue }

                $kid   = $kbObj.ID
                $kbNorm = if ($kid -like 'KB*') { $kid } else { "KB$kid" }

                if (-not $kbMap.ContainsKey($kbNorm)) {
                    $kbMap[$kbNorm] = [pscustomobject]@{
                        KB     = $kbNorm
                        Months = @()
                        Cves   = @()
                    }
                }

                # Month
                if ($kbMap[$kbNorm].Months -notcontains $month) {
                    $kbMap[$kbNorm].Months += $month
                }

                # CVEs
                foreach ($c in $cveList) {
                    if ($c -and $kbMap[$kbNorm].Cves -notcontains $c) {
                        $kbMap[$kbNorm].Cves += $c
                    }
                }
            }
        }
    }
}

# Build final list
$kbList = $kbMap.GetEnumerator() |
    Where-Object { $_.Key -notlike '__ERROR__*' } |
    ForEach-Object { $_.Value } |
    Sort-Object KB

[pscustomobject]@{
    ProductName = $ProductNameHint
    MonthIds    = $MonthIds
    KbEntries   = $kbList
} | ConvertTo-Json -Depth 6

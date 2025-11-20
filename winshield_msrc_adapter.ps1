<#
.SYNOPSIS
    WinShield MSRC adapter (multi month, CVEs + supersedence)

.DESCRIPTION
    - Requires MsrcSecurityUpdates module (MSRC API client)
    - For given MonthIds and ProductNameHint, returns:
        * KBs for that product across those months
        * per-KB list of CVEs (from affected software rows)
        * per-KB list of Supersedes (KBs this KB replaces)
    - Emits JSON for WinShield (Python) to consume

.PARAMETER MonthIds
    Can be passed as:
        -MonthIds 2025-Nov 2025-Oct 2025-Sep
    or
        -MonthIds "2025-Nov,2025-Oct,2025-Sep"

.PARAMETER ProductNameHint
    MSRC product name, e.g. "Windows 11 Version 25H2 for x64-based Systems".
#>

param(
    [Parameter(Mandatory = $true)]
    [string[]]$MonthIds,

    [Parameter(Mandatory = $true)]
    [string]$ProductNameHint
)

# -------------------------------------------------------------------
# Normalize MonthIds (support array + comma-separated)
# -------------------------------------------------------------------
$flatMonths = @()

foreach ($m in $MonthIds) {
    if ($null -eq $m) { continue }
    # If someone passed "2025-Nov,2025-Oct", split on comma
    $parts = $m -split '\s*,\s*'
    foreach ($p in $parts) {
        if ($p -and $p.Trim() -ne "") {
            $flatMonths += $p.Trim()
        }
    }
}

$MonthIds = $flatMonths | Select-Object -Unique

# -------------------------------------------------------------------
# Load MSRC module
# -------------------------------------------------------------------
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

# Map: KB -> object { KB, Months[], Cves[], Supersedes[] }
$kbMap = @{}

foreach ($month in $MonthIds) {
    if (-not $month) { continue }

    try {
        $doc = Get-MsrcCvrfDocument -ID $month -ErrorAction Stop
        $aff = Get-MsrcCvrfAffectedSoftware -Vulnerability $doc.Vulnerability -ProductTree $doc.ProductTree
    } catch {
        # Store the error for this month but continue with others
        $kbMap["__ERROR__$month"] = [pscustomobject]@{
            KB         = $null
            Months     = @($month)
            Cves       = @()
            Supersedes = @()
            Error      = "Failed to query MSRC for month ${month}: $($_.Exception.Message)"
        }
        continue
    }

    # Only rows for our product
    $rows = $aff | Where-Object {
        $_.FullProductName -like "*$ProductNameHint*"
    }

    if (-not $rows) { continue }

    foreach ($row in $rows) {

        # --- CVEs ---------------------------------------------------
        $cveList = @()
        if ($row.CVE) {
            if ($row.CVE -is [System.Collections.IEnumerable] -and -not ($row.CVE -is [string])) {
                $cveList = @($row.CVE)
            } else {
                $cveList = @($row.CVE)
            }
        }

        # --- Supersedence: values like {, 5066835, , ...} ----------
        $supersededCandidates = @()
        if ($row.PSObject.Properties.Name -contains 'Supercedence' -and $row.Supercedence) {
            foreach ($s in $row.Supercedence) {
                if ($null -eq $s) { continue }
                $sStr = [string]$s
                if ($sStr -match '(\d{4,7})') {
                    $supersededCandidates += ("KB" + $Matches[1])
                }
            }
        }

        # --- Per KB in KBArticle -----------------------------------
        if ($row.KBArticle) {
            foreach ($kbObj in $row.KBArticle) {
                if (-not $kbObj.ID) { continue }

                $kid    = $kbObj.ID
                $kbNorm = if ($kid -like 'KB*') { $kid } else { "KB$kid" }

                if (-not $kbMap.ContainsKey($kbNorm)) {
                    $kbMap[$kbNorm] = [pscustomobject]@{
                        KB         = $kbNorm
                        Months     = @()
                        Cves       = @()
                        Supersedes = @()
                    }
                }

                # Month membership
                if ($kbMap[$kbNorm].Months -notcontains $month) {
                    $kbMap[$kbNorm].Months += $month
                }

                # CVEs
                foreach ($c in $cveList) {
                    if ($c -and $kbMap[$kbNorm].Cves -notcontains $c) {
                        $kbMap[$kbNorm].Cves += $c
                    }
                }

                # Supersedes (KBs this KB replaces)
                foreach ($sup in $supersededCandidates) {
                    if ($kbMap[$kbNorm].Supersedes -notcontains $sup) {
                        $kbMap[$kbNorm].Supersedes += $sup
                    }
                }
            }
        }
    }
}

# -------------------------------------------------------------------
# Build final list and output JSON
# -------------------------------------------------------------------
$kbList = $kbMap.GetEnumerator() |
    Where-Object { $_.Key -notlike '__ERROR__*' } |
    ForEach-Object { $_.Value } |
    Sort-Object KB

[pscustomobject]@{
    ProductName = $ProductNameHint
    MonthIds    = $MonthIds
    KbEntries   = $kbList
} | ConvertTo-Json -Depth 6

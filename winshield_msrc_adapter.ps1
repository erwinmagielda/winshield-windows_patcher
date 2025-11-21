<#
.SYNOPSIS
WinShield MSRC adapter (stable multi-month version)

- Accepts multiple MonthIds via proper PowerShell binding
- Queries MSRC module for each month
- Filters by ProductNameHint
- Returns KB list with CVEs + Supersedes
- Fully JSON safe
#>

param(
    [Parameter(Mandatory = $true)]
    [string[]]$MonthIds,

    [Parameter(Mandatory = $true)]
    [string]$ProductNameHint
)

# --- Normalise MonthIds ---
# Accepts:
#   -MonthIds 2025-Nov 2025-Oct
#   -MonthIds "2025-Nov,2025-Oct,2025-Sep"
#   or any mix of the above
$normMonths = @()
foreach ($m in $MonthIds) {
    if (-not $m) { continue }
    $parts = $m -split ","
    foreach ($p in $parts) {
        $val = $p.Trim()
        if ($val) { $normMonths += $val }
    }
}
$MonthIds = $normMonths | Select-Object -Unique

# --- Load module ---
try {
    Import-Module -Name MsrcSecurityUpdates -ErrorAction Stop
} catch {
    [pscustomobject]@{
        Error   = "Failed to load MsrcSecurityUpdates"
        Details = $_.Exception.Message
    } | ConvertTo-Json -Depth 5
    exit 1
}

# KB map
$kbMap = @{}

foreach ($month in $MonthIds) {

    # Query MSRC
    try {
        $doc = Get-MsrcCvrfDocument -ID $month -ErrorAction Stop
        $aff = Get-MsrcCvrfAffectedSoftware -Vulnerability $doc.Vulnerability -ProductTree $doc.ProductTree
    } catch {
        continue
    }

    # Rows matching our ProductNameHint
    $rows = $aff | Where-Object { $_.FullProductName -like "*$ProductNameHint*" }
    if (-not $rows) { continue }

    foreach ($row in $rows) {
        # CVE list normalize
        $cveList = @()
        if ($row.CVE) {
            if ($row.CVE -is [System.Collections.IEnumerable] -and -not ($row.CVE -is [string])) {
                $cveList = @($row.CVE)
            } else {
                $cveList = @($row.CVE)
            }
        }

        # Supersedence cleanup
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

        # KBArticle processing
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

                if ($kbMap[$kb].Months -notcontains $month) {
                    $kbMap[$kb].Months += $month
                }

                foreach ($c in $cveList) {
                    if ($kbMap[$kb].Cves -notcontains $c) {
                        $kbMap[$kb].Cves += $c
                    }
                }

                foreach ($s in $supers) {
                    if ($kbMap[$kb].Supersedes -notcontains $s) {
                        $kbMap[$kb].Supersedes += $s
                    }
                }
            }
        }
    }
}

# Output JSON
[pscustomobject]@{
    ProductName = $ProductNameHint
    MonthIds    = $MonthIds
    KbEntries   = ($kbMap.GetEnumerator() | ForEach-Object { $_.Value } | Sort-Object KB)
} | ConvertTo-Json -Depth 10

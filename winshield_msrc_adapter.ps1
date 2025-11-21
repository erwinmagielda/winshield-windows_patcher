<#
.SYNOPSIS
    WinShield MSRC adapter (manual arg parser, multi-month safe)

.DESCRIPTION
    - Accepts multiple MonthIds from CLI (Python or manual):
        winshield_msrc_adapter.ps1 -MonthIds 2025-Nov 2025-Oct ...
      or:
        winshield_msrc_adapter.ps1 -MonthIds "2025-Nov,2025-Oct,2025-Sep" ...
    - Accepts ProductNameHint
    - Queries MsrcSecurityUpdates for each month
    - Filters by ProductNameHint
    - Returns KB list with CVEs and Supersedes as JSON
#>

# -------------------------------------------------------------
# Manual argument parsing to avoid PowerShell param binding quirks
# -------------------------------------------------------------

$MonthIds = @()
$ProductNameHint = $null

for ($i = 0; $i -lt $args.Count; $i++) {
    switch -Regex ($args[$i]) {

        '^-MonthIds$' {
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
        Error  = "Usage: winshield_msrc_adapter.ps1 -MonthIds <list> -ProductNameHint <name>"
        RawArgs = $args
    } | ConvertTo-Json -Depth 5
    exit 1
}

# -------------------------------------------------------------
# Normalise MonthIds: split on commas, trim, dedupe
# -------------------------------------------------------------

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

# -------------------------------------------------------------
# Load MSRC module
# -------------------------------------------------------------

try {
    Import-Module -Name MsrcSecurityUpdates -ErrorAction Stop
} catch {
    [pscustomobject]@{
        Error   = "Failed to load MsrcSecurityUpdates"
        Details = $_.Exception.Message
    } | ConvertTo-Json -Depth 5
    exit 1
}

# -------------------------------------------------------------
# Build KB map for all months
# -------------------------------------------------------------

$kbMap = @{}

foreach ($month in $MonthIds) {

    try {
        $doc = Get-MsrcCvrfDocument -ID $month -ErrorAction Stop
        $aff = Get-MsrcCvrfAffectedSoftware -Vulnerability $doc.Vulnerability -ProductTree $doc.ProductTree
    } catch {
        continue
    }

    $rows = $aff | Where-Object { $_.FullProductName -like "*$ProductNameHint*" }
    if (-not $rows) { continue }

    foreach ($row in $rows) {

        $cveList = @()
        if ($row.CVE) {
            if ($row.CVE -is [System.Collections.IEnumerable] -and -not ($row.CVE -is [string])) {
                $cveList = @($row.CVE)
            } else {
                $cveList = @($row.CVE)
            }
        }

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

[pscustomobject]@{
    ProductName = $ProductNameHint
    MonthIds    = $MonthIds
    KbEntries   = ($kbMap.GetEnumerator() | ForEach-Object { $_.Value } | Sort-Object KB)
} | ConvertTo-Json -Depth 10

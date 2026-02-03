<#
.SYNOPSIS
    WinShield Adapter

.DESCRIPTION
    Aggregates MSRC CVRF data for a specific Windows product across one or more MonthIds.
    Emits a JSON object consumed by winshield_scanner.py.
#>

param(
    [Parameter(Mandatory = $true)]
    [string[]]$MonthIds,

    [Parameter(Mandatory = $true)]
    [string]$ProductNameHint
)

# ------------------------------------------------------------
# INPUT NORMALISATION
# ------------------------------------------------------------

$MonthIds = @(
    $MonthIds |
        ForEach-Object { $_ -split "," } |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ }
) | Sort-Object -Unique

if (-not $MonthIds -or -not $ProductNameHint) {
    [pscustomobject]@{
        Error           = "Invalid arguments"
        MonthIds        = $MonthIds
        ProductNameHint = $ProductNameHint
    } | ConvertTo-Json -Depth 5
    exit 1
}

# ------------------------------------------------------------
# MODULE DEPENDENCY
# ------------------------------------------------------------

try {
    Import-Module MsrcSecurityUpdates -ErrorAction Stop
} catch {
    [pscustomobject]@{
        Error   = "Failed to load MsrcSecurityUpdates"
        Details = $_.Exception.Message
    } | ConvertTo-Json -Depth 5
    exit 1
}

# ------------------------------------------------------------
# AGGREGATION CONTAINER
# ------------------------------------------------------------

$kbMap = @{}

# ------------------------------------------------------------
# PER-MONTH PROCESSING
# ------------------------------------------------------------

foreach ($month in $MonthIds) {

    try {
        $doc = Get-MsrcCvrfDocument -ID $month -ErrorAction Stop
        $aff = Get-MsrcCvrfAffectedSoftware `
            -Vulnerability $doc.Vulnerability `
            -ProductTree $doc.ProductTree
    } catch {
        continue
    }

    if (-not $aff) { continue }

    $rows = $aff | Where-Object { $_.FullProductName -eq $ProductNameHint }
    if (-not $rows) { continue }

    foreach ($row in $rows) {

        $cveList = @()
        if ($row.CVE) {
            $cveList = @($row.CVE)
        }

        $supersedes = @()
        if ($row.Supercedence) {
            foreach ($s in @($row.Supercedence)) {
                if ($s -and $s -match '(\d{4,7})') {
                    $supersedes += "KB$($Matches[1])"
                }
            }
        }
        $supersedes = $supersedes | Sort-Object -Unique

        foreach ($kbObj in @($row.KBArticle)) {
            if (-not $kbObj -or -not $kbObj.ID) { continue }

            $kb = if ($kbObj.ID -like 'KB*') {
                $kbObj.ID
            } else {
                "KB$($kbObj.ID)"
            }

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
                if ($c -and $kbMap[$kb].Cves -notcontains $c) {
                    $kbMap[$kb].Cves += $c
                }
            }

            foreach ($s in $supersedes) {
                if ($s -and $kbMap[$kb].Supersedes -notcontains $s) {
                    $kbMap[$kb].Supersedes += $s
                }
            }
        }
    }
}

# ------------------------------------------------------------
# OUTPUT
# ------------------------------------------------------------

[pscustomobject]@{
    ProductNameHint = $ProductNameHint
    MonthIds        = $MonthIds
    KbEntries       = @(
        $kbMap.GetEnumerator() |
            ForEach-Object { $_.Value } |
            Sort-Object KB
    )
} | ConvertTo-Json -Depth 10

<#
.SYNOPSIS
WinShield MSRC adapter (stable multi-month version)

- Accepts multiple MonthIds via proper PowerShell binding
- Queries MSRC module for each month
- Filters by ProductNameHint
- Returns KB list with CVEs + Supersedes
- Ignores non-mainline KBs (e.g. Security Hotpatch Update) by default
- Emits JSON for Python scanner
#>

param(
    [Parameter(Mandatory = $true)]
    [string[]]$MonthIds,

    [Parameter(Mandatory = $true)]
    [string]$ProductNameHint
)

# --- Ensure MonthIds is always an array of clean strings ---
if ($MonthIds -is [string]) {
    $MonthIds = $MonthIds -split ","
}
$MonthIds = $MonthIds |
    ForEach-Object { ($_ -as [string]).Trim() } |
    Where-Object { $_ }

# --- Load MSRC module ---
try {
    Import-Module -Name MsrcSecurityUpdates -ErrorAction Stop
}
catch {
    [pscustomobject]@{
        Error   = "Failed to load MsrcSecurityUpdates"
        Details = $_.Exception.Message
    } | ConvertTo-Json -Depth 5
    exit 1
}

# Map: KB -> object { KB, Months[], Cves[], Supersedes[] }
$kbMap = @{}

foreach ($month in $MonthIds) {

    try {
        $doc = Get-MsrcCvrfDocument -ID $month -ErrorAction Stop
        $aff = Get-MsrcCvrfAffectedSoftware -Vulnerability $doc.Vulnerability -ProductTree $doc.ProductTree
    }
    catch {
        # If that month fails, just skip it – scanner will still work with others
        continue
    }

    # Rows matching our ProductNameHint
    $rows = $aff | Where-Object { $_.FullProductName -like "*$ProductNameHint*" }
    if (-not $rows) { continue }

    foreach ($row in $rows) {

        # Normalise CVE list
        $cveList = @()
        if ($row.CVE) {
            if ($row.CVE -is [System.Collections.IEnumerable] -and -not ($row.CVE -is [string])) {
                $cveList = @($row.CVE)
            }
            else {
                $cveList = @($row.CVE)
            }
        }

        # Supersedence cleanup (values like {, 5066835, , ...})
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

                # Skip anything that is not a mainline Security Update
                # (e.g. Security Hotpatch Update, Tooling, Docs, etc.)
                $subType = $kbObj.SubType
                if ($subType -and ($subType -ne "Security Update")) {
                    continue
                }

                if (-not $kbObj.ID) { continue }

                $kbId = $kbObj.ID
                $kb   = if ($kbId -like "KB*") { $kbId } else { "KB$kbId" }

                if (-not $kbMap.ContainsKey($kb)) {
                    $kbMap[$kb] = [pscustomobject]@{
                        KB         = $kb
                        Months     = @()
                        Cves       = @()
                        Supersedes = @()
                    }
                }

                # Month
                if ($kbMap[$kb].Months -notcontains $month) {
                    $kbMap[$kb].Months += $month
                }

                # CVEs
                foreach ($c in $cveList) {
                    if ($c -and $kbMap[$kb].Cves -notcontains $c) {
                        $kbMap[$kb].Cves += $c
                    }
                }

                # Supersedes (KBs this KB replaces)
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

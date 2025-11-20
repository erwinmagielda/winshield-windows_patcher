<#
.SYNOPSIS
    WinShield MSRC debug helper

.DESCRIPTION
    Debugs MSRC behaviour for given MonthIds and ProductNameHint.

    - MonthIds is a single string: "2025-Nov,2025-Oct,2025-Sep"
    - Splits it to an array internally so it mirrors adapter behaviour
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$MonthIds,          # e.g. "2025-Nov,2025-Oct,2025-Sep"

    [Parameter(Mandatory = $true)]
    [string]$ProductNameHint    # e.g. "Windows 11 Version 25H2 for x64-based Systems"
)

Write-Host "=== WinShield MSRC DEBUG ===" -ForegroundColor Cyan
Write-Host "MonthIds (raw): $MonthIds"
Write-Host "ProductNameHint: $ProductNameHint"
Write-Host ""

# Split comma-separated string into an array of clean month tokens
$monthList = $MonthIds -split '\s*,\s*' | Where-Object { $_ -ne "" }

Write-Host "Parsed MonthIds:"
foreach ($m in $monthList) {
    Write-Host " - '$m'"
}
Write-Host ""

# Load MSRC module
Write-Host "[*] Loading MsrcSecurityUpdates module..." -ForegroundColor Yellow
try {
    Import-Module -Name MsrcSecurityUpdates -ErrorAction Stop
    Write-Host "[+] Module loaded." -ForegroundColor Green
} catch {
    Write-Host "[X] Failed to load MsrcSecurityUpdates: $($_.Exception.Message)" -ForegroundColor Red
    return
}

foreach ($month in $monthList) {
    if (-not $month) { continue }

    Write-Host ""
    Write-Host "=== Month: $month ===" -ForegroundColor Magenta

    # Try to get CVRF document
    try {
        $doc = Get-MsrcCvrfDocument -ID $month -ErrorAction Stop
    } catch {
        Write-Host "[X] Get-MsrcCvrfDocument failed for ${month}: $($_.Exception.Message)" -ForegroundColor Red
        continue
    }

    $vulnCount = ($doc.Vulnerability | Measure-Object).Count

    try {
        $aff = Get-MsrcCvrfAffectedSoftware -Vulnerability $doc.Vulnerability -ProductTree $doc.ProductTree
    } catch {
        Write-Host "[X] Get-MsrcCvrfAffectedSoftware failed for ${month}: $($_.Exception.Message)" -ForegroundColor Red
        continue
    }

    $affCount = ($aff | Measure-Object).Count

    Write-Host "[*] Vulnerabilities: $vulnCount"
    Write-Host "[*] AffectedSoftware rows: $affCount"

    # All distinct product names
    $allNames = $aff | Select-Object -ExpandProperty FullProductName -Unique
    $win11x64 = $allNames |
        Where-Object { $_ -like "Windows 11*for x64-based Systems*" } |
        Sort-Object

    Write-Host ""
    Write-Host ">>> Candidate FullProductName values for Windows 11 x64:" -ForegroundColor Yellow
    if ($win11x64) {
        $win11x64 | ForEach-Object { Write-Host " - $_" }
    } else {
        Write-Host " (none matched)"
    }

    # Rows matching ProductNameHint
    $rowsForHint = $aff | Where-Object {
        $_.FullProductName -like "*$ProductNameHint*"
    }

    $rowsCount = ($rowsForHint | Measure-Object).Count
    Write-Host ""
    Write-Host ">>> Rows matching ProductNameHint:" -ForegroundColor Yellow
    Write-Host "    Count: $rowsCount"

    if ($rowsCount -gt 0) {
        $rowsForHint |
            Select-Object -First 3 `
                FullProductName,
                CVE,
                KBArticle,
                Supercedence |
            Format-List | Out-String |
            ForEach-Object { Write-Host $_ }
    } else {
        Write-Host "    (none)"
    }

    # Sample KBs for Windows 11 x64
    $rowsWin11 = $aff | Where-Object {
        $_.FullProductName -like "Windows 11*for x64-based Systems*"
    }

    $sampleKbs = @()
    foreach ($r in $rowsWin11) {
        if ($r.KBArticle) {
            foreach ($kbObj in $r.KBArticle) {
                if ($kbObj.ID) {
                    $sampleKbs += $kbObj.ID
                }
            }
        }
    }

    $sampleKbs = $sampleKbs | Select-Object -Unique | Select-Object -First 10

    Write-Host ""
    Write-Host ">>> Sample KBArticle IDs for Windows 11 x64 in ${month}:" -ForegroundColor Yellow
    if ($sampleKbs) {
        $sampleKbs | ForEach-Object { Write-Host " - $_" }
    } else {
        Write-Host " (none)"
    }
}

Write-Host ""
Write-Host "=== End of MSRC debug ===" -ForegroundColor Cyan

<#
.SYNOPSIS
    WinShield Baseline Generator (de-hardcoded)

.DESCRIPTION
    Detects OS name, version, build, arch, latest LCU (if run as admin),
    and automatically discovers the correct MSRC ProductNameHint via the
    official MsrcSecurityUpdates module.

    Outputs JSON to stdout for the Python scanner.
#>

function Import-MsrcModule {
    try {
        Import-Module MsrcSecurityUpdates -ErrorAction Stop
    }
    catch {
        throw "Failed to load MsrcSecurityUpdates module: $($_.Exception.Message)"
    }
}

function Get-WinShieldProductNameHint {
    param(
        [Parameter(Mandatory = $true)]
        [string]$MonthId  # e.g. "2025-Nov"
    )

    try {
        Import-MsrcModule

        # Detect current OS
        $os = Get-CimInstance Win32_OperatingSystem
        $osFullName = $os.Caption                     # "Microsoft Windows 11 Home"
        $osMajor    = ($osFullName -replace '^Microsoft ', '')
        $arch       = if ($os.OSArchitecture -match "64") { "x64" } else { "x86" }

        # Query MSRC for this month
        $doc = Get-MsrcCvrfDocument -ID $MonthId -ErrorAction Stop
        $aff = Get-MsrcCvrfAffectedSoftware -Vulnerability $doc.Vulnerability -ProductTree $doc.ProductTree

        # Unique product names
        $names = $aff | Select-Object -ExpandProperty FullProductName -Unique

        # Filter matching our OS major string and arch
        $candidates = $names |
            Where-Object { $_ -like "$osMajor*" -and $_ -like "*$arch*" } |
            Sort-Object

        if (-not $candidates) {
            $candidates = $names | Sort-Object
        }

        # Prefer entries with "Version", pick the last (newest) one
        $best = $candidates |
            Where-Object { $_ -like "*Version*" } |
            Sort-Object |
            Select-Object -Last 1

        if (-not $best) {
            $best = $candidates | Select-Object -Last 1
        }

        return $best
    }
    catch {
        Write-Error "Failed to query MSRC for ProductNameHint: $($_.Exception.Message)"
        return $null
    }
}

# -------------------------------------------------------------------------
# Detect system info
# -------------------------------------------------------------------------
$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$os = Get-CimInstance Win32_OperatingSystem

$build     = [int]$cv.CurrentBuild
$ubr       = [int]$cv.UBR
$fullBuild = "$build.$ubr"

$displayVersion = $cv.DisplayVersion
if (-not $displayVersion) {
    $displayVersion = $cv.ReleaseId
}

$arch = switch ($env:PROCESSOR_ARCHITECTURE) {
    'AMD64' { 'x64' }
    'ARM64' { 'ARM64' }
    default { $env:PROCESSOR_ARCHITECTURE }
}

# Admin check (fixed syntax)
$isAdmin = (
    New-Object Security.Principal.WindowsPrincipal(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    )
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# -------------------------------------------------------------------------
# Detect latest LCU (if admin)
# -------------------------------------------------------------------------
$lcuPkgName = $null
$lcuTime    = $null

if ($isAdmin) {
    try {
        $rollups = Get-WindowsPackage -Online |
            Where-Object { $_.PackageName -like "*RollupFix*" } |
            Sort-Object -Property InstallTime -Descending

        if ($rollups -and $rollups.Count -gt 0) {
            $lcu = $rollups[0]
            $lcuPkgName = $lcu.PackageName
            $lcuTime    = $lcu.InstallTime
        }
    }
    catch {
        Write-Error "Failed to query LCU via Get-WindowsPackage: $($_.Exception.Message)"
    }
}

# Derive LCU month id for MSRC range
$lcuMonthId = $null
if ($lcuTime) {
    $lcuMonthId = (Get-Date $lcuTime).ToString("yyyy-MMM")  # e.g. 2025-Nov
}

# -------------------------------------------------------------------------
# Auto-detect MSRC ProductNameHint for current month
# -------------------------------------------------------------------------
$monthId = (Get-Date).ToString("yyyy-MMM")  # e.g. "2025-Nov"
$productHint = Get-WinShieldProductNameHint -MonthId $monthId

# -------------------------------------------------------------------------
# Build final baseline object
# -------------------------------------------------------------------------
$baseline = [pscustomobject]@{
    ComputerName    = $env:COMPUTERNAME
    OSName          = $os.Caption
    OSEdition       = $cv.EditionID
    DisplayVersion  = $displayVersion
    Build           = $build
    UBR             = $ubr
    FullBuild       = $fullBuild
    Architecture    = $arch
    IsAdmin         = $isAdmin
    LCU_PackageName = $lcuPkgName
    LCU_InstallTime = $lcuTime
    LCU_MonthId     = $lcuMonthId
    ProductNameHint = $productHint
}

$baseline | ConvertTo-Json -Depth 4

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
        $osFullName = $os.Caption
        $osArchRaw  = $os.OSArchitecture
        $arch       = if ($osArchRaw -match "64") { "x64" } else { "x86" }

        # Normalise family: "Windows 11" or "Windows 10" etc.
        $osFamily = $null
        if ($osFullName -like "*Windows 11*") {
            $osFamily = "Windows 11"
        } elseif ($osFullName -like "*Windows 10*") {
            $osFamily = "Windows 10"
        } else {
            $osFamily = ($osFullName -replace '^Microsoft\s+', '')
        }

        # Get display version (22H2, 23H2, 25H2, etc.) from registry
        $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
        $displayVersion = $cv.DisplayVersion
        if (-not $displayVersion) {
            $displayVersion = $cv.ReleaseId
        }

        # Query MSRC for this month
        $doc = Get-MsrcCvrfDocument -ID $MonthId -ErrorAction Stop
        $aff = Get-MsrcCvrfAffectedSoftware -Vulnerability $doc.Vulnerability -ProductTree $doc.ProductTree

        # Unique product names
        $names = $aff | Select-Object -ExpandProperty FullProductName -Unique

        # 1) candidates for this OS family + arch
        $candidates = $names |
            Where-Object { $_ -like "$osFamily*for *$arch-based Systems*" } |
            Sort-Object

        # 2) if we know a displayVersion like "22H2", prefer that
        if ($displayVersion) {
            $versionToken1 = $displayVersion
            $versionToken2 = "Version $displayVersion"

            $candidatesForVersion = $candidates |
                Where-Object {
                    $_ -like "*$versionToken2*" -or $_ -like "*$versionToken1*"
                } |
                Sort-Object

            if ($candidatesForVersion) {
                $candidates = $candidatesForVersion
            }
        }

        # 3) Fallback: if still nothing, use all names that start with family
        if (-not $candidates -and $osFamily) {
            $candidates = $names |
                Where-Object { $_ -like "$osFamily*" } |
                Sort-Object
        }

        if (-not $candidates) {
            $candidates = $names |
                Where-Object { $_ -like "Windows*for *$arch-based Systems*" } |
                Sort-Object
        }

        # Prefer entries with "Version", pick the last (newest)
        $best = $candidates |
            Where-Object { $_ -like "*Version*" } |
            Sort-Object |
            Select-Object -Last 1

        if (-not $best) {
            $best = $candidates | Sort-Object | Select-Object -Last 1
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

# Admin check
$windowsIdentity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$windowsPrincipal = New-Object Security.Principal.WindowsPrincipal($windowsIdentity)
$isAdmin          = $windowsPrincipal.IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)

if (-not $isAdmin) {
    Write-Warning "WinShield baseline is not running as Administrator. LCU_PackageName, LCU_InstallTime and LCU_MonthId will be null because Get-WindowsPackage requires elevation."
}

# -------------------------------------------------------------------------
# Detect latest LCU (if admin)
# -------------------------------------------------------------------------
$lcuPkgName = $null
$lcuTime    = $null

if ($isAdmin) {
    try {
        $allPkgs = Get-WindowsPackage -Online

        # Prefer RollupFix
        $rollups = $allPkgs |
            Where-Object { $_.PackageName -like "*RollupFix*" } |
            Sort-Object InstallTime -Descending

        if (-not $rollups -or $rollups.Count -eq 0) {
            # fallback: Description / PackageName (if MS changes naming)
            $rollups = $allPkgs |
                Where-Object {
                    ($_.Description -like "*Cumulative Update*" -or $_.Description -like "*LCU*") -or
                    ($_.PackageName -like "*Cumulative Update*" -or $_.PackageName -like "*LCU*")
                } |
                Sort-Object InstallTime -Descending
        }

        if ($rollups -and $rollups.Count -gt 0) {
            $lcu = $rollups[0]
            $lcuPkgName = $lcu.PackageName
            $lcuTime    = $lcu.InstallTime
        } else {
            Write-Error "Could not identify LCU package. Adjust filters in winshield_baseline.ps1."
        }
    }
    catch {
        Write-Error "Failed to query LCU via Get-WindowsPackage: $($_.Exception.Message)"
    }
}

# Derive LCU month id for scanner
$lcuMonthId = $null
if ($lcuTime) {
    $lcuMonthId = (Get-Date $lcuTime).ToString("yyyy-MMM")
}

# -------------------------------------------------------------------------
# Auto-detect MSRC ProductNameHint for current month
# -------------------------------------------------------------------------
$monthId = (Get-Date).ToString("yyyy-MMM")
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

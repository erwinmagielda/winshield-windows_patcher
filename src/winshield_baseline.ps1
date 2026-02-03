<#
.SYNOPSIS
    WinShield Baseline

.DESCRIPTION
    Collects host baseline metadata required for MSRC correlation.
    Emits a stable JSON object consumed by winshield_scanner.py.
#>

function Get-WinShieldLatestMsrcMonthId {

    try {
        Import-Module MsrcSecurityUpdates -ErrorAction Stop

        $cmd  = Get-Command Get-MsrcCvrfDocument -ErrorAction Stop
        $attr = $cmd.Parameters['ID'].Attributes |
            Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] } |
            Select-Object -First 1

        if (-not $attr -or -not $attr.ValidValues) { return $null }

        $parsed = foreach ($id in $attr.ValidValues) {
            if (-not $id) { continue }

            $parts = $id -split '-', 2
            if ($parts.Count -ne 2) { continue }

            $normMonth = $parts[1].Substring(0,1).ToUpper() + $parts[1].Substring(1).ToLower()

            try {
                $dt = [datetime]::ParseExact(
                    "$($parts[0])-$normMonth",
                    'yyyy-MMM',
                    [System.Globalization.CultureInfo]::InvariantCulture
                )
                [pscustomobject]@{ Id = $id; Date = $dt }
            } catch {
            }
        }

        if (-not $parsed) { return $null }

        return ($parsed | Sort-Object Date | Select-Object -Last 1).Id
    }
    catch {
        return $null
    }
}

function Get-WinShieldProductNameHint {

    param(
        [Parameter(Mandatory = $true)]
        [string]$MonthId
    )

    try {
        Import-Module MsrcSecurityUpdates -ErrorAction Stop

        $os = Get-CimInstance Win32_OperatingSystem
        $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'

        if ($os.Caption -like "*Windows 11*") { $family = "Windows 11" }
        elseif ($os.Caption -like "*Windows 10*") { $family = "Windows 10" }
        else { return $null }

        $displayVersion = $cv.DisplayVersion
        if (-not $displayVersion) { $displayVersion = $cv.ReleaseId }

        $archToken = switch ($env:PROCESSOR_ARCHITECTURE) {
            'AMD64' { 'x64' }
            'ARM64' { 'ARM64' }
            'x86'   { '32-bit' }
            default { 'x64' }
        }

        $doc = Get-MsrcCvrfDocument -ID $MonthId -ErrorAction Stop
        $aff = Get-MsrcCvrfAffectedSoftware -Vulnerability $doc.Vulnerability -ProductTree $doc.ProductTree
        if (-not $aff) { return $null }

        $windowsNames = $aff |
            Select-Object -ExpandProperty FullProductName -Unique |
            Where-Object { $_ -like "Windows *" } |
            Sort-Object

        if (-not $windowsNames) { return $null }

        if ($displayVersion) {
            $target = if ($archToken -eq '32-bit') {
                "$family Version $displayVersion for 32-bit Systems"
            } else {
                "$family Version $displayVersion for $archToken-based Systems"
            }

            $hit = $windowsNames | Where-Object { $_ -eq $target } | Select-Object -First 1
            if ($hit) { return $hit }
        }

        $target = if ($archToken -eq '32-bit') {
            "$family for 32-bit Systems"
        } else {
            "$family for $archToken-based Systems"
        }

        $hit = $windowsNames | Where-Object { $_ -eq $target } | Select-Object -First 1
        if ($hit) { return $hit }

        if ($archToken -eq '32-bit') {
            $hit = $windowsNames | Where-Object { $_ -like "$family*32-bit*" } | Select-Object -First 1
        } else {
            $hit = $windowsNames | Where-Object { $_ -like "$family*$archToken-based*" } | Select-Object -First 1
        }

        if ($hit) { return $hit }

        return ($windowsNames | Where-Object { $_ -like "$family*" } | Select-Object -First 1)
    }
    catch {
        return $null
    }
}

# ------------------------------------------------------------
# SYSTEM IDENTITY
# ------------------------------------------------------------

$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$os = Get-CimInstance Win32_OperatingSystem

$buildString = "$($cv.CurrentBuild).$($cv.UBR)"

$arch = switch ($env:PROCESSOR_ARCHITECTURE) {
    'AMD64' { 'x64' }
    'ARM64' { 'ARM64' }
    'x86'   { 'x86' }
    default { $env:PROCESSOR_ARCHITECTURE }
}

# ------------------------------------------------------------
# PRIVILEGE CONTEXT
# ------------------------------------------------------------

$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
$isAdmin   = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# ------------------------------------------------------------
# LCU ANCHOR (ADMIN ONLY)
# ------------------------------------------------------------

$lcuMonthId     = $null
$lcuPackageName = $null
$lcuInstallTime = $null

if ($isAdmin) {
    try {
        $pkg = Get-WindowsPackage -Online |
            Where-Object { $_.PackageName -like "*RollupFix*" } |
            Sort-Object InstallTime -Descending |
            Select-Object -First 1

        if ($pkg) {
            $lcuPackageName = $pkg.PackageName
            $lcuInstallTime = $pkg.InstallTime
            $lcuMonthId     = (Get-Date $pkg.InstallTime).ToString("yyyy-MMM")
        }
    } catch {
    }
}

# ------------------------------------------------------------
# MSRC RESOLUTION
# ------------------------------------------------------------

$msrcLatestMonthId = Get-WinShieldLatestMsrcMonthId

$productNameHint = $null
if ($msrcLatestMonthId) {
    $productNameHint = Get-WinShieldProductNameHint -MonthId $msrcLatestMonthId
}

# ------------------------------------------------------------
# OUTPUT
# ------------------------------------------------------------

[pscustomobject]@{
    OsName            = $os.Caption
    OsEdition         = $cv.EditionID
    DisplayVersion    = $cv.DisplayVersion
    Build             = $buildString
    Architecture      = $arch
    IsAdmin           = $isAdmin

    LcuMonthId        = $lcuMonthId
    LcuPackageName    = $lcuPackageName
    LcuInstallTime    = $lcuInstallTime

    MsrcLatestMonthId = $msrcLatestMonthId
    ProductNameHint   = $productNameHint
} | ConvertTo-Json -Depth 4

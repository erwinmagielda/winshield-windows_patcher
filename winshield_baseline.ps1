<#
.SYNOPSIS
WinShield baseline detector

- Detects Windows version, build, arch
- Detects servicing family
- Finds latest RollupFix LCU (if run as admin)
- Produces a ProductNameHint used for MSRC product matching
- Outputs JSON when run directly
#>

function Get-WinShieldBaseline {

    # basic OS info
    $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $os = Get-CimInstance Win32_OperatingSystem

    $build     = [int]$cv.CurrentBuild
    $ubr       = [int]$cv.UBR
    $fullBuild = "$build.$ubr"

    $arch = switch ($env:PROCESSOR_ARCHITECTURE) {
        'AMD64' { 'x64' }
        'ARM64' { 'ARM64' }
        default { $env:PROCESSOR_ARCHITECTURE }
    }

    # servicing family
    $family = switch ($build) {
        {$_ -ge 26100 -and $_ -lt 27000} { 'Windows 11 24H2 / 25H2 (26100.x line)' }
        {$_ -ge 22621 -and $_ -lt 26100} { 'Windows 11 22H2 / 23H2 (22621 / 22631 line)' }
        {$_ -ge 22000 -and $_ -lt 22621} { 'Windows 11 21H2 (22000.x line)' }
        {$_ -ge 19041 -and $_ -le 19045} { 'Windows 10 2004 - 22H2 (1904x line)' }
        default { "Unknown build line: $build" }
    }

    # map to an MSRC product name hint
    $displayVersion = $cv.DisplayVersion
    $productHint = $null

    if ($os.Caption -like '*Windows 11*') {
        if ($displayVersion -in @('23H2','24H2','25H2')) {
            $productHint = "Windows 11 Version $displayVersion for $arch-based Systems"
        } elseif ($displayVersion -eq '22H2') {
            $productHint = "Windows 11 Version 22H2 for $arch-based Systems"
        } else {
            $productHint = "Windows 11 for $arch-based Systems"
        }
    }
    elseif ($os.Caption -like '*Windows 10*') {
        if ($displayVersion -eq '22H2') {
            $productHint = "Windows 10 Version 22H2 for $arch-based Systems"
        } elseif ($displayVersion -eq '21H2') {
            $productHint = "Windows 10 Version 21H2 for $arch-based Systems"
        } else {
            $productHint = "Windows 10 for $arch-based Systems"
        }
    }
    else {
        $productHint = $os.Caption
    }

    # are we admin (fixed line, no weird wrapping)
    $isAdmin = (
        [Security.Principal.WindowsPrincipal] `
            [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    # latest LCU package
    $lcuPackageName = $null
    $lcuInstallTime = $null
    $lcuBuildHint   = $null

    if ($isAdmin) {
        try {
            $lcu = Get-WindowsPackage -Online -ErrorAction Stop |
                   Where-Object { $_.PackageName -like '*Package_for_RollupFix*' } |
                   Sort-Object InstallTime -Descending |
                   Select-Object -First 1

            if ($lcu) {
                $lcuPackageName = $lcu.PackageName
                $lcuInstallTime = $lcu.InstallTime

                if ($lcu.PackageName -match '(\d{5})\.(\d+)\.\d+\.\d+$') {
                    $lcuBuildHint = "$($Matches[1]).$($Matches[2])"
                }
            }
        } catch {
            # leave LCU fields null if it fails
        }
    }

    [pscustomobject]@{
        ComputerName     = $env:COMPUTERNAME
        OSName           = $os.Caption
        OSEdition        = $cv.EditionID
        DisplayVersion   = $displayVersion
        ReleaseId        = $cv.ReleaseId
        Build            = $build
        UBR              = $ubr
        FullBuild        = $fullBuild
        Architecture     = $arch
        ServicingFamily  = $family
        ProductNameHint  = $productHint
        IsAdmin          = $isAdmin
        LCU_PackageName  = $lcuPackageName
        LCU_InstallTime  = $lcuInstallTime
        LCU_BuildHint    = $lcuBuildHint
    }
}

# if run as a script, emit JSON for Python
if ($MyInvocation.InvocationName -ne '.') {
    Get-WinShieldBaseline | ConvertTo-Json -Depth 4
}

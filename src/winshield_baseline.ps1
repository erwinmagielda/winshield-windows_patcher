<#
.SYNOPSIS
    WinShield Baseline Generator

.DESCRIPTION
    Collects local system baseline information for WinShield:

    - OS name, edition, version, build, architecture
    - Whether the script was run as Administrator
    - Latest installed cumulative update (LCU):
        * Package name (from Get-WindowsPackage)
        * Install time
        * Derived MonthId (yyyy-MMM)
        * Parsed KB number, if present
    - MSRC ProductNameHint for the current month

    The result is emitted as JSON to stdout for winshield_scanner.py.
#>

function Import-MsrcModule {
    try {
        Import-Module MsrcSecurityUpdates -ErrorAction Stop
    }
    catch {
        throw "Failed to load MsrcSecurityUpdates module: $($_.Exception.Message)"
    }
}

function Get-WinShieldLatestMsrcId {
    try {
        Import-MsrcModule

        $cmd = Get-Command Get-MsrcCvrfDocument -ErrorAction Stop
        $idParam = $cmd.Parameters['ID']
        $validIds = @()

        if ($idParam) {
            foreach ($attr in $idParam.Attributes) {
                if ($attr -is [System.Management.Automation.ValidateSetAttribute]) {
                    $validIds = $attr.ValidValues
                    break
                }
            }
        }

        if (-not $validIds -or $validIds.Count -eq 0) {
            return $null
        }

        # Parse valid IDs as dates and pick the latest
        $parsedList = @()

        foreach ($id in $validIds) {
            if (-not $id) { continue }
            $trimId = $id.Trim()

            $parsed = $null
            try {
                $parsed = [datetime]::ParseExact(
                    $trimId,
                    'yyyy-MMM',
                    [System.Globalization.CultureInfo]::InvariantCulture
                )
            } catch {
                try {
                    $parsed = [datetime]::ParseExact(
                        $trimId,
                        'yyyy-MMM',
                        [System.Globalization.CultureInfo]::GetCultureInfo('en-US')
                    )
                } catch {
                    $parsed = $null
                }
            }

            if ($parsed) {
                $parsedList += [pscustomobject]@{
                    Id   = $trimId
                    Date = $parsed
                }
            }
        }

        if ($parsedList.Count -eq 0) {
            return $null
        }

        return ($parsedList | Sort-Object Date | Select-Object -Last 1).Id
    }
    catch {
        return $null
    }
}

function Get-WinShieldProductNameHint {
    param(
        [Parameter(Mandatory = $true)]
        [string]$MonthId  # for example: "2025-Nov"
    )

    try {
        Import-MsrcModule

        # -------------------------------------------------------------
        # Resolve the most appropriate MSRC ID based on the module ValidateSet
        # -------------------------------------------------------------
        $effectiveMonthId = $MonthId

        try {
            $cmd = Get-Command Get-MsrcCvrfDocument -ErrorAction Stop
            $idParam = $cmd.Parameters['ID']
            $validIds = @()

            if ($idParam) {
                foreach ($attr in $idParam.Attributes) {
                    if ($attr -is [System.Management.Automation.ValidateSetAttribute]) {
                        $validIds = $attr.ValidValues
                        break
                    }
                }
            }

            if ($validIds -and $validIds -notcontains $MonthId) {

                # Parse requested MonthId as a DateTime
                $requestedDate = $null
                try {
                    $requestedDate = [datetime]::ParseExact(
                        $MonthId,
                        'yyyy-MMM',
                        [System.Globalization.CultureInfo]::InvariantCulture
                    )
                } catch {
                    # If parsing fails, leave requestedDate as null
                }

                if ($requestedDate) {
                    $candidates = @()

                    foreach ($id in $validIds) {
                        if (-not $id) { continue }
                        $trimId = $id.Trim()

                        $parsed = $null
                        try {
                            $parsed = [datetime]::ParseExact(
                                $trimId,
                                'yyyy-MMM',
                                [System.Globalization.CultureInfo]::InvariantCulture
                            )
                        } catch {
                            # Handle odd cases like 2018-FEB
                            try {
                                $parsed = [datetime]::ParseExact(
                                    $trimId,
                                    'yyyy-MMM',
                                    [System.Globalization.CultureInfo]::GetCultureInfo('en-US')
                                )
                            } catch {
                                $parsed = $null
                            }
                        }

                        if ($parsed -and $parsed -le $requestedDate) {
                            $candidates += [pscustomobject]@{
                                Id   = $trimId
                                Date = $parsed
                            }
                        }
                    }

                    if ($candidates.Count -gt 0) {
                        # Latest valid ID not later than the requested MonthId
                        $effectiveMonthId = ($candidates | Sort-Object Date | Select-Object -Last 1).Id
                    }
                    else {
                        # No ID on or before requested date, fall back to latest known ID
                        $allParsed = @()

                        foreach ($id in $validIds) {
                            if (-not $id) { continue }
                            $trimId = $id.Trim()

                            $parsed = $null
                            try {
                                $parsed = [datetime]::ParseExact(
                                    $trimId,
                                    'yyyy-MMM',
                                    [System.Globalization.CultureInfo]::InvariantCulture
                                )
                            } catch {
                                try {
                                    $parsed = [datetime]::ParseExact(
                                        $trimId,
                                        'yyyy-MMM',
                                        [System.Globalization.CultureInfo]::GetCultureInfo('en-US')
                                    )
                                } catch {
                                    $parsed = $null
                                }
                            }

                            if ($parsed) {
                                $allParsed += [pscustomobject]@{
                                    Id   = $trimId
                                    Date = $parsed
                                }
                            }
                        }

                        if ($allParsed.Count -gt 0) {
                            $effectiveMonthId = ($allParsed | Sort-Object Date | Select-Object -Last 1).Id
                        }
                    }
                }
            }
        } catch {
            # If anything goes wrong while resolving IDs, keep the original MonthId
        }

        if ($effectiveMonthId -ne $MonthId) {
            Write-Verbose "WinShield: MonthId '$MonthId' not valid in MSRC module. Using '$effectiveMonthId' for ProductNameHint."
        }

        # -------------------------------------------------------------
        # Detect current OS identity for product matching
        # -------------------------------------------------------------
        $os = Get-CimInstance Win32_OperatingSystem
        $osFullName = $os.Caption                # eg "Microsoft Windows 11 Home"
        $osArchRaw  = $os.OSArchitecture         # eg "64-bit"
        $arch       = if ($osArchRaw -match "64") { "x64" } else { "x86" }

        # Normalise family name
        $osFamily = $null
        if ($osFullName -like "*Windows 11*") {
            $osFamily = "Windows 11"
        } elseif ($osFullName -like "*Windows 10*") {
            $osFamily = "Windows 10"
        } else {
            $osFamily = ($osFullName -replace '^Microsoft\s+', '')
        }

        # Determine Windows display version (eg 22H2, 23H2, 25H2)
        $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
        $displayVersion = $cv.DisplayVersion
        if (-not $displayVersion) {
            $displayVersion = $cv.ReleaseId
        }

        # -------------------------------------------------------------
        # Query MSRC CVRF document for the chosen month
        # -------------------------------------------------------------
        $doc = Get-MsrcCvrfDocument -ID $effectiveMonthId -ErrorAction Stop
        $aff = Get-MsrcCvrfAffectedSoftware -Vulnerability $doc.Vulnerability -ProductTree $doc.ProductTree

        # Full product name candidates
        $names = $aff | Select-Object -ExpandProperty FullProductName -Unique

        # Step 1: best match for OS family + architecture
        $candidates = $names |
            Where-Object { $_ -like "$osFamily*for *$arch-based Systems*" } |
            Sort-Object

        # Step 2: refine with display version if available
        if ($displayVersion) {
            $versionToken1 = $displayVersion               # "22H2"
            $versionToken2 = "Version $displayVersion"     # "Version 22H2"

            $candidatesForVersion = $candidates |
                Where-Object {
                    $_ -like "*$versionToken2*" -or $_ -like "*$versionToken1*"
                } |
                Sort-Object

            if ($candidatesForVersion) {
                $candidates = $candidatesForVersion
            }
        }

        # Step 3: fallback based on family prefix only
        if (-not $candidates -and $osFamily) {
            $candidates = $names |
                Where-Object { $_ -like "$osFamily*" } |
                Sort-Object
        }

        # Step 4: final fallback based on "Windows*for *arch-based Systems*"
        if (-not $candidates) {
            $candidates = $names |
                Where-Object { $_ -like "Windows*for *$arch-based Systems*" } |
                Sort-Object
        }

        # Prefer entries containing the word "Version", then take the newest (sorted lexicographically)
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
# Local system information
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

# Determine whether the script is running with administrative privileges
$windowsIdentity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$windowsPrincipal = New-Object Security.Principal.WindowsPrincipal($windowsIdentity)
$isAdmin          = $windowsPrincipal.IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)

if (-not $isAdmin) {
    Write-Warning "WinShield baseline is not running as Administrator. LCU fields (LCU_PackageName, LCU_InstallTime, LCU_MonthId, LCU_KB) will be null because Get-WindowsPackage requires elevation."
}

# -------------------------------------------------------------------------
# Detect latest installed cumulative update (LCU) when running as admin
# -------------------------------------------------------------------------
$lcuPkgName = $null
$lcuTime    = $null
$lcuKbId    = $null

if ($isAdmin) {
    try {
        # Retrieve all packages and order them by install time (newest first)
        $allPkgs = Get-WindowsPackage -Online

        # Primary filter: traditional RollupFix naming
        $rollupCandidates = $allPkgs |
            Where-Object { $_.PackageName -like "*RollupFix*" } |
            Sort-Object InstallTime -Descending

        # Secondary filter: text hints if RollupFix is not present on some builds
        if (-not $rollupCandidates -or $rollupCandidates.Count -eq 0) {
            $rollupCandidates = $allPkgs |
                Where-Object {
                    ($_.Description -like "*Cumulative Update*" -or $_.Description -like "*LCU*") -or
                    ($_.PackageName -like "*Cumulative Update*" -or $_.PackageName -like "*LCU*")
                } |
                Sort-Object InstallTime -Descending
        }

        if ($rollupCandidates -and $rollupCandidates.Count -gt 0) {
            $lcu = $rollupCandidates[0]
            $lcuPkgName = $lcu.PackageName
            $lcuTime    = $lcu.InstallTime

            # Attempt to extract the KB number from the description or package name
            $kbSource = "$($lcu.Description) $($lcu.PackageName)"
            if ($kbSource -match 'KB(\d{4,7})') {
                $lcuKbId = "KB$($Matches[1])"
            }
        }
        else {
            Write-Error "WinShield baseline: could not identify LCU package from Get-WindowsPackage. Filters may need adjustment."
        }
    }
    catch {
        Write-Error "WinShield baseline: Get-WindowsPackage failed: $($_.Exception.Message)"
    }
}

# Convert LCU install time to yyyy-MMM month identifier
$lcuMonthId = $null
if ($lcuTime) {
    $lcuMonthId = (Get-Date $lcuTime).ToString("yyyy-MMM")
}

# -------------------------------------------------------------------------
# Auto-detect MSRC ProductNameHint for current month
# -------------------------------------------------------------------------
$monthId     = (Get-Date).ToString("yyyy-MMM")
$productHint = Get-WinShieldProductNameHint -MonthId $monthId
# Discover the latest MSRC ID known to the module (for scanner clamping)
$msrcLatestId = Get-WinShieldLatestMsrcId

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
    LCU_KB          = $lcuKbId
    ProductNameHint = $productHint
    MsrcLatestId    = $msrcLatestId 
    LatestLCU       = [pscustomobject]@{
        KB          = $lcuKbId
        PackageName = $lcuPkgName
        InstallTime = $lcuTime
        MonthId     = $lcuMonthId
    }
}

$baseline | ConvertTo-Json -Depth 4

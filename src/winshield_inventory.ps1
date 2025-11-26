<#
.SYNOPSIS
    WinShield local KB inventory

.DESCRIPTION
    Collects local KB information from:

    - Get-HotFix (standard Windows hotfixes)
    - Get-WindowsPackage (LCUs and component based packages, when run as admin)

    Emits a JSON object with:
      - IsAdmin flag
      - HotFixKbs (sorted unique list of HotFixID values)
      - PackageKbs (sorted list of KB IDs derived from package metadata)
      - AllInstalledKbs (combined and sorted set)
#>

function Get-WinShieldInventory {

    # Determine whether the current process is elevated
    $windowsIdentity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $windowsPrincipal = New-Object Security.Principal.WindowsPrincipal($windowsIdentity)
    $isAdmin          = $windowsPrincipal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )

    # KBs reported by Get-HotFix
    $hotfixKbs = @()
    try {
        $hotfixKbs = Get-HotFix |
            Where-Object { $_.HotFixID -match '^KB\d+$' } |
            Select-Object -ExpandProperty HotFixID
    } catch {
        # On some unusual systems Get-HotFix may fail; in that case it is safe to continue with an empty set.
    }

    # KBs derived from Get-WindowsPackage metadata (LCUs and servicing components)
    $packageKbs = @()
    if ($isAdmin) {
        try {
            $packageKbs = Get-WindowsPackage -Online -ErrorAction Stop |
                ForEach-Object {
                    $kb = $null

                    # Try to read KB from PackageName
                    if ($_.PackageName -match 'KB(\d{4,7})') {
                        $kb = 'KB' + $Matches[1]
                    }
                    # If that fails, attempt to read KB from Description
                    elseif ($_.Description -and $_.Description -match 'KB(\d{4,7})') {
                        $kb = 'KB' + $Matches[1]
                    }

                    if ($kb) { $kb }
                } |
                Sort-Object -Unique
        } catch {
            # If DISM / Get-WindowsPackage fails or elevation is missing, PackageKbs remains empty.
        }
    }

    $allKbs = @($hotfixKbs + $packageKbs) | Sort-Object -Unique

    [pscustomobject]@{
        IsAdmin         = $isAdmin
        HotFixKbs       = $hotfixKbs | Sort-Object -Unique
        PackageKbs      = $packageKbs
        AllInstalledKbs = $allKbs
    }
}

# Emit JSON when the function is executed as a script entry point
if ($MyInvocation.InvocationName -ne '.') {
    Get-WinShieldInventory | ConvertTo-Json -Depth 4
}

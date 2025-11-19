<#
.SYNOPSIS
WinShield local KB inventory

- Collects KBs from Get-HotFix
- Collects KBs from Get-WindowsPackage (LCUs etc.) when run as admin
- Emits JSON with distinct KB IDs
#>

function Get-WinShieldInventory {

    # --- detect admin: use explicit objects to avoid parser issues ---
    $windowsIdentity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $windowsPrincipal = New-Object Security.Principal.WindowsPrincipal($windowsIdentity)
    $isAdmin          = $windowsPrincipal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )

    # --- KBs from Get-HotFix ---
    $hotfixKbs = @()
    try {
        $hotfixKbs = Get-HotFix |
            Where-Object { $_.HotFixID -match '^KB\d+$' } |
            Select-Object -ExpandProperty HotFixID
    } catch {
        # ignore on weird systems
    }

    # --- KBs from Get-WindowsPackage (LCUs etc.) ---
    $packageKbs = @()
    if ($isAdmin) {
        try {
            $packageKbs = Get-WindowsPackage -Online -ErrorAction Stop |
                ForEach-Object {
                    $kb = $null

                    if ($_.PackageName -match 'KB(\d{4,7})') {
                        $kb = 'KB' + $Matches[1]
                    }
                    elseif ($_.Description -and $_.Description -match 'KB(\d{4,7})') {
                        $kb = 'KB' + $Matches[1]
                    }

                    if ($kb) { $kb }
                } |
                Sort-Object -Unique
        } catch {
            # DISM failed or needs elevation – leave PackageKbs empty
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

# When run as script, emit JSON
if ($MyInvocation.InvocationName -ne '.') {
    Get-WinShieldInventory | ConvertTo-Json -Depth 4
}

<#
.SYNOPSIS
    WinShield Inventory

.DESCRIPTION
    Collects installed Windows update identifiers using Get-HotFix and Get-WindowsPackage.
    Emits a stable JSON object consumed by winshield_scanner.py.
#>

function Get-WinShieldInventory {

    # ------------------------------------------------------------
    # PRIVILEGE CONTEXT
    # ------------------------------------------------------------

    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    $isAdmin   = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    # ------------------------------------------------------------
    # PRIMARY SOURCE: GET-HOTFIX
    # ------------------------------------------------------------

    try {
        $hotFixKbs = Get-HotFix |
            Where-Object { $_.HotFixID -match '^KB\d+$' } |
            Select-Object -ExpandProperty HotFixID |
            Sort-Object -Unique
    } catch {
        $hotFixKbs = @()
    }

    # ------------------------------------------------------------
    # SECONDARY SOURCE: GET-WINDOWSPACKAGE (ADMIN ONLY)
    # ------------------------------------------------------------

    $packageKbs = @()

    if ($isAdmin) {
        try {
            $packageKbs = Get-WindowsPackage -Online |
                ForEach-Object {
                    if ($_.PackageName -match 'KB(\d{4,7})') {
                        "KB$($Matches[1])"
                    }
                    elseif ($_.Description -match 'KB(\d{4,7})') {
                        "KB$($Matches[1])"
                    }
                } |
                Sort-Object -Unique
        } catch {
            $packageKbs = @()
        }
    }

    # ------------------------------------------------------------
    # NORMALISATION
    # ------------------------------------------------------------

    $allInstalledKbs = @($hotFixKbs + $packageKbs) | Sort-Object -Unique

    [pscustomobject]@{
        IsAdmin         = $isAdmin
        HotFixKbs       = $hotFixKbs
        PackageKbs      = $packageKbs
        AllInstalledKbs = $allInstalledKbs
    }
}

# ------------------------------------------------------------
# ENTRY POINT
# ------------------------------------------------------------

if ($MyInvocation.InvocationName -ne '.') {
    Get-WinShieldInventory | ConvertTo-Json -Depth 3
}

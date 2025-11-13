<#
    WinShield Master Orchestrator
    - User-facing entry point
    - Runs the Controller
    - Checks controller_results.json
    - If environment is OK → runs Scanner
    - If not → exits with reason
#>

Clear-Host
Write-Host "=== WinShield Master Orchestrator ===" -ForegroundColor Cyan
Write-Host

# --------------------------------------------------------------
# Helper functions
# --------------------------------------------------------------

function Ask-YesNo($msg) {
    while ($true) {
        $ans = Read-Host "$msg (Y/N)"
        switch ($ans.ToUpper()) {
            "Y" { return $true }
            "N" { return $false }
            default { Write-Host "Please enter Y or N." -ForegroundColor Yellow }
        }
    }
}

function Fail($msg) {
    Write-Host "[X] $msg" -ForegroundColor Red
    exit
}

function Info($msg) {
    Write-Host "[*] $msg" -ForegroundColor Cyan
}

function Good($msg) {
    Write-Host "[+] $msg" -ForegroundColor Green
}

# --------------------------------------------------------------
# 1. Ask whether to run the Controller
# --------------------------------------------------------------

if (-not (Ask-YesNo "Run environment controller now?")) {
    Fail "User cancelled."
}

# --------------------------------------------------------------
# 2. Run Controller
# --------------------------------------------------------------

$controller = Join-Path $PSScriptRoot "WinShield_Controller.ps1"
if (!(Test-Path $controller)) {
    Fail "Controller not found: $controller"
}

Info "Running environment controller..."
powershell.exe -ExecutionPolicy Bypass -File "$controller"

# --------------------------------------------------------------
# 3. Read controller results
# --------------------------------------------------------------

$controller_json = Join-Path $PSScriptRoot "controller_results.json"

if (!(Test-Path $controller_json)) {
    Fail "Controller did not write controller_results.json; cannot continue."
}

try {
    $controller_data = Get-Content $controller_json -Raw | ConvertFrom-Json
}
catch {
    Fail "Could not parse controller_results.json"
}

# --------------------------------------------------------------
# 4. Evaluate controller readiness
# --------------------------------------------------------------

if (-not $controller_data.ready) {
    Write-Host ""
    Write-Host "Environment check FAILED:" -ForegroundColor Red
    foreach ($e in $controller_data.errors) {
        Write-Host " - $e" -ForegroundColor Yellow
    }
    Fail "Cannot proceed to scanning."
}

Good "Controller reports environment is ready."

# --------------------------------------------------------------
# 5. Run Scanner
# --------------------------------------------------------------

$scanner = Join-Path $PSScriptRoot "WinShield_Scanner.py"
if (!(Test-Path $scanner)) {
    Fail "Scanner file missing: $scanner"
}

Info "Launching WinShield Scanner..."
python "$scanner"

# --------------------------------------------------------------
# 6. Read scanner results (optional for phase 1)
# --------------------------------------------------------------

$scanner_json = Join-Path $PSScriptRoot "scanner_results.json"
if (Test-Path $scanner_json) {
    $scan = Get-Content $scanner_json -Raw | ConvertFrom-Json
    Good "Scan completed. Results saved to scanner_results.json."
    Write-Host "Bulletin month: $($scan.bulletin_month)"
    Write-Host "Missing CVEs:   $($scan.missing_cves_count)"
} else {
    Warn "Scanner did not produce scanner_results.json (older version?)"
}

Write-Host ""
Good "WinShield Master complete."

<#
    WinShield_Controller (Modern, Clean Version)
    - Detect OS, build, version, bitness
    - Detect PowerShell version
    - Detect Python + version
    - Install Python if missing
    - Install Python dependencies
    - Write controller_results.json
    - Does NOT run the scanner anymore
#>

# =============================
# Helper functions
# =============================

function Info($m) { Write-Host "[*] $m" -ForegroundColor Cyan }
function Good($m) { Write-Host "[+] $m" -ForegroundColor Green }
function Warn($m) { Write-Host "[!] $m" -ForegroundColor Yellow }
function Fail($m) { Write-Host "[X] $m" -ForegroundColor Red }

$errors = @()

# Location of result file
$resultFile = Join-Path $PSScriptRoot "controller_results.json"

# =============================
# 1. OS Detection
# =============================

try {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
} catch {
    $os = Get-WmiObject Win32_OperatingSystem
}

$os_name = $os.Caption
$os_version = $os.Version
$build = $os.BuildNumber
$bitness = if ([Environment]::Is64BitOperatingSystem) { "64-bit" } else { "32-bit" }

Good "Detected: $os_name ($os_version) Build $build [$bitness]"

# =============================
# 2. PowerShell version
# =============================

$psVersion = $PSVersionTable.PSVersion.Major
Good "PowerShell version: $psVersion"

# =============================
# 3. Python detection
# =============================

function Test-Python {
    try {
        $ver = & python --version 2>$null
        return $LASTEXITCODE -eq 0
    } catch {
        return $false
    }
}

$python_ok = Test-Python
if (-not $python_ok) {
    Warn "Python is missing. Installing Python..."

    $url = "https://www.python.org/ftp/python/3.12.6/python-3.12.6-amd64.exe"
    $installer = Join-Path $PSScriptRoot "python_installer.exe"

    try {
        Invoke-WebRequest -Uri $url -OutFile $installer -UseBasicParsing -ErrorAction Stop
        Start-Process $installer -ArgumentList "/quiet PrependPath=1 InstallAllUsers=1" -Wait
        Remove-Item $installer -Force
        Good "Python installed."
        $python_ok = Test-Python
    }
    catch {
        $errors += "Python installation failed."
    }
}
else {
    Good "Python is present."
}

# =============================
# 4. Python dependencies
# =============================

$deps_ok = $false

if ($python_ok) {
    Info "Checking Python modules..."
    try {
        pip install --upgrade pip
        pip install requests rich python-dateutil
        $deps_ok = $true
        Good "Python dependencies installed."
    } catch {
        $errors += "Python dependencies failed to install."
    }
}

# =============================
# 5. Final readiness decision
# =============================

$ready = $true

if (-not $python_ok) { $ready = $false }
if (-not $deps_ok)   { $ready = $false }
if ($errors.Count -gt 0) { $ready = $false }

# =============================
# 6. Write controller_results.json
# =============================

$payload = @{
    ready = $ready
    errors = $errors

    os_name = $os_name
    os_version = $os_version
    build = $build
    bitness = $bitness

    powershell_version = $psVersion
    python_ok = $python_ok
    deps_ok = $deps_ok
}

$payload | ConvertTo-Json -Depth 5 | Out-File $resultFile -Encoding UTF8

if ($ready) {
    Good "Environment ready. Controller completed."
} else {
    Fail "Environment not ready. Controller completed with errors."
}
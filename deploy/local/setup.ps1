# One-time setup for running AIGatekeeper on this workstation.
#
#   cd deploy\local
#   .\setup.ps1
#
# Generates the root CA and an admin password, then prints the two commands
# that need an elevated shell. It never changes your system on its own:
# trusting a root certificate is your decision to make deliberately.
param(
    [string]$AdminPassword,
    [switch]$Force
)
$ErrorActionPreference = "Stop"
$here = $PSScriptRoot
$certs = Join-Path $here "certs"

function Require-Docker {
    try { docker info --format '{{.ServerVersion}}' | Out-Null }
    catch { throw "Docker is not running. Start Docker Desktop and try again." }
}

Require-Docker

Write-Host "Building the image (first run takes a few minutes)..."
docker build -q -f (Join-Path $here "..\Dockerfile") -t aigatekeeper:local (Join-Path $here "..\..") | Out-Null

New-Item -ItemType Directory -Force -Path $certs | Out-Null
$caPath = Join-Path $certs "ca.crt"

if ((Test-Path $caPath) -and -not $Force) {
    Write-Host "Reusing the existing CA at $caPath (pass -Force to replace it)."
} else {
    Write-Host "Generating the root CA..."
    docker run --rm -v "${certs}:/certs" aigatekeeper:local ca init --out /certs --force
}

if (-not $AdminPassword) {
    $secure = Read-Host "Choose a console password (at least 8 characters)" -AsSecureString
    $AdminPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))
}
if ($AdminPassword.Length -lt 8) { throw "The password must be at least 8 characters." }

# hash-password prompts on stderr, which PowerShell 5.1 turns into a
# terminating error, so both streams are captured as plain text and the
# hash line is picked out.
$prev = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
$out = $AdminPassword | docker run --rm -i aigatekeeper:local admin hash-password 2>&1
$ErrorActionPreference = $prev
$hash = ($out | ForEach-Object { "$_" } | Where-Object { $_.Trim().StartsWith('$2') } | Select-Object -First 1)
if (-not $hash) { throw "Could not generate the password hash. Output was: $($out -join ' ')" }
$hash = $hash.Trim()

# The hash goes into the config file, which compose only bind-mounts. It
# must not travel through compose as a variable: a bcrypt hash is full of
# $ signs and compose expands them, corrupting it without a word.
$cfgPath = Join-Path $here "aigatekeeper.yaml"
$lines = [System.IO.File]::ReadAllLines($cfgPath)
$patched = $false
for ($i = 0; $i -lt $lines.Length; $i++) {
    if ($lines[$i].TrimStart().StartsWith("password_hash:")) {
        $indent = $lines[$i].Substring(0, $lines[$i].IndexOf("password_hash:"))
        $lines[$i] = $indent + 'password_hash: "' + $hash + '"'
        $patched = $true
        break
    }
}
if (-not $patched) { throw "Could not find password_hash in $cfgPath" }
[System.IO.File]::WriteAllLines($cfgPath, $lines, (New-Object System.Text.UTF8Encoding($false)))
Remove-Item (Join-Path $here "aigatekeeper.env") -ErrorAction SilentlyContinue
Remove-Item (Join-Path $here ".env") -ErrorAction SilentlyContinue
Write-Host "Wrote the console password into deploy\local\aigatekeeper.yaml"

$abs = (Resolve-Path $caPath).Path
Write-Host ""
Write-Host "Setup is done. Three things left, and the first two need an admin shell:" -ForegroundColor Green
Write-Host ""
Write-Host "1. Trust the CA for Windows and Chrome:"
Write-Host "     certutil -addstore -f Root `"$abs`"" -ForegroundColor Cyan
Write-Host ""
Write-Host "2. Trust it for Copilot, which uses Node's own certificate store:"
Write-Host "     setx NODE_EXTRA_CA_CERTS `"$abs`"" -ForegroundColor Cyan
Write-Host "   (a normal shell is fine for this one; restart VS Code afterwards)"
Write-Host ""
Write-Host "3. Start it and point VS Code at it:"
Write-Host "     docker compose up -d" -ForegroundColor Cyan
Write-Host "   then add to your VS Code settings.json:"
Write-Host '     "http.proxy": "http://127.0.0.1:8080"' -ForegroundColor Cyan
Write-Host '     "http.proxySupport": "override"' -ForegroundColor Cyan
Write-Host ""
Write-Host "The console is at http://127.0.0.1:9090"

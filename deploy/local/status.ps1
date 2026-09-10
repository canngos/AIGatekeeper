# Says whether AIGatekeeper is running here, and if not, why.
#
#   cd deploy\local
#   .\status.ps1
param([int]$WaitSeconds = 45)
$ErrorActionPreference = "Continue"
$here = $PSScriptRoot

function Say($text, $colour = "Gray") { Write-Host $text -ForegroundColor $colour }

# 1. Docker itself
docker info --format '{{.ServerVersion}}' 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    Say "Docker is not running. Start Docker Desktop, then try again." "Red"
    exit 1
}

# 2. Does the container exist at all?
$state = docker inspect aigatekeeper --format '{{.State.Status}}' 2>$null
if (-not $state) {
    Say "There is no aigatekeeper container yet. Run:" "Yellow"
    Say "    docker compose up -d" "Cyan"
    exit 1
}

# 3. Wait for the health check, which only turns green once the admin
#    listener answers. A crash-looping container never gets there.
$deadline = (Get-Date).AddSeconds($WaitSeconds)
do {
    $state  = docker inspect aigatekeeper --format '{{.State.Status}}' 2>$null
    $health = docker inspect aigatekeeper --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' 2>$null
    $restarts = [int](docker inspect aigatekeeper --format '{{.RestartCount}}' 2>$null)
    if ($health -eq "healthy" -or $state -eq "exited" -or $restarts -ge 2) { break }
    Start-Sleep -Seconds 2
} while ((Get-Date) -lt $deadline)

if ($health -eq "healthy") {
    Say "AIGatekeeper is healthy." "Green"
    Say "  Proxy   http://127.0.0.1:8080"
    Say "  Console http://127.0.0.1:9090"
    $ca = Join-Path $here "certs\ca.crt"
    if (Test-Path $ca) {
        $node = [Environment]::GetEnvironmentVariable("NODE_EXTRA_CA_CERTS", "User")
        if (-not $node) {
            Say ""
            Say "NODE_EXTRA_CA_CERTS is not set, so Copilot will reject the proxy's" "Yellow"
            Say "certificate. Set it, then restart your IDE completely:" "Yellow"
            Say "    setx NODE_EXTRA_CA_CERTS `"$((Resolve-Path $ca).Path)`"" "Cyan"
        }
    }
    exit 0
}

# 4. Not healthy: work out why and say so plainly.
Say "AIGatekeeper is not healthy (state: $state, health: $health, restarts: $restarts)." "Red"
Say ""

$log = docker logs aigatekeeper 2>&1 | Out-String
$fatal = ($log -split "`n" | Where-Object { $_ -match 'level=ERROR' } | Select-Object -Last 1)

# A port clash happens before the container runs, so it leaves no log at
# all: the container sits in "created" and Docker reported the error on
# the `up` command that has already scrolled away.
function Test-PortTaken($port) {
    # The @() matters: a single CIM instance has no usable .Count in
    # PowerShell 5.1, so an unwrapped result reads as "not taken".
    @(Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue).Count -gt 0
}
if ($state -eq "created" -and -not $fatal) {
    $taken = @(8080, 9090) | Where-Object { Test-PortTaken $_ }
    if ($taken) {
        Say "The container could not be given port $($taken -join ' and '): something else is" "Yellow"
        Say "already listening there. Free it, or change the published ports in" "Yellow"
        Say "docker-compose.yml, then:" "Yellow"
        Say "    docker compose up -d --force-recreate" "Cyan"
        Say ""
        Say "What is holding it:" "Gray"
        foreach ($p in $taken) {
            Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue |
                ForEach-Object {
                    $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
                    Say "    port $p  <-  $($proc.ProcessName) (pid $($_.OwningProcess))"
                }
        }
        Say ""
        Say "Full log:  docker compose logs" "Gray"
        exit 1
    }
    Say "The container was created but never started. Docker reported the reason on" "Yellow"
    Say "the `docker compose up` command itself; run it again to see it:" "Yellow"
    Say "    docker compose up -d --force-recreate" "Cyan"
    Say ""
    exit 1
}

if ($log -match "no such file or directory" -and $log -match "ca\.crt") {
    Say "The root certificate has not been generated yet. Run setup first:" "Yellow"
    Say "    .\setup.ps1" "Cyan"
    Say "    docker compose up -d" "Cyan"
} elseif ($log -match "admin API and UI are disabled") {
    Say "No console password is set. Run setup, which writes one into" "Yellow"
    Say "aigatekeeper.yaml, then recreate the container:" "Yellow"
    Say "    .\setup.ps1" "Cyan"
    Say "    docker compose up -d --force-recreate" "Cyan"
} elseif ($log -match "configuration is invalid" -or $log -match "parse config") {
    Say "The configuration was rejected. The proxy prints each problem with its" "Yellow"
    Say "path; the last error was:" "Yellow"
    Say "    $fatal" "Cyan"
} elseif ($log -match "address already in use" -or $log -match "port is already allocated") {
    Say "Port 8080 or 9090 is already taken by something else. Free it, or change" "Yellow"
    Say "the published ports in docker-compose.yml." "Yellow"
} elseif ($fatal) {
    Say "The proxy stopped with:" "Yellow"
    Say "    $fatal" "Cyan"
} else {
    Say "No fatal error was logged. The last few lines were:" "Yellow"
    ($log -split "`n" | Select-Object -Last 8) | ForEach-Object { Say "    $_" }
}

Say ""
Say "Full log:  docker compose logs" "Gray"
exit 1

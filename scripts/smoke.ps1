# End-to-end smoke test for a running AIGatekeeper (Windows, PowerShell 5.1+).
#
#   scripts\smoke.ps1 -Proxy http://127.0.0.1:8080 -Admin http://127.0.0.1:9090 -CA certs\ca.crt
#
# Unlike smoke.sh this script does not start the proxy; it exercises one that
# is already running (for example the Docker Compose deployment) against the
# real OpenAI endpoint, so no API key is needed: OpenAI answers 401 for the
# clean request, which proves interception and forwarding, and AIGatekeeper
# answers 403 for the request carrying a secret.
param(
    [string]$Proxy = "http://127.0.0.1:8080",
    [string]$Admin = "http://127.0.0.1:9090",
    [string]$CA = "certs\ca.crt"
)
$ErrorActionPreference = "Stop"
$curl = (Get-Command curl.exe).Source

function Invoke-Curl([string[]]$args) {
    $out = & $curl @args 2>&1
    return ($out | Out-String)
}

Write-Host "== admin health"
$health = Invoke-RestMethod "$Admin/healthz"
if ($health.status -ne "ok") { throw "healthz: $($health | ConvertTo-Json)" }

Write-Host "== clean request reaches OpenAI (expect 401 without an API key)"
$code = Invoke-Curl @("-sS", "--ssl-revoke-best-effort", "-o", "NUL", "-w", "%{http_code}", "-x", $Proxy, "--cacert", $CA,
    "-H", "Content-Type: application/json", "-d", '{"model":"gpt-4o","messages":[{"role":"user","content":"hello"}]}',
    "https://api.openai.com/v1/chat/completions")
if ($code.Trim() -ne "401") { throw "expected 401 from OpenAI through the proxy, got $code" }

Write-Host "== request with an AWS key is blocked by AIGatekeeper (expect 403)"
$code = Invoke-Curl @("-sS", "--ssl-revoke-best-effort", "-o", "NUL", "-w", "%{http_code}", "-x", $Proxy, "--cacert", $CA,
    "-H", "Content-Type: application/json", "-d", '{"model":"gpt-4o","messages":[{"role":"user","content":"key AKIAIOSFODNN7REALKEY"}]}',
    "https://api.openai.com/v1/chat/completions")
if ($code.Trim() -ne "403") { throw "expected 403 from AIGatekeeper, got $code" }

Write-Host "== unmatched host is tunnelled (system trust store, no proxy CA needed)"
$code = Invoke-Curl @("-sS", "-o", "NUL", "-w", "%{http_code}", "-x", $Proxy, "https://github.com/")
if ($code.Trim() -notmatch '^(200|301|302)$') { throw "tunnel to github.com failed: $code" }

Write-Host "== policy summary and metrics"
$policy = Invoke-RestMethod "$Admin/-/policy"
if (-not $policy.loaded) { throw "policy not loaded" }
$metrics = Invoke-RestMethod "$Admin/metrics"
if ($null -eq $metrics.aigk_requests_total) { throw "metrics missing" }

Write-Host "SMOKE OK"

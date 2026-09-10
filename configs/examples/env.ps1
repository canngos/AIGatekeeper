# AIGatekeeper client environment for Windows (PowerShell).
# Run once per machine as Administrator to trust the CA, then set the variables for the user.
# Download the certificate from the admin listener: http://proxy.corp.local:9090/ca.crt

$ca = "$env:ProgramData\AIGatekeeper\ca.crt"
certutil -addstore -f Root $ca

$proxy = "http://proxy.corp.local:8080"
[Environment]::SetEnvironmentVariable("HTTPS_PROXY", $proxy, "User")
[Environment]::SetEnvironmentVariable("HTTP_PROXY", $proxy, "User")
[Environment]::SetEnvironmentVariable("NO_PROXY", "localhost,127.0.0.1,.corp.local", "User")
[Environment]::SetEnvironmentVariable("NODE_EXTRA_CA_CERTS", $ca, "User")   # GitHub Copilot, VS Code extensions, Node CLIs
[Environment]::SetEnvironmentVariable("SSL_CERT_FILE", $ca, "User")         # Cursor and OpenSSL-based tools
[Environment]::SetEnvironmentVariable("REQUESTS_CA_BUNDLE", $ca, "User")    # Python requests / OpenAI SDK

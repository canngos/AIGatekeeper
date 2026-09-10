# AIGatekeeper client environment for macOS / Linux. Source from your shell profile.
# Download the certificate from the admin listener: http://proxy.corp.local:9090/ca.crt
# macOS trust:  sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "$AIGK_CA"
# Debian/Ubuntu: sudo cp "$AIGK_CA" /usr/local/share/ca-certificates/aigatekeeper.crt && sudo update-ca-certificates

export AIGK_CA="/etc/aigatekeeper/ca.crt"
export HTTPS_PROXY="http://proxy.corp.local:8080"
export HTTP_PROXY="$HTTPS_PROXY"
export NO_PROXY="localhost,127.0.0.1,.corp.local"
export NODE_EXTRA_CA_CERTS="$AIGK_CA"      # GitHub Copilot, VS Code extensions, Node CLIs
export SSL_CERT_FILE="$AIGK_CA"            # Cursor and OpenSSL-based tools
export REQUESTS_CA_BUNDLE="$AIGK_CA"       # Python requests / OpenAI SDK

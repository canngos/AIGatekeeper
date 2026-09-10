#!/usr/bin/env bash
# End-to-end smoke test against a locally started AIGatekeeper binary.
#
#   scripts/smoke.sh [path/to/aigatekeeper] [proxy_port] [admin_port]
#
# It generates a throwaway CA and config in a temp directory, starts the
# proxy, and verifies through a local TLS upstream that:
#   1. a clean request is intercepted, forwarded and answered by the upstream
#   2. a request carrying an AWS key is blocked with 403 and never reaches the upstream
#   3. a host outside the policy is tunnelled without interception
#   4. editing the config is picked up by hot reload
#   5. the admin endpoints answer
set -euo pipefail

BIN=${1:-bin/aigatekeeper}
PROXY_PORT=${2:-18080}
ADMIN_PORT=${3:-19090}
UPSTREAM_PORT=${4:-18443}

command -v curl >/dev/null || { echo "curl is required"; exit 1; }
command -v python3 >/dev/null || { echo "python3 is required for the local upstream"; exit 1; }
command -v openssl >/dev/null || { echo "openssl is required for the upstream certificate"; exit 1; }

WORK=$(mktemp -d)
trap 'kill ${PROXY_PID:-} ${UPSTREAM_PID:-} 2>/dev/null || true; rm -rf "$WORK"' EXIT
mkdir -p "$WORK/configs" "$WORK/certs"

echo "== generating CA"
"$BIN" ca init --out "$WORK/certs" >/dev/null

echo "== starting local TLS upstream on :$UPSTREAM_PORT"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
  -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -keyout "$WORK/upstream.key" -out "$WORK/upstream.crt" >/dev/null 2>&1
cat > "$WORK/upstream.py" <<'PY'
import http.server, ssl, sys, json
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0)); body = self.rfile.read(n)
        out = json.dumps({"upstream": "ok", "received": len(body)}).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out))); self.end_headers()
        self.wfile.write(out)
    def do_GET(self): self.do_POST()
    def log_message(self, *a): pass
srv = http.server.HTTPServer(("127.0.0.1", int(sys.argv[1])), H)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(sys.argv[2], sys.argv[3])
srv.socket = ctx.wrap_socket(srv.socket, server_side=True); srv.serve_forever()
PY
python3 "$WORK/upstream.py" "$UPSTREAM_PORT" "$WORK/upstream.crt" "$WORK/upstream.key" &
UPSTREAM_PID=$!
for _ in $(seq 1 50); do curl -sS --cacert "$WORK/upstream.crt" "https://127.0.0.1:$UPSTREAM_PORT/" >/dev/null 2>&1 && break; sleep 0.1; done
curl -sS --cacert "$WORK/upstream.crt" "https://127.0.0.1:$UPSTREAM_PORT/" >/dev/null || { echo "upstream did not start"; exit 1; }

cat > "$WORK/configs/aigatekeeper.yaml" <<YAML
version: 1
listen: { forward: "127.0.0.1:$PROXY_PORT", admin: "127.0.0.1:$ADMIN_PORT" }
ca: { cert: ../certs/ca.crt, key: ../certs/ca.key }
tls: { upstream_extra_roots: [../upstream.crt] }
reload: { watch: true, debounce: 100ms, poll_interval: 500ms }
audit: { stdout: true }
services:
  - { name: local, hosts: ['^127\\.0\\.0\\.1$'], extractor: openai, block_mode: reject, rules: [secrets] }
rules:
  - { id: secrets, severity: critical, action: block, detectors: [aws_access_key] }
YAML

echo "== starting proxy on :$PROXY_PORT (admin :$ADMIN_PORT)"
"$BIN" serve --config "$WORK/configs/aigatekeeper.yaml" >"$WORK/audit.log" 2>"$WORK/proxy.log" &
PROXY_PID=$!
for _ in $(seq 1 50); do curl -fsS "http://127.0.0.1:$ADMIN_PORT/readyz" >/dev/null 2>&1 && break; sleep 0.1; done
curl -fsS "http://127.0.0.1:$ADMIN_PORT/readyz" >/dev/null || { echo "proxy did not become ready"; cat "$WORK/proxy.log"; exit 1; }

PROXY="http://127.0.0.1:$PROXY_PORT"
CA="$WORK/certs/ca.crt"
UP="https://127.0.0.1:$UPSTREAM_PORT/v1/chat/completions"
fail() { echo "FAIL: $*"; echo "--- proxy log"; cat "$WORK/proxy.log"; echo "--- audit log"; cat "$WORK/audit.log"; exit 1; }

echo "== 1. clean request is intercepted and forwarded"
out=$(curl -sS -x "$PROXY" --cacert "$CA" -H 'Content-Type: application/json' \
  -d '{"model":"gpt-4o","messages":[{"role":"user","content":"hello"}]}' -D "$WORK/h1" "$UP")
grep -q '"upstream": "ok"' <<<"$out" || fail "clean request not forwarded: $out"
grep -qi '^X-AIGatekeeper-Request-Id:' "$WORK/h1" || fail "request id header missing (not intercepted?)"

echo "== 2. secret is blocked with 403 and does not reach the upstream"
code=$(curl -sS -o "$WORK/b2" -w '%{http_code}' -x "$PROXY" --cacert "$CA" -H 'Content-Type: application/json' \
  -d '{"model":"gpt-4o","messages":[{"role":"user","content":"key AKIAIOSFODNN7REALKEY"}]}' "$UP")
[[ "$code" == "403" ]] || fail "expected 403, got $code: $(cat "$WORK/b2")"
grep -q 'dlp_blocked' "$WORK/b2" || fail "block body missing: $(cat "$WORK/b2")"
grep -q '"action":"block"' "$WORK/audit.log" || fail "no block audit event"
grep -q 'AKIAIOSFODNN7REALKEY' "$WORK/audit.log" && fail "audit log leaks the secret"

echo "== 3. unmatched host is tunnelled (upstream certificate seen directly)"
curl -sS -x "$PROXY" --cacert "$WORK/upstream.crt" "https://localhost:$UPSTREAM_PORT/tunnel" >/dev/null \
  || fail "tunnel to unmatched host failed"

echo "== 4. hot reload: switch to monitor mode and re-send the secret"
sed -i 's/^audit:/mode: { monitor: true }\naudit:/' "$WORK/configs/aigatekeeper.yaml"
for _ in $(seq 1 40); do grep -q '"kind":"config_reload"' "$WORK/audit.log" && [[ $(grep -c '"kind":"config_reload"' "$WORK/audit.log") -ge 2 ]] && break; sleep 0.1; done
code=$(curl -sS -o /dev/null -w '%{http_code}' -x "$PROXY" --cacert "$CA" -H 'Content-Type: application/json' \
  -d '{"messages":[{"role":"user","content":"key AKIAIOSFODNN7REALKEY"}]}' "$UP")
[[ "$code" == "200" ]] || fail "monitor mode should forward, got $code"
grep -q '"action":"monitor"' "$WORK/audit.log" || fail "no monitor audit event after reload"

echo "== 5. admin endpoints"
curl -fsS "http://127.0.0.1:$ADMIN_PORT/ca.crt" | grep -q 'BEGIN CERTIFICATE' || fail "ca.crt not served"
curl -fsS -X POST "http://127.0.0.1:$ADMIN_PORT/-/reload" | grep -q '"reloaded":true' || fail "reload endpoint"
curl -fsS "http://127.0.0.1:$ADMIN_PORT/-/policy" | grep -q '"monitor":true' || fail "policy summary"
curl -fsS "http://127.0.0.1:$ADMIN_PORT/metrics" | grep -q 'aigk_requests_total' || fail "metrics"

echo "SMOKE OK"

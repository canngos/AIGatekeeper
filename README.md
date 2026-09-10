# AIGatekeeper

Self-hosted, open-source TLS-intercepting proxy that inspects GenAI traffic from IDE assistants
(GitHub Copilot, Tabnine, Ollama-backed tools) and API clients (OpenAI, Anthropic, Gemini), scans
prompts for secrets and PII, blocks violations before they leave your network, and records a
structured audit trail. No third-party SaaS, one static binary, Apache-2.0.

> Status: phases 1 to 6 of the [implementation plan](AIGatekeeper.md) are complete (proxy, parsers,
> DLP engine, policy and block responses, hot reload, containerisation). The web admin UI and
> identity/alerting are in progress.

## How it works

1. Workstations point their HTTP proxy at AIGatekeeper and trust its root CA.
2. For hosts listed in the policy the proxy terminates TLS with an on-the-fly certificate, extracts
   the prompt text from the JSON request (OpenAI-compatible, Copilot, Anthropic, Gemini, Ollama, or a
   generic JSON walker), and runs the DLP detectors over it.
3. Clean requests are forwarded unchanged and streamed back without buffering. Violations are
   answered with either an HTTP 403 in the service's error format (`block_mode: reject`) or an HTTP 200
   synthetic completion that tells the developer why (`block_mode: synthetic`), so the IDE never hangs.
4. Every transaction is logged as one JSON line on stdout (for ELK/Splunk) with masked previews of
   the matched values. Prompt text is never persisted.
5. Hosts outside the policy are tunnelled as opaque TCP streams and never decrypted.

```
IDE / SDK ──CONNECT──▶ AIGatekeeper ──TLS──▶ api.openai.com, api.githubcopilot.com, ...
                          │  route ▸ decode ▸ parse ▸ policy ▸ (block | forward)
                          └──▶ audit JSON (stdout, file)   admin :9090 (health, CA, reload, metrics)
```

## Quick start (binary)

```sh
go build -o bin/aigatekeeper ./cmd/aigatekeeper          # or: make build-noui
bin/aigatekeeper ca init                                  # writes certs/ca.crt and certs/ca.key
bin/aigatekeeper serve --config configs/aigatekeeper.yaml
```

Test it from another shell (OpenAI answers 401 without a key, which proves the request was
intercepted and forwarded; the second request is blocked by AIGatekeeper):

```sh
curl -x http://127.0.0.1:8080 --cacert certs/ca.crt https://api.openai.com/v1/chat/completions \
  -H 'Content-Type: application/json' -d '{"model":"gpt-4o","messages":[{"role":"user","content":"hello"}]}'
curl -x http://127.0.0.1:8080 --cacert certs/ca.crt https://api.openai.com/v1/chat/completions \
  -H 'Content-Type: application/json' -d '{"model":"gpt-4o","messages":[{"role":"user","content":"AKIAIOSFODNN7REALKEY"}]}'
```

`scripts/smoke.sh bin/aigatekeeper` runs a self-contained end-to-end check against a local TLS
upstream (Linux/macOS); `scripts/smoke.ps1` exercises an already running proxy on Windows.

## Quick start (Docker)

```sh
docker compose -f deploy/docker-compose.yml run --rm aigatekeeper ca init --out /certs   # once
docker compose -f deploy/docker-compose.yml up -d
curl http://127.0.0.1:9090/ca.crt -o aigatekeeper-ca.crt
```

The image is built from `scratch`, runs as UID 65532, and mounts `certs/`, `configs/` and a data
volume. Environment variables prefixed `AIGK_` override paths and listeners (see the Dockerfile).

## Client setup

Install the CA on every workstation and route the AI tools through the proxy. Ready-to-use
snippets are in `configs/examples/`.

| Client | Proxy | Certificate |
|---|---|---|
| Windows trust store | | `certutil -addstore -f Root ca.crt` (admin shell) |
| macOS | | `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ca.crt` |
| Debian/Ubuntu | | copy to `/usr/local/share/ca-certificates/` and run `update-ca-certificates` |
| VS Code + GitHub Copilot | `"http.proxy": "http://proxy:8080"` (or `HTTPS_PROXY`) | OS trust store plus `NODE_EXTRA_CA_CERTS=ca.crt` |
| Cursor | `HTTPS_PROXY` | `SSL_CERT_FILE=ca.crt` (Cursor's own transport is protobuf; it is tunnelled, not inspected) |
| Python / Node SDKs | `HTTPS_PROXY` | `REQUESTS_CA_BUNDLE` / `NODE_EXTRA_CA_CERTS` |
| Ollama clients | none (localhost bypasses proxies) | run Ollama on 11435 and a `listen.reverse` entry on 11434 |

Windows note: the interception certificates carry no revocation information. Clients that use
Schannel with strict revocation checking (notably `curl.exe`) report
`CERT_TRUST_REVOCATION_STATUS_UNKNOWN`; pass `--ssl-revoke-best-effort` to curl. Browsers, Node,
Python and .NET's `HttpClient` do not hard-fail on unknown revocation status by default.

## Configuration

`configs/aigatekeeper.yaml` is documented inline. The important knobs:

- `services`: host regexes, which extractor parses the body, `block_mode` (`reject` or `synthetic`),
  `passthrough_paths` that are never inspected, and the `rules` to apply.
- `rules`: built-in `detectors` (AWS, GitHub, Slack, Google, OpenAI and Anthropic keys, JWT, private
  keys, high-entropy secrets, credit cards, email, US SSN, IBAN), plus `keywords` files and custom
  `regex` patterns, each with a `severity` and an `action` (`block`, `monitor`, `allow`).
- `allowlist`: literal values, patterns, email domains, client CIDRs, a bypass header for trusted
  automation, and JSON-pointer globs for segments that must not be scanned (tool schemas).
- `mode.monitor: true` never blocks and only logs, which is the recommended rollout setting.
- `limits`: body size caps, what to do with oversized or unparsable bodies, upstream timeout.
- `reload`: the file is watched and re-applied within a second; `POST /-/reload` and `SIGHUP` also
  work. Set `poll_interval` on Docker Desktop bind mounts.
- Relative paths in the file resolve against the file's own directory.

Environment overrides: `AIGK_LISTEN_FORWARD`, `AIGK_LISTEN_ADMIN`, `AIGK_CA_CERT`, `AIGK_CA_KEY`,
`AIGK_MODE_MONITOR`, `AIGK_TUNNEL_UNMATCHED`, `AIGK_AUDIT_FILE`, `AIGK_RELOAD_POLL_INTERVAL`,
`AIGK_UPSTREAM_PROXY`, `AIGK_TLS_UPSTREAM_INSECURE`.

## Audit log

One JSON object per line, for example:

```json
{"ts":"2026-09-10T09:14:02Z","kind":"request","request_id":"01J...","client_ip":"10.20.4.57",
 "listener":"forward","method":"POST","host":"api.githubcopilot.com","path":"/chat/completions",
 "service":"copilot","model":"gpt-4o","stream":true,"action":"block","block_mode":"synthetic",
 "reason":"dlp","rule":"secrets","findings":[{"detector":"aws_secret_key","severity":"critical",
 "confidence":0.9,"segment":"/messages/1/content","role":"user","preview":"wJal****EY"}],
 "bytes_in":812,"upstream_status":200,"latency_ms":4}
```

Other kinds: `tunnel`, `passthrough`, `tls_error`, `proxy_start`, `config_reload`. Counters are
exposed at `GET /metrics` on the admin listener (expvar JSON).

## Admin listener

`/healthz`, `/readyz`, `/ca.crt`, `POST /-/reload`, `/-/policy` (secret-free summary), `/metrics`.
It binds to 127.0.0.1 by default; keep it off the workstation network.

## Development

```sh
make test          # go test ./... -race (needs cgo)
make test-docker   # same, inside golang:1.27 (Windows hosts with Smart App Control, no cgo)
make build-noui    # static binary
make docker        # container image
```

## Security notes

- `certs/ca.key` can impersonate any host for machines that trust the CA. Restrict access to it.
- The forward listener should sit on a trusted network segment; it is not authenticated yet
  (proxy authentication and per-user attribution arrive in Phase 8).
- Findings are stored masked; enable `audit.include_preview: false` to drop previews entirely.

## License

Apache-2.0. See `LICENSE`.

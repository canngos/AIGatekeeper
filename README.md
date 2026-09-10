# AIGatekeeper

Self-hosted, open-source TLS-intercepting proxy that inspects GenAI traffic from IDE assistants
(GitHub Copilot, Tabnine, Ollama-backed tools) and API clients (OpenAI, Anthropic, Gemini), scans
prompts for secrets and PII, blocks violations before they leave your network, and records a
structured audit trail.

> Status: under active development. See `AIGatekeeper.md` for the original specification.

## How it works

1. Workstations point their HTTP proxy at AIGatekeeper and trust its root CA.
2. For known GenAI hosts the proxy terminates TLS with an on-the-fly certificate, extracts the
   prompt text from the JSON request, and runs the DLP engine over it.
3. Clean requests are forwarded unchanged. Violations are blocked with either an HTTP 403 or a
   synthetic completion that tells the developer why, so the IDE never hangs.
4. Every transaction is logged as JSON (stdout for your SIEM, SQLite for the built-in admin UI).
5. All other hosts pass through as opaque tunnels and are never decrypted.

## Quick start

```sh
aigatekeeper ca init                      # generates certs/ca.crt and certs/ca.key
aigatekeeper serve --config configs/aigatekeeper.yaml
curl -x http://127.0.0.1:8080 --cacert certs/ca.crt https://api.openai.com/v1/models
```

Full client setup (Windows trust store, VS Code, SDK environment variables, Ollama) and the
configuration reference will be documented as the corresponding phases land.

## Development

```sh
make test        # go test ./... -race
make build-noui  # static binary without the web UI
make build       # web UI + binary with the UI embedded
```

## License

Apache-2.0. See `LICENSE`.

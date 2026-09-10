# AIGatekeeper

Self-hosted, open-source TLS-intercepting proxy that inspects GenAI traffic from IDE assistants
(GitHub Copilot, Tabnine, Ollama-backed tools) and API clients (OpenAI, Anthropic, Gemini), scans
prompts for secrets and PII, blocks violations before they leave your network, and records a
structured audit trail. No third-party SaaS, one static binary, Apache-2.0.

> Status: all eight phases of the [implementation plan](AIGatekeeper.md) are complete: proxy and TLS
> interception, payload parsers, DLP engine, policy and block responses, hot reload, containerisation,
> the web console, and per-user attribution with alerting.

## How it works

1. Workstations point their HTTP proxy at AIGatekeeper and trust its root CA.
2. For hosts listed in the policy the proxy terminates TLS with an on-the-fly certificate, extracts
   the prompt text from the JSON request (OpenAI-compatible, Copilot, Anthropic, Gemini, Ollama, or a
   generic JSON walker), and runs the DLP detectors over it.
3. Clean requests are forwarded unchanged and streamed back without buffering. Violations are
   answered with either an HTTP 403 in the service's error format (`block_mode: reject`) or an HTTP 200
   synthetic completion that tells the developer why (`block_mode: synthetic`), so the IDE never hangs.
4. Every transaction is logged as one JSON line on stdout (for ELK/Splunk) with masked previews of
   the matched values. Prompt text is not persisted unless you switch it on.
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

## Watching your own machine

`deploy/local` sets the proxy up for a single workstation, aimed at GitHub Copilot: nothing is
blocked, the prompt text is recorded so you can read your own chat, and the console keeps a week of
history.

```powershell
cd deploy\local
.\setup.ps1                     # builds the image, makes the CA, sets a console password
docker compose up -d
```

`setup.ps1` prints the two commands that need an elevated shell (trusting the CA) and the VS Code
settings to add. See "Reading your own Copilot chat" below.

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
| JetBrains IDEs + Copilot | Settings > Tools > GitHub Copilot > Network > Customize HTTP proxy (the plugin has its own stack and does not follow the IDE proxy), and the IDE proxy for everything else | OS trust store plus `NODE_EXTRA_CA_CERTS=ca.crt`; verify with the "Copilot: Log CA Certificates" action |
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

## Web console

The admin listener serves a console at `http://127.0.0.1:9090/` with six views:

- **Overview** shows what proportion of traffic was forwarded, flagged and stopped over a chosen
  window, requests over time, and which rules, detectors, services and workstations were involved.
- **Traffic** streams inspected requests live, or searches the recorded history. Each row expands to
  show what was found, where in the prompt, and the masked match.
- **Policy** edits services, rules and exceptions as forms, or the file directly with the comments
  intact. Check validates without saving; Apply writes the file and the proxy reloads in place.
- **Tester** runs a prompt or a captured request body through the live policy, or through a
  candidate configuration, without contacting a provider.
- **People** lists who is running into the policy and the alerts raised about them, with the
  contributing requests and an acknowledge button.
- **Status** reports the loaded policy, listeners, attribution, alerting, reload history and audit
  sink health, and can send a test alert through the real relay.

The console and its API stay closed until a credential exists:

```sh
aigatekeeper admin hash-password        # prompts, prints a bcrypt hash
# then set admin.auth.password_hash in the config, or AIGK_ADMIN_PASSWORD_HASH
```

Sessions use an HttpOnly cookie with double-submit CSRF; `admin.auth.token` enables a bearer token
for scripting. Set `audit.sqlite.enabled: true` to record the searchable history the Overview and
Traffic history views read; without it the live feed and the API still work.

The console is embedded in the binary, so the container needs no Node at runtime. A binary built
without it (`make build-noui`) serves a short page explaining how to build it, and the API is
unaffected.

## Who sent it, and telling someone

By default an event carries a client address, which names a workstation and changes with the DHCP
lease. Two optional sources turn that into a person:

- **Proxy authentication** (`identity.proxy_auth`) makes the proxy answer 407 until a workstation
  sends credentials, checked against a bcrypt `htpasswd` file or an LDAP bind. Credentials ride on
  the CONNECT request, so every request later decrypted inside that tunnel is attributed to the same
  person, and the header never reaches the provider. VS Code sends them from
  `"http.proxy": "http://alice@proxy:8080"` or `http.proxyAuthorization`.
- **Reverse DNS** (`identity.reverse_dns`) names the workstation, cached and time-boxed. It is a
  hint, not authentication.

With `alerts.rules` configured, repeated violations by one person raise an alert:

```yaml
alerts:
  email: { host: smtp.corp.local, from: aigatekeeper@corp.local, password_env: AIGK_SMTP_PASSWORD }
  rules:
    - id: repeat-offender
      match: { actions: [block], min_severity: high }
      group_by: user            # falls back to device, then address
      threshold: 3
      window: 24h
      cooldown: 24h             # at most one message per person per day
      notify:
        - { type: email, to: [security@corp.local] }
        - { type: email, to_manager: true }   # manager from identity.directory
        - { type: webhook, name: soc }
```

The message lists the contributing requests with the same masked previews the audit log keeps; the
matched value never leaves the proxy. A destination that fails does not stop the others, and the
failure is recorded on the alert. The console's People view lists who is running into the policy and
lets an analyst acknowledge an alert; Status has a button that sends a sample through the real relay.

Emailing the person who triggered an alert (`to_user`) is off unless you switch it on. Automated mail
to an employee about their own activity is employee monitoring, and in many places it needs
works-council or privacy sign-off before you enable it. Running in `mode.monitor` while you tune the
rules is the safer way to start.

### JetBrains IDEs

The Copilot plugin runs its completions and chat through a bundled Node runtime
(`copilot-agent/native/<platform>/copilot-language-server`), not through the IDE's Java HTTP stack,
so the IDE's own proxy setting does not reach it. Configure it in two places:

- **Settings > Tools > GitHub Copilot > Network**: tick *Customize HTTP proxy* and point it at the
  gatekeeper. The *Networking* mode there decides which stack it uses: `Native` is the bundled Node
  one, which reads `NODE_EXTRA_CA_CERTS`; `Client` is the IDE's, which uses the IDE trust store and
  the Windows root store. If certificate errors persist in `Native`, switching to `Client` is the
  documented fallback.
- **Settings > Appearance & Behavior > System Settings > HTTP Proxy**: covers the IDE itself.

Set `NODE_EXTRA_CA_CERTS` as a **user** environment variable, then quit the IDE completely and start
it again: the language server inherits its environment at launch, so reopening a project is not
enough. To confirm the certificate arrived, double-press Shift and run the action
**Copilot: Log CA Certificates**, which dumps the authorities the agent actually loaded.

## Reading your own Copilot chat

By default the audit trail records what was *found* in a prompt, never the prompt itself. For a
pilot on your own machine that is usually too little: you want to see what Copilot actually sends.
Turn it on with:

```yaml
audit:
  capture_prompts: true
  max_prompt_bytes: 32KiB     # longer prompts are truncated
```

Every inspected request then carries its extracted text, shown under "What was sent" when you expand
a row in Traffic. It is stored in the history database alongside the event and deleted by the same
retention sweep.

Leave this off in a real deployment. A proxy that keeps a copy of everything your developers type is
a bigger liability than the leaks it prevents, and it turns the audit database into the most
sensitive store you own.

## Admin listener

Operational endpoints: `/healthz`, `/readyz`, `/ca.crt`, `POST /-/reload`, `/-/policy` (secret-free
summary), `/metrics`. JSON API under `/api/v1/`. It binds to 127.0.0.1 by default; on any other
address set `admin.tls_cert` and `admin.tls_key`, and keep it off the workstation network.

## Development

```sh
make test          # go test ./... -race (needs cgo)
make test-docker   # same, inside golang:1.27 (Windows hosts with Smart App Control, no cgo)
make test-ui       # frontend tests (vitest)
make build-noui    # static binary without the console
make build         # console + binary with the console embedded
make docker        # container image (builds the console in its own stage)
```

For the console, `cd web && npm run dev` serves it on port 5173 and proxies the API to a gatekeeper
running on 9090, so cookies stay same-origin. Add `http://localhost:5173` to `admin.cors_origins`
only if you run the two on different origins.

## Security notes

- `certs/ca.key` can impersonate any host for machines that trust the CA. Restrict access to it.
- Proxy credentials travel as HTTP Basic between workstation and proxy, so the forward listener
  belongs on a trusted network segment. Without `identity.proxy_auth` the listener is unauthenticated
  and anyone who can reach it can use it.
- Findings are stored masked. Prompt text is stored only if you set `audit.capture_prompts`.
- The admin listener binds to loopback by default. On any other address set `admin.tls_cert` and
  `admin.tls_key`, or put it behind a TLS terminator.

## License

Apache-2.0. See `LICENSE`.

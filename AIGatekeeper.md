# AIGatekeeper - Implementation Plan

## 1. Project Overview
**Objective:** Develop an open-source, self-hosted Man-in-the-Middle (MITM) proxy to intercept, inspect, and secure GenAI traffic (specifically targeting IDE extensions like GitHub Copilot, Cursor, Tabnine, and standard API requests).
**Target Audience:** Enterprise security teams needing Data Loss Prevention (DLP) and compliance without relying on third-party SaaS solutions.
**Key Mechanism:** TLS Interception (SSL Inspection) via a custom Root CA deployed on the client network.

## 2. System Architecture

The system operates as a forward proxy and consists of 5 core modules:

1.  **TLS Interceptor (Core Proxy):** Handles TCP/HTTP connections, decrypts inbound TLS traffic using a dynamically generated certificate, and re-encrypts outbound traffic to the destination (e.g., `api.githubcopilot.com`).
2.  **Payload Parser:** Identifies the target service, extracts the JSON payload, and isolates the specific `prompt` or `content` fields containing the developer's input.
3.  **Policy & Config Manager:** Loads rules (YAML/JSON), defining which endpoints to intercept and which DLP patterns (Regex/Heuristics) to apply.
4.  **DLP Engine:** Scans the extracted text for sensitive data (Credentials, PII, PHI, Internal Project Names). Returns a safety boolean and the violation type.
5.  **Action & Audit Engine:** 
    *   If safe: Forwards the request.
    *   If unsafe: Blocks the request, returning a mocked HTTP 403 response to prevent IDE crashes.
    *   Logs the transaction in structured JSON for observability (ELK/Splunk).

## 3. Implementation Phases

### Phase 1: Core Proxy & TLS Interception
*   **Goal:** Establish the fundamental MITM capability.
*   **Tasks:**
    *   Implement an HTTP/HTTPS proxy using Go (e.g., leveraging `elazarl/goproxy`).
    *   Create a local CA certificate generation utility (`ca.crt`, `ca.key`).
    *   Configure the proxy to decrypt traffic matching specific regex domains (e.g., `^api\.githubcopilot\.com$`).

### Phase 2: Payload Parsing & Reverse Engineering
*   **Goal:** Isolate the prompt text from specific AI tools.
*   **Tasks:**
    *   Capture standard Copilot/OpenAI HTTP POST requests.
    *   Write structural parsers to extract `messages[].content` or equivalent fields.
    *   Ensure the parser can handle chunked/streamed requests if necessary.

### Phase 3: DLP Engine Implementation
*   **Goal:** Detect sensitive information in the parsed prompt.
*   **Tasks:**
    *   Implement a regex-based scanner for standard PII (Credit Cards, Emails) and Secrets (AWS Keys, JWTs).
    *   Create a pluggable interface (`Scanner` interface in Go) to allow future integration with external NLP services (like Microsoft Presidio).

### Phase 4: Action Engine & Mock Responses
*   **Goal:** Safely block non-compliant requests.
*   **Tasks:**
    *   Implement blocking logic that stops the HTTP request from leaving the network.
    *   Craft realistic, mock HTTP response payloads matching the expected format of the IDE extension (e.g., returning a valid JSON structure with an error message) so the IDE does not hang or crash.

### Phase 5: Configuration & Observability
*   **Goal:** Make the system enterprise-ready.
*   **Tasks:**
    *   Implement YAML-based configuration for dynamic rule management (hot-reloading preferred).
    *   Implement structured JSON logging (stdout) for every intercepted request (Timestamp, Client IP, Target, Action Taken, Violation Type).

### Phase 6: Containerization & Deployment
*   **Goal:** Ensure plug-and-play capability.
*   **Tasks:**
    *   Create a multi-stage `Dockerfile` (using `scratch` or `alpine`) to output a minimal Go binary.
    *   Create a `docker-compose.yml` defining volume mounts for certificates and configuration files.

## 4. Suggested Project Structure (Go)

```text
aigatekeeper/
├── cmd/
│   └── server/          # main.go (Application entry point)
├── internal/
│   ├── proxy/           # MITM HTTPS server & TLS management
│   ├── parser/          # Service-specific JSON extractors
│   ├── dlp/             # Regex engine and scanning interfaces
│   ├── config/          # YAML loader and hot-reload logic
│   └── audit/           # Structured JSON logger
├── configs/             # Default policies.yaml
├── certs/               # Auto-generated CA files (git-ignored)
├── Dockerfile
└── README.md
```

## 5. Technology Stack
*   **Primary Language:** Go (Golang) - Chosen for high concurrency (Goroutines), low latency, native `net/http` and `crypto/tls` strength, and single-binary compilation.
*   **Proxy Library:** `elazarl/goproxy` (or standard `net/http` reverse proxy tailored for MITM).
*   **Configuration:** `gopkg.in/yaml.v3` for YAML parsing.
*   **Deployment:** Docker, Docker Compose.

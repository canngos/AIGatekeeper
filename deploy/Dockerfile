# syntax=docker/dockerfile:1
# Multi-stage build producing a static, non-root AIGatekeeper image.
# Build from the repository root:  docker build -f deploy/Dockerfile -t aigatekeeper .

ARG GO_VERSION=1.27
ARG NODE_VERSION=24

# The admin UI is built here and embedded into the binary by the Go stage,
# so the image needs no Node at runtime and the repository needs no
# committed build output.
FROM node:${NODE_VERSION}-alpine AS ui
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci
COPY web/ ./
RUN npm run build

FROM golang:${GO_VERSION}-alpine AS build
ARG VERSION=dev
WORKDIR /src
RUN apk add --no-cache git
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
COPY --from=ui /web/dist ./web/dist
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" \
      -o /out/aigatekeeper ./cmd/aigatekeeper
# Empty, non-root-owned directories for the final image (scratch has no mkdir),
# and the shipped config rewritten to the image's fixed layout.
RUN mkdir -p /empty && chown 65532:65532 /empty \
 && sed -e 's|\.\./certs/|/certs/|g' -e 's|\.\./data/|/data/|g' configs/aigatekeeper.yaml > /out/aigatekeeper.yaml

FROM alpine:3 AS certs
RUN apk add --no-cache ca-certificates

FROM scratch
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/aigatekeeper /aigatekeeper
COPY --from=build --chown=65532:65532 /out/aigatekeeper.yaml /etc/aigatekeeper/aigatekeeper.yaml
COPY --chown=65532:65532 configs/keywords.txt /etc/aigatekeeper/keywords.txt
# Writable locations for the generated CA (/certs) and the audit history store (/data).
COPY --from=build --chown=65532:65532 /empty /certs
COPY --from=build --chown=65532:65532 /empty /data
USER 65532:65532
ENV AIGK_LISTEN_FORWARD=0.0.0.0:8080 \
    AIGK_LISTEN_ADMIN=0.0.0.0:9090
EXPOSE 8080 9090 11434
VOLUME ["/certs", "/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["/aigatekeeper", "healthcheck", "--url", "http://127.0.0.1:9090/healthz"]
ENTRYPOINT ["/aigatekeeper"]
CMD ["serve", "--config", "/etc/aigatekeeper/aigatekeeper.yaml"]

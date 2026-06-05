# Multi-arch container image for Hopframe.
#
# This Dockerfile is the single source of truth for the
# ghcr.io/jlupsp/hopframe image. It works two ways:
#
#   1. Anyone who clones the repo can run `docker build -t hopframe .`
#      and get a working local image. No Go install needed.
#   2. CI publishes the same Dockerfile to ghcr.io on every release tag
#      via docker/build-push-action with --platform linux/amd64,linux/arm64.
#
# Usage:
#
#   docker compose up                           full stack, bundled stub MCP
#   docker compose up --build                   force rebuild from this Dockerfile
#   docker run -p 7090:7090 hopframe            just the control plane
#   docker run hopframe mcp-sensor --config ... just the sensor

ARG GO_VERSION=1.25

FROM golang:${GO_VERSION}-alpine AS builder
WORKDIR /src

# Layer: dep download (caches across source changes)
COPY go.mod go.sum ./
RUN go mod download

# Layer: source
COPY . .

ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown
ARG TARGETOS=linux
ARG TARGETARCH=amd64

ENV CGO_ENABLED=0 \
    GOOS=${TARGETOS} \
    GOARCH=${TARGETARCH}

# Build every operator-facing binary in one pass, with version
# metadata stamped into each via -X main.{version,commit,date}.
# Stub binaries are not shipped in the published image; they exist
# only to support the local `make demo` flow.
RUN set -eux; \
    for cmd in control-plane mcp-sensor a2a-sensor mcp-stdio-sensor hopframe hopframe-export dumb-proxy; do \
        go build \
            -trimpath \
            -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
            -o /out/${cmd} \
            ./cmd/${cmd}; \
    done

# Final stage: distroless static, nonroot. No shell, no package
# manager, no setuid binaries. The smallest credible attack surface
# for a security tool.
FROM gcr.io/distroless/static-debian12:nonroot

LABEL org.opencontainers.image.title="hopframe" \
      org.opencontainers.image.description="Source-available security mesh for MCP and A2A agent traffic" \
      org.opencontainers.image.source="https://github.com/jLuPSP/hopframe" \
      org.opencontainers.image.vendor="Jordan Lu" \
      org.opencontainers.image.licenses="BSL-1.1"

COPY --from=builder /out/* /usr/local/bin/
COPY --from=builder /src/LICENSE /src/NOTICE /
COPY --from=builder /src/content /etc/hopframe/content

USER nonroot:nonroot
EXPOSE 7090

# Default to the control plane. docker-compose.yml and the Helm
# chart override per-service via `command:`.
ENTRYPOINT ["/usr/local/bin/control-plane"]
CMD ["--addr=:7090", "--log=/var/lib/hopframe/events.ndjson"]

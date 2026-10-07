# Build args must be immutable references from build/base-images.lock.
ARG GO_IMAGE=golang:1.26.3-bookworm@sha256:3bf5b04541eb4a37fe62aa1bc9c98a1dec09db9d2e79c1d2eb54e3c9d08dbca9
ARG RUNTIME_IMAGE=debian:12.13-slim@sha256:2749ca60ffb3c42de053229d7967d292d7dad1067936b38995da0bbfb96c4c23
FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
ARG RELEASE
RUN test "$(go env GOVERSION)" = go1.26.3 && \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
    -ldflags "-s -w -X webscan/internal/deploy.Release=$RELEASE" -o /webscan ./cmd/webscan
FROM ${RUNTIME_IMAGE} AS runtime
COPY config/bootstrap-ca.crt /etc/ssl/certs/ca-certificates.crt
RUN sed -i s,http://deb.debian.org,https://deb.debian.org,g /etc/apt/sources.list.d/debian.sources && apt-get -o Acquire::Retries=3 -o Acquire::https::Timeout=30 update && apt-get -o Acquire::Retries=3 -o Acquire::https::Timeout=30 install -y --no-install-recommends ca-certificates=20250419~deb12u1 tzdata=2026c-0+deb12u1 \
    && rm -rf /var/lib/apt/lists/*
ENTRYPOINT ["/usr/local/bin/webscan"]
FROM runtime AS central
# The shared binary provides both the central service and the deploy CLI.
COPY --from=builder /webscan /usr/local/bin/webscan
CMD ["central", "--config", "/etc/webscan-v1/runtime.json"]
FROM runtime AS agent
RUN sed -i s,http://deb.debian.org,https://deb.debian.org,g /etc/apt/sources.list.d/debian.sources && apt-get -o Acquire::Retries=3 -o Acquire::https::Timeout=30 update && apt-get -o Acquire::Retries=3 -o Acquire::https::Timeout=30 install -y --no-install-recommends yara=4.2.3-4 clamdscan=1.4.3+dfsg-1~deb12u2 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /webscan /usr/local/bin/webscan
CMD ["agent", "--config", "/etc/webscan-v1/runtime.json"]

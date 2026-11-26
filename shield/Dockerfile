# ── Build stage ──────────────────────────────────────────────────────────────
FROM golang:1.26-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev COMMIT=none BUILD_DATE=unknown
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags "-s -w \
      -X github.com/Yoosuf01/mcpguard/shield/internal/version.Version=${VERSION} \
      -X github.com/Yoosuf01/mcpguard/shield/internal/version.Commit=${COMMIT} \
      -X github.com/Yoosuf01/mcpguard/shield/internal/version.BuildDate=${BUILD_DATE}" \
    -o /out/mcpguard ./cmd/shield

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM gcr.io/distroless/static:nonroot
LABEL org.opencontainers.image.title="MCPGuard"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.source="https://github.com/Yoosuf01/mcpguard"
COPY --from=builder /out/mcpguard /mcpguard
COPY --from=builder /src/configs  /configs
EXPOSE 8080 8081
ENTRYPOINT ["/mcpguard"]
CMD ["-config", "/configs/shield.yaml"]

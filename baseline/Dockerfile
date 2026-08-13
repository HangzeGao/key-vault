FROM golang:1.25-alpine AS backend-build
WORKDIR /src
RUN apk add --no-cache ca-certificates git
COPY go.mod go.sum ./
RUN go mod download
COPY . ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/key-vault ./cmd/key-vault
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/kvltctl ./cmd/kvltctl

FROM alpine:3.21 AS runtime
RUN apk add --no-cache ca-certificates tpm2-tools
WORKDIR /app
COPY --from=backend-build /out/key-vault /app/key-vault
COPY --from=backend-build /out/kvltctl /app/kvltctl
RUN mkdir -p /tmp/kvlt-tpm /tmp/kvlt-wal
EXPOSE 8081
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=6 CMD wget -q -O - http://127.0.0.1:8080/healthz | grep -q '"status":"ok"' || exit 1
ENTRYPOINT ["/app/key-vault"]

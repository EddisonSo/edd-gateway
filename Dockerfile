FROM golang:1.25-bookworm AS builder

WORKDIR /build

# Copy go-gfs dependency
COPY go-gfs/ ./go-gfs/

# Copy gateway source
COPY edd-gateway/ ./edd-gateway/

WORKDIR /build/edd-gateway

# Download dependencies and build
RUN go mod download
RUN CGO_ENABLED=0 go build -o /gateway .

# Final image
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /gateway /gateway
COPY --from=builder /build/edd-gateway/routes.yaml /routes.yaml

WORKDIR /

EXPOSE 22 80 443

ENTRYPOINT ["/gateway"]

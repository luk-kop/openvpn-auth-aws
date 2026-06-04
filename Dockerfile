FROM golang:1.26.4-alpine AS builder

WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build
RUN CGO_ENABLED=0 GOOS=linux go build -o openvpn-auth-daemon ./cmd/openvpn-auth-daemon

FROM alpine:3.23

RUN apk --no-cache add ca-certificates

WORKDIR /app

COPY --from=builder /build/openvpn-auth-daemon .

RUN adduser -S -D -H -u 10001 -G daemon appuser
USER appuser

EXPOSE 8080

CMD ["/app/openvpn-auth-daemon"]

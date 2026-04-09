## ── Build stage ─────────────────────────────────────────────
FROM golang:1.22-alpine AS builder

WORKDIR /app

COPY go.mod .
COPY main.go .

RUN go build -o http-auth-app .

## ── Runtime stage ────────────────────────────────────────────
FROM alpine:3.19

WORKDIR /app

COPY --from=builder /app/http-auth-app .

EXPOSE 8080

ENTRYPOINT ["./http-auth-app"]

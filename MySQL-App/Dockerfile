FROM golang:1.22-alpine AS builder

WORKDIR /app

COPY go.mod ./
RUN go mod download

COPY . .
RUN go build -o mysql-app .

# ---

FROM alpine:3.19

WORKDIR /app

COPY --from=builder /app/mysql-app .

EXPOSE 8082

CMD ["./mysql-app"]

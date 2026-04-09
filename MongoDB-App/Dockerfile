FROM golang:1.22-alpine AS builder

WORKDIR /app

COPY go.mod ./
RUN go mod download

COPY . .
RUN go build -o mongo-app .

# ---

FROM alpine:3.19

WORKDIR /app

COPY --from=builder /app/mongo-app .

EXPOSE 8083

CMD ["./mongo-app"]

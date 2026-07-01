FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY outbound-secrets-app ./outbound-secrets-app
EXPOSE 8080
ENTRYPOINT ["./outbound-secrets-app"]

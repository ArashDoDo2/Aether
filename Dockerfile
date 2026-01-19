FROM golang:1.24-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o /bin/aether-client ./cmd/client
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o /bin/aether-server ./cmd/server

FROM alpine:3.18 AS runtime
RUN apk add --no-cache ca-certificates
COPY --from=builder /bin/aether-client /usr/local/bin/aether-client
COPY --from=builder /bin/aether-server /usr/local/bin/aether-server

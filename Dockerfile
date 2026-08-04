# syntax=docker/dockerfile:1.7
FROM golang:1.26.5-alpine3.23 AS build
WORKDIR /src
RUN apk add --no-cache ca-certificates git
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build \
      -trimpath \
      -ldflags="-s -w -buildid=" \
      -o /out/ferventio-backend \
      ./cmd/ferventio-backend

FROM alpine:3.24
RUN apk add --no-cache ca-certificates tzdata wget \
    && addgroup -S -g 10001 ferventio \
    && adduser -S -D -H -u 10001 -G ferventio ferventio
WORKDIR /app
COPY --from=build --chown=ferventio:ferventio /out/ferventio-backend /usr/local/bin/ferventio-backend
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/ferventio-backend"]

# Stage 1: Build the Go binary
FROM golang:1.23-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-w -s -X main.version=$VERSION" \
    -o /out/git-smells-wrong ./cmd/git-smells-wrong

# Stage 2: Minimal runtime image
FROM alpine:3.20

RUN apk add --no-cache git bash ca-certificates jq \
    && adduser -D -u 10001 appuser

USER 10001
WORKDIR /home/appuser

COPY --from=builder /out/git-smells-wrong /usr/local/bin/git-smells-wrong

ENTRYPOINT ["git-smells-wrong"]
CMD ["--help"]

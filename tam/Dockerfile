FROM golang:1.25.3-alpine AS build

WORKDIR /src

# Install build tooling and certificate bundle for module downloads.
RUN apk add --no-cache build-base ca-certificates git

# Pre-fetch module dependencies for better layer caching.
COPY go.mod go.sum ./
RUN go mod download

# Copy the full source tree and build the tam4wasm-mock binary.
COPY . .
RUN CGO_ENABLED=0 GOOS=linux \
    go build -trimpath -o /out/tam4wasm-mock ./cmd/tam4wasm-mock


FROM alpine:3.20 AS runtime

WORKDIR /app

# Install certificate bundle for outbound TLS calls to verifier endpoints.
RUN apk add --no-cache ca-certificates

# Copy the compiled binary and runtime resources.
COPY --from=build /out/tam4wasm-mock ./tam4wasm-mock
COPY --from=build /src/resources ./resources

# Default configuration mirrors the CLI flags defined in cmd/tam4wasm-mock/main.go.
ENV TAM4WASM_ADDR=":8080" \
    TAM4WASM_DISABLE_COSE="false" \
    TAM4WASM_CHALLENGE_SERVER="" \
    TAM4WASM_CHALLENGE_CONTENT_TYPE="application/psa-attestation-token" \
    TAM4WASM_CHALLENGE_INSECURE_TLS="true" \
    TAM4WASM_CHALLENGE_TIMEOUT="1m0s"

EXPOSE 8080

ENTRYPOINT ["./tam4wasm-mock"]

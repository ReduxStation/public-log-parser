# Multi-stage build of tg-public-log-parser.
# Stage 1: build the release binary against the full Rust toolchain.
# Stage 2: copy the binary into a minimal runtime image.

FROM rust:1-slim AS builder
WORKDIR /src

# Install native build deps for the release link (openssl-sys, etc.)
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        pkg-config \
        libssl-dev \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Cache deps before copying source for faster incremental builds
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && cargo build --release && rm -rf src

# Real source build
COPY src ./src
RUN touch src/main.rs && cargo build --release


FROM debian:12-slim AS runtime
WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        libssl3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/target/release/tg-public-log-parser /usr/local/bin/tg-public-log-parser

# config.toml is loaded from CWD at runtime; mount one in via docker-compose.
EXPOSE 8090
ENTRYPOINT ["/usr/local/bin/tg-public-log-parser"]

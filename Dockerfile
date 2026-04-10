# --- Stage 1: Builder ---
FROM rust:1.85-slim-bookworm AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace Cargo files first for dependency caching
COPY Cargo.toml ./
COPY server/Cargo.toml server/

# Create dummy source to cache dependency downloads
RUN mkdir -p server/src && \
    echo "fn main() {}" > server/src/main.rs && \
    cargo fetch --manifest-path server/Cargo.toml || true

# Copy actual source
COPY server/src server/src

# Build in release mode
RUN cargo build --release --manifest-path server/Cargo.toml && \
    cp /app/target/release/w9-tools-server /usr/local/bin/w9-tools-server

# --- Stage 2: Runtime ---
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    wget \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash appuser

WORKDIR /app

RUN mkdir -p /app/data /app/uploads && chown -R appuser:appuser /app

USER appuser

COPY --from=builder /usr/local/bin/w9-tools-server /usr/local/bin/w9-tools-server

ENV HOST=0.0.0.0
ENV PORT=8080

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --retries=3 --start-period=30s \
    CMD wget --quiet --tries=1 --spider http://localhost:8080/api/health || exit 1

ENTRYPOINT ["w9-tools-server"]

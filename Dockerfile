# === Tier 1: Dependency Preparation ===

# Stage 1: chef — base image with cargo-chef
ARG RUST_VERSION=1.92
FROM lukemathwalker/cargo-chef:latest-rust-${RUST_VERSION}-bookworm AS chef
WORKDIR /app

# Stage 2: planner — generate dependency recipe
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# Stage 3: cook — compile dependencies (cached until Cargo.toml/Cargo.lock change)
FROM chef AS cook

RUN apt-get update && apt-get install -y --no-install-recommends \
    protobuf-compiler \
    gcc \
    make \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

# === Tier 2: Source Compilation ===

# Stage 4: builder — compile all binaries
FROM cook AS builder
COPY . .
RUN cargo build --release --bin rvc --bin rvc-signer --bin rvc-keygen

# === Tier 3: Runtime Images ===

# Stage 5: rvc — validator client runtime
FROM debian:bookworm-slim AS rvc

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libgcc-s1 \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --gid 10001 rvc && \
    useradd --uid 10001 --gid rvc --shell /usr/sbin/nologin --create-home rvc

RUN mkdir -p /data/keystores /config /certs && \
    chown -R rvc:rvc /data /config /certs

COPY --from=builder /app/target/release/rvc /usr/local/bin/rvc

VOLUME ["/data", "/config"]

EXPOSE 8080 5062

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["curl", "-f", "http://localhost:8080/healthz"]

USER rvc

ENTRYPOINT ["/usr/local/bin/rvc"]

# Stage 6: rvc-signer — remote signer runtime
FROM debian:bookworm-slim AS rvc-signer

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libgcc-s1 \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --gid 10001 rvc && \
    useradd --uid 10001 --gid rvc --shell /usr/sbin/nologin --create-home rvc

RUN mkdir -p /data /config /certs && \
    chown -R rvc:rvc /data /config /certs

COPY --from=builder /app/target/release/rvc-signer /usr/local/bin/rvc-signer

VOLUME ["/data", "/config", "/certs"]

EXPOSE 50051 9101

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["curl", "-f", "http://localhost:9101/healthz"]

USER rvc

ENTRYPOINT ["/usr/local/bin/rvc-signer"]

# Stage 7: rvc-keygen — key generation CLI
FROM debian:bookworm-slim AS rvc-keygen

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libgcc-s1 \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --gid 10001 rvc && \
    useradd --uid 10001 --gid rvc --shell /usr/sbin/nologin --create-home rvc

RUN mkdir -p /data/keystores && \
    chown -R rvc:rvc /data

COPY --from=builder /app/target/release/rvc-keygen /usr/local/bin/rvc-keygen

VOLUME ["/data"]

USER rvc

ENTRYPOINT ["/usr/local/bin/rvc-keygen"]

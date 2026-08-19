# syntax=docker/dockerfile:1.7
FROM --platform=linux/amd64 node:24-bookworm-slim AS web-builder

WORKDIR /build/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM --platform=linux/amd64 rust:1.97.1-bookworm AS builder

WORKDIR /build
COPY rust-toolchain.toml /build/rust-toolchain.toml
COPY security-service/Cargo.toml security-service/Cargo.lock /build/security-service/
COPY security-service/src/ /build/security-service/src/
RUN cargo build --locked --release --manifest-path /build/security-service/Cargo.toml \
    --bin security-service --bin lattice-security-cli

FROM --platform=linux/amd64 debian:bookworm-slim

LABEL org.opencontainers.image.title="lattice-security security-service" \
      org.opencontainers.image.description="Public API, SQLite cache, and scheduler"

RUN groupadd --system --gid 10001 lattice-security \
    && useradd --system --uid 10001 --gid lattice-security --home-dir /nonexistent --shell /usr/sbin/nologin lattice-security \
    && mkdir -p /var/lib/lattice-security \
    && chown lattice-security:lattice-security /var/lib/lattice-security

COPY --from=builder /build/security-service/target/release/security-service /usr/local/bin/security-service
COPY --from=builder /build/security-service/target/release/lattice-security-cli /usr/local/bin/lattice-security-cli
COPY --from=web-builder /build/web/dist/ /usr/share/lattice-security/web/
ENV LATTICE_SECURITY_BIND=0.0.0.0:8080 \
    LATTICE_SECURITY_DATABASE=/var/lib/lattice-security/lattice-security.db \
    LATTICE_SECURITY_WEB_DIR=/usr/share/lattice-security/web \
    ESTIMATOR_API_URL=http://estimator-api:8000/ \
    RUST_LOG=info

EXPOSE 8080
VOLUME ["/var/lib/lattice-security"]
USER 10001:10001

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["security-service", "healthcheck"]

ENTRYPOINT ["security-service"]

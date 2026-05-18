# syntax=docker/dockerfile:1.6
#
# Multi-stage build for lumi-server v2.
#
# Phase 2+ requires cgo (yrs/yffi for the CRDT engine). The builder
# stage compiles libyrs.a from the y-crdt submodule via cargo, then
# Go links it statically. The runtime image uses distroless/base
# because it includes glibc — distroless/static cannot load even a
# minimally-cgo binary.

# ---- Build stage -----------------------------------------------------------
FROM golang:1.25-bookworm AS builder
WORKDIR /src

# Install Rust toolchain for yffi. Pin to a known-good MSRV that
# matches third_party/y-crdt v0.26.0 (Rust 1.79+; we use stable).
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        build-essential \
        curl \
    && rm -rf /var/lib/apt/lists/* \
    && curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
       sh -s -- --default-toolchain stable -y --profile minimal
ENV PATH="/root/.cargo/bin:${PATH}"

# Pre-fetch Go deps for a stable cache layer.
COPY go.mod go.sum ./
RUN go mod download

# Bring in the source. third_party/y-crdt is a submodule on the host;
# `git submodule update --init --recursive` must have run before
# `docker build`, or the Dockerfile will fail at the cargo step.
COPY . .

# Build yffi static lib + copy header into the project tree. This
# mirrors what `make libyrs` does on the host.
RUN cargo build --release -p yffi --manifest-path third_party/y-crdt/Cargo.toml \
    && mkdir -p internal/crdt/lib internal/crdt/include \
    && cp third_party/y-crdt/target/release/libyrs.a internal/crdt/lib/libyrs.a \
    && cp third_party/y-crdt/tests-ffi/include/libyrs.h internal/crdt/include/libyrs.h \
    && sed -i -E \
        -e 's|^typedef YDoc YDoc;|/* typedef YDoc YDoc; — removed for cgo */|' \
        -e 's|^typedef Branch Branch;|/* typedef Branch Branch; — removed for cgo */|' \
        -e 's|^typedef YSubscription YSubscription;|/* typedef YSubscription YSubscription; — removed for cgo */|' \
        internal/crdt/include/libyrs.h

# Build the server with cgo enabled. Strip + trimpath for size.
RUN CGO_ENABLED=1 go build \
        -trimpath \
        -ldflags="-s -w" \
        -o /out/lumi-server \
        ./cmd/lumi-server

# ---- Runtime stage ---------------------------------------------------------
FROM gcr.io/distroless/base-debian12:nonroot
COPY --from=builder /out/lumi-server /lumi-server

ENV LUMI_ROOT=/vaults \
    LUMI_PORT=8080

EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/lumi-server"]

# syntax=docker/dockerfile:1.29.0
#
# Multi-stage build for lumi-server v2.
#
# Phase 2+ requires cgo (yrs/yffi for the CRDT engine):
#   1. `yrs` stage: libyrs.a built by a pinned official Rust image. It only
#      depends on third_party/y-crdt, so Docker reuses it when only Go code
#      changes. (Replaces `curl sh.rustup.rs | sh` with a floating "stable".)
#   2. `builder` stage: Go links the static lib (same steps as `make libyrs`).
#   3. Runtime: distroless/base (glibc; distroless/static cannot load a cgo
#      binary), pinned by digest. Ships migrations/ (LUMI_MIGRATIONS_DIR) so
#      LUMI_AUTO_MIGRATE=true and `lumi-server migrate up` work in the
#      container, and /vaults owned by nonroot (65532) so a fresh named
#      volume inherits a writable owner.
# Both build images are bookworm (same glibc), so the .a links cleanly.
# Note: Go >= 1.27 rejects archives carrying LLVM bitcode sections in
# #cgo LDFLAGS; keep the Go image on 1.25.x (or strip bitcode) when bumping.

# ---- yrs (y-crdt) ----------------------------------------------------------
FROM rust:1.100.0-bookworm AS yrs
WORKDIR /src
COPY third_party/y-crdt ./third_party/y-crdt
RUN cargo build --release --locked -p yffi --manifest-path third_party/y-crdt/Cargo.toml

# ---- Go build --------------------------------------------------------------
FROM golang:1.25.14-bookworm AS builder
WORKDIR /src

# Pre-fetch Go deps for a stable cache layer.
COPY go.mod go.sum ./
RUN go mod download

# third_party/y-crdt is a submodule on the host; run
# `git submodule update --init --recursive` before `docker build`.
COPY . .

# Same result as `make libyrs`, with the archive from the yrs stage.
COPY --from=yrs /src/third_party/y-crdt/target/release/libyrs.a internal/crdt/lib/libyrs.a
RUN mkdir -p internal/crdt/include \
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
        ./cmd/lumi-server \
    && mkdir -p /out/vaults

# ---- Runtime ---------------------------------------------------------------
# distroless/base-debian12:nonroot as of 2026-11-22.
FROM gcr.io/distroless/base-debian12:nonroot@sha256:7f0c72cd138b442ae0deeb69c08b1acf5525439ba251a49ad93c320a061567e5
COPY --from=builder /out/lumi-server /lumi-server
COPY --from=builder /src/migrations /migrations
COPY --from=builder --chown=65532:65532 /out/vaults /vaults

ENV LUMI_ROOT=/vaults \
    LUMI_PORT=8080 \
    LUMI_MIGRATIONS_DIR=/migrations

EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/lumi-server"]

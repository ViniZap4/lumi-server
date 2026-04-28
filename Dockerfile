# syntax=docker/dockerfile:1.6

FROM golang:1.23-bookworm AS builder
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/lumi-server ./cmd/lumi-server

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /out/lumi-server /lumi-server

ENV LUMI_ROOT=/vaults \
    LUMI_PORT=8080

EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/lumi-server"]

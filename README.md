# lumi-server

> **🚧 Work in progress** — lumi is under active development. Features may change, break, or be incomplete.

HTTP/WebSocket server for [lumi](https://github.com/ViniZap4/lumi) — a local-first, markdown-based note-taking system.

Built with [Go](https://golang.org).

## Features

- RESTful API for notes and folders
- WebSocket hub for real-time sync
- Token-based authentication (`X-Lumi-Token`)
- CORS support for web client

## Run

```bash
LUMI_ROOT=/path/to/notes LUMI_PASSWORD=secret go run main.go
```

Or with Docker:

```bash
docker build -t lumi-server .
docker run -p 8080:8080 -v /path/to/notes:/notes \
  -e LUMI_PASSWORD=secret lumi-server
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `LUMI_ROOT` | `/notes` (Docker) / `./notes` | Notes directory |
| `LUMI_PASSWORD` | `dev` | Auth token (`-e` required in Docker) |
| `LUMI_PORT` | `8080` | Server port |
| `LUMI_SERVER_ID` | auto | Unique ID for peer sync |
| `LUMI_PEERS` | — | Comma-separated peer URLs |

## API

```
POST   /api/auth          Validate token (login)
GET    /api/folders       List folders
GET    /api/notes         List notes
GET    /api/notes/:id     Get note
POST   /api/notes         Create note
PUT    /api/notes/:id     Update note
DELETE /api/notes/:id     Delete note
WS     /ws?token=<token>  Real-time updates (token required)
```

All REST endpoints require `X-Lumi-Token` header. WebSocket requires `?token=` query param.

## Part of lumi

This is a component of the [lumi monorepo](https://github.com/ViniZap4/lumi).
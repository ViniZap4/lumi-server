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

Environment variables:
- `LUMI_ROOT` — path to notes directory
- `LUMI_PASSWORD` — auth token
- `LUMI_PORT` — server port (default: 8080)

## API

```
GET    /api/folders       List folders
GET    /api/notes         List notes
GET    /api/notes/:id     Get note
POST   /api/notes         Create note
PUT    /api/notes/:id     Update note
DELETE /api/notes/:id     Delete note
WS     /ws                Real-time updates
```

## Part of lumi

This is a component of the [lumi monorepo](https://github.com/ViniZap4/lumi).
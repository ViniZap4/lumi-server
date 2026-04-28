.PHONY: run build test test-integration smoke migrate migrate-down sqlc fmt lint dev clean tools

DATABASE_URL ?= postgres://lumi:lumi@localhost:5432/lumi?sslmode=disable

run:
	go run ./cmd/lumi-server

build:
	mkdir -p bin
	go build -trimpath -ldflags="-s -w" -o bin/lumi-server ./cmd/lumi-server

test:
	go test ./...

test-integration:
	go test -tags=integration ./...

smoke:
	docker compose up -d --build
	./scripts/smoke.sh
	docker compose down

migrate:
	go run ./cmd/lumi-server migrate up

migrate-down:
	go run ./cmd/lumi-server migrate down 1

sqlc:
	sqlc generate

fmt:
	gofmt -w .

lint:
	go vet ./...

dev:
	docker compose up -d postgres
	$(MAKE) migrate
	$(MAKE) run

tools:
	go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest

clean:
	rm -rf bin/

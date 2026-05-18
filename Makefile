.PHONY: run build test test-integration smoke migrate migrate-down sqlc fmt lint dev clean tools libyrs libyrs-clean

DATABASE_URL ?= postgres://lumi:lumi@localhost:5432/lumi?sslmode=disable

# ---- CRDT native lib (yrs) -------------------------------------------------
# yffi from vendor/y-crdt produces libyrs.a (static) + libyrs.dylib/.so.
# We copy the static lib + C header into internal/crdt/lib so the cgo wrapper
# has a stable, repository-local search path that does not change per build
# environment. The submodule is pinned to v0.26.0.
YRS_DIR     := third_party/y-crdt
YRS_OUT     := $(YRS_DIR)/target/release
CRDT_LIBDIR := internal/crdt/lib
CRDT_INCDIR := internal/crdt/include

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
  YRS_SHARED := libyrs.dylib
else
  YRS_SHARED := libyrs.so
endif

libyrs:
	cargo build --release -p yffi --manifest-path $(YRS_DIR)/Cargo.toml
	mkdir -p $(CRDT_LIBDIR) $(CRDT_INCDIR)
	cp $(YRS_OUT)/libyrs.a $(CRDT_LIBDIR)/libyrs.a
	cp $(YRS_DIR)/tests-ffi/include/libyrs.h $(CRDT_INCDIR)/libyrs.h
	# cbindgen emits redundant `typedef X X;` lines for opaque structs
	# that cgo rejects as a "type conversion loop". Patch them out.
	sed -i.bak -E \
		-e 's|^typedef YDoc YDoc;|/* typedef YDoc YDoc; — removed for cgo */|' \
		-e 's|^typedef Branch Branch;|/* typedef Branch Branch; — removed for cgo */|' \
		-e 's|^typedef YSubscription YSubscription;|/* typedef YSubscription YSubscription; — removed for cgo */|' \
		$(CRDT_INCDIR)/libyrs.h
	rm -f $(CRDT_INCDIR)/libyrs.h.bak

libyrs-clean:
	rm -rf $(CRDT_LIBDIR) $(CRDT_INCDIR)
	cargo clean --manifest-path $(YRS_DIR)/Cargo.toml || true

run: | $(CRDT_LIBDIR)/libyrs.a
	go run ./cmd/lumi-server

build: | $(CRDT_LIBDIR)/libyrs.a
	mkdir -p bin
	go build -trimpath -ldflags="-s -w" -o bin/lumi-server ./cmd/lumi-server

$(CRDT_LIBDIR)/libyrs.a:
	$(MAKE) libyrs

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

# Convenience: full clean including the vendored CRDT artefacts.
distclean: clean libyrs-clean

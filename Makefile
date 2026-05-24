.PHONY: build test test-integration lint fmt vet tidy clean help man

BIN     := drift
PKG     := github.com/sufforest/drift
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -ldflags "-X $(PKG)/internal/cli.Version=$(VERSION)"

help: ## Show this help
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build the drift binary
	go build $(LDFLAGS) -o $(BIN) ./cmd/drift/

test: ## Run unit tests
	go test ./...

test-integration: docker-up ## Run integration tests against MinIO (auto starts + stops docker compose)
	@trap 'docker compose down -v >/dev/null 2>&1' EXIT INT TERM; \
	go test -tags=integration -count=1 ./...

docker-up: ## Start MinIO (foreground for logs in another terminal: `docker compose logs -f`)
	docker compose up -d
	@echo "Waiting for MinIO to be healthy..."
	@for i in $$(seq 1 30); do \
		if docker compose ps minio --format '{{.Health}}' | grep -q healthy; then \
			echo "MinIO ready at http://127.0.0.1:9000 (console http://127.0.0.1:9001)"; \
			exit 0; \
		fi; \
		sleep 1; \
	done; \
	echo "MinIO did not become healthy in 30s"; \
	exit 1

docker-down: ## Stop MinIO and remove its volume
	docker compose down -v

lint: ## Run golangci-lint (requires golangci-lint installed)
	golangci-lint run

vet: ## Run go vet
	go vet ./...

fmt: ## Format all Go source
	gofmt -s -w .

tidy: ## Tidy go.mod / go.sum
	go mod tidy

clean: ## Remove build artifacts
	rm -f $(BIN)
	rm -rf man/

man: ## Generate man pages into ./man/
	go run ./cmd/drift-gen-man man/
	@echo "Man pages written to man/ — try: man -l man/drift.1"

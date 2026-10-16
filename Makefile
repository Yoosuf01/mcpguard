SHELL      := /bin/bash
BINARY     := mcpguard
BUILD_DIR  := bin
VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT     ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS    := -s -w \
  -X github.com/Yoosuf01/mcpguard/shield/internal/version.Version=$(VERSION) \
  -X github.com/Yoosuf01/mcpguard/shield/internal/version.Commit=$(COMMIT) \
  -X github.com/Yoosuf01/mcpguard/shield/internal/version.BuildDate=$(BUILD_DATE)

.PHONY: all build test test-cover lint vet tidy clean docker compose mint-token help

all: vet test build

build: ## Build the mcpguard binary
	@mkdir -p $(BUILD_DIR)
	cd shield && go build -ldflags "$(LDFLAGS)" -o ../$(BUILD_DIR)/$(BINARY) ./cmd/shield

test: ## Run all tests with race detector
	cd shield && go test -race -count=1 ./...

test-cover: ## Run tests and open HTML coverage report
	cd shield && go test -race -coverprofile=coverage.out ./...
	cd shield && go tool cover -html=coverage.out -o coverage.html

lint: ## Run golangci-lint
	cd shield && golangci-lint run ./...

vet: ## Run go vet
	cd shield && go vet ./...

tidy: ## Tidy go.mod
	cd shield && go mod tidy && go mod verify

clean: ## Remove build artefacts
	rm -rf $(BUILD_DIR) shield/coverage.out shield/coverage.html

docker: ## Build Docker image
	docker build --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) \
	  --build-arg BUILD_DATE=$(BUILD_DATE) -t mcpguard:$(VERSION) ./shield

compose: ## Start full local stack
	docker compose up --build

mint-token: ## Mint a dev agent JWT
	cd shield && go run ./cmd/shield -config configs/shield.yaml \
	  -mint -agent customer-support-bot -sub alice@example.com -scope "db:read crm:update"

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS=":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

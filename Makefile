SHELL := /bin/bash

COMPOSE      := docker compose -f docker-compose.dev.yml --env-file .env.dev
KEY_DIR      := docker/keys
DEV_KEY      := $(KEY_DIR)/dev_ed25519
GO_TEST_FLAGS := -count=1 -race

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show the available targets
	@grep -hE '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  %-14s %s\n", $$1, $$2}'

# ---------------------------------------------------------------------------
# Development stack
# ---------------------------------------------------------------------------

.PHONY: dev-env
dev-env: ## Create .env.dev from the example when it is missing
	@if [ ! -f .env.dev ]; then \
		cp .env.dev.example .env.dev; \
		echo "created .env.dev from the example"; \
		echo "replace every CHANGEME value before starting the stack"; \
		exit 1; \
	fi
	@if grep -qE '^[A-Z_]+=CHANGEME' .env.dev; then \
		echo "error: .env.dev still contains CHANGEME values"; \
		exit 1; \
	fi

.PHONY: dev-keys
dev-keys: ## Generate the development SSH key pair when it is missing
	@mkdir -p $(KEY_DIR)
	@if [ ! -f $(DEV_KEY) ]; then \
		ssh-keygen -t ed25519 -N '' -C 'unbound-web dev key' -f $(DEV_KEY); \
		echo "generated $(DEV_KEY)"; \
	else \
		echo "$(DEV_KEY) already exists"; \
	fi
	@chmod 600 $(DEV_KEY)

.PHONY: dev-up
dev-up: dev-env dev-keys ## Build and start the development stack
	$(COMPOSE) up -d --build

.PHONY: dev-down
dev-down: ## Stop the development stack and drop its volumes
	$(COMPOSE) down -v

.PHONY: dev-restart
dev-restart: ## Recreate the development stack from scratch
	$(MAKE) dev-down
	$(MAKE) dev-up

.PHONY: dev-logs
dev-logs: ## Follow the panel logs
	$(COMPOSE) logs -f app

.PHONY: dev-ps
dev-ps: ## Show the state of every service
	$(COMPOSE) ps

.PHONY: dev-shell
dev-shell: ## Open a shell in the panel container
	$(COMPOSE) exec app bash

.PHONY: dev-verify
dev-verify: ## Check the Faz 0 acceptance criteria
	@./scripts/verify-dev-stack.sh

.PHONY: dev-protocol
dev-protocol: ## Exercise the SSH transfer protocol against a target (TARGET=dns1)
	@./scripts/verify-ssh-protocol.sh $(or $(TARGET),dns1)

.PHONY: dev-test
dev-test: ## Run the unit tests inside the panel container
	$(COMPOSE) exec -T app go test ./... $(GO_TEST_FLAGS)

.PHONY: dev-itest
dev-itest: ## Run the integration tests inside the panel container
	$(COMPOSE) exec -T app go test -tags=integration ./... $(GO_TEST_FLAGS)

# ---------------------------------------------------------------------------
# Build and quality
# ---------------------------------------------------------------------------

.PHONY: build
build: ## Build the static panel binary
	CGO_ENABLED=0 go build -trimpath -o dist/unbound-web ./cmd/unbound-web

.PHONY: build-helper
build-helper: ## Build the setuid PAM helper
	$(MAKE) -C authhelper

.PHONY: test
test: ## Run the unit tests on the host
	go test ./... $(GO_TEST_FLAGS)

.PHONY: fmt
fmt: ## Format the Go sources
	gofmt -l -w .

.PHONY: vet
vet: ## Run go vet
	go vet ./...

.PHONY: lint
lint: vet ## Run the static analysers
	@command -v staticcheck >/dev/null 2>&1 \
		&& staticcheck ./... \
		|| echo "staticcheck not installed, skipped"

.PHONY: vuln
vuln: ## Scan for known vulnerabilities
	@command -v govulncheck >/dev/null 2>&1 \
		&& govulncheck ./... \
		|| echo "govulncheck not installed, skipped"

.PHONY: clean
clean: ## Remove build output
	rm -rf dist tmp coverage.out

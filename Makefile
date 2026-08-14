SHELL := /bin/bash

COMPOSE      := docker compose -f docker-compose.dev.yml --env-file .env.dev
KEY_DIR      := docker/keys
DEV_KEY      := $(KEY_DIR)/dev_ed25519
GO_TEST_FLAGS := -count=1 -race

# The analysers are pinned and run through go run, so a checkout needs nothing
# installed beyond the Go toolchain and every run uses the same version.
STATICCHECK := go run honnef.co/go/tools/cmd/staticcheck@2025.1.1
GOVULNCHECK := go run golang.org/x/vuln/cmd/govulncheck@v1.1.4
MODERNIZE := go run golang.org/x/tools/gopls/internal/analysis/modernize/cmd/modernize@v0.20.0

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

.PHONY: dev-cppcheck
dev-cppcheck: ## Analyse the setuid helper inside the panel container
	$(COMPOSE) exec -T app make cppcheck

.PHONY: dev-itest
dev-itest: ## Run the integration tests inside the panel container
	# As the service account, not as root. One of the gate checks is that the
	# panel never runs with uid 0, and root would also mask the 4750 mode of
	# the setuid helper.
	#
	# One package at a time. Several of these write the same file on the same
	# development target, and Go runs packages in parallel by default, which
	# turns two honest tests into one flake.
	$(COMPOSE) exec -T -u unbound-web app go test -p 1 -tags=integration ./... $(GO_TEST_FLAGS)

# ---------------------------------------------------------------------------
# Build and quality
# ---------------------------------------------------------------------------

.PHONY: build
build: ## Build the static panel binary
	CGO_ENABLED=0 go build -trimpath -o dist/unbound-web ./cmd/unbound-web

.PHONY: build-helper
build-helper: ## Build the setuid PAM helper
	$(MAKE) -C authhelper

.PHONY: install
install: build build-helper ## Install the panel, the helper and the unit (needs root)
	# The script is the single description of the install. Doing half of it
	# here would give two answers to what the file modes are.
	./deploy/install.sh

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
	# Both tag sets. The integration files are compiled out of the default
	# build, so an analyser that only sees it would never read them.
	$(STATICCHECK) ./...
	$(STATICCHECK) -tags=integration ./...
	# The moderniser reports constructs the standard library has replaced.
	# Left unattended they accumulate, so they fail the build like any other
	# lint problem.
	$(MODERNIZE) ./...
	$(MODERNIZE) -tags=integration ./...

.PHONY: vuln
vuln: ## Scan for known vulnerabilities
	$(GOVULNCHECK) ./...

.PHONY: cppcheck
cppcheck: ## Analyse the setuid helper
	# The helper is the only privileged component, so it carries a second
	# analyser on top of -Wall -Wextra -Werror.
	@command -v cppcheck >/dev/null 2>&1 \
		|| { echo "cppcheck is not installed"; exit 1; }
	cppcheck --enable=warning,style,performance,portability \
		--error-exitcode=1 --inline-suppr --std=c11 \
		--suppress=missingIncludeSystem authhelper/authhelper.c

.PHONY: shellcheck
shellcheck: ## Analyse the install and setup scripts
	# The install and setup scripts run as root on a production host, so they
	# are read by an analyser like the rest of the code.
	@command -v shellcheck >/dev/null 2>&1 \
		|| { echo "shellcheck is not installed"; exit 1; }
	shellcheck --severity=warning deploy/*.sh scripts/*.sh docker/*.sh

.PHONY: coverage
coverage: ## Report the test coverage of every package
	go test ./... -count=1 -coverprofile=coverage.out
	@go tool cover -func=coverage.out | tail -1

.PHONY: check
check: lint vuln test cppcheck shellcheck ## Run every check that needs no container
	# The setuid helper and the scripts that run as root during install are
	# the two highest risk artefacts here, so they belong in the aggregate
	# rather than in a target somebody has to remember.

.PHONY: clean
clean: ## Remove build output
	rm -rf dist tmp coverage.out

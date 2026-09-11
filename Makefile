GO      ?= go
PKG     := ./...
BIN     := bin/blindbucket
FUZZTIME ?= 30s

.PHONY: all
all: fmt lint test

.PHONY: build
build:
	$(GO) build -o $(BIN) ./cmd/blindbucket

.PHONY: fmt
fmt:
	$(GO) fmt $(PKG)

.PHONY: tidy
tidy:
	$(GO) mod tidy

.PHONY: vet
vet:
	$(GO) vet $(PKG)

.PHONY: lint
lint:
	golangci-lint run

.PHONY: test
test:
	$(GO) test -race -count=1 $(PKG)

.PHONY: cover
cover:
	$(GO) test -race -count=1 -coverprofile=coverage.out $(PKG)
	$(GO) tool cover -func=coverage.out | tail -n 1

# Short fuzz run over every fuzz target, as used in CI on every push.
.PHONY: fuzz
fuzz:
	@for pkg in $$($(GO) list $(PKG)); do \
		for target in $$($(GO) test -list 'Fuzz.*' $$pkg 2>/dev/null | grep '^Fuzz' || true); do \
			echo "==> $$pkg $$target ($(FUZZTIME))"; \
			$(GO) test $$pkg -run '^$$' -fuzz "^$$target$$" -fuzztime=$(FUZZTIME) || exit 1; \
		done; \
	done

.PHONY: bench
bench:
	$(GO) test -run '^$$' -bench . -benchmem $(PKG)

.PHONY: vuln
vuln:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@latest $(PKG)

.PHONY: clean
clean:
	rm -rf bin dist coverage.out

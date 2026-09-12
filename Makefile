GO      ?= go
PKG     := ./...
BIN     := bin/blindbucket
FUZZTIME ?= 30s

# TLA+ tools for the formal model in spec/tla (M3.5). The jar is not committed.
TLA_VERSION ?= v1.7.4
TLA_TOOLS   ?= .tools/tla2tools.jar

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

# --- Formal model (spec/tla) -------------------------------------------------

$(TLA_TOOLS):
	@mkdir -p $(dir $@)
	curl -sSLf -o $@ \
	  https://github.com/tlaplus/tlaplus/releases/download/$(TLA_VERSION)/tla2tools.jar

.PHONY: tla-tools
tla-tools: $(TLA_TOOLS)

# Regenerate the TLA+ translation of the PlusCal algorithm. Both live in
# Multipart.tla and both are committed; CI fails if they drift apart.
.PHONY: tla-translate
tla-translate: $(TLA_TOOLS)
	java -cp $(TLA_TOOLS) pcal.trans spec/tla/Multipart.tla
	@rm -f spec/tla/Multipart.cfg spec/tla/Multipart.old

# Run TLC over every configuration. Four of the five are expected to report a
# counterexample; check.sh treats a missing one as a failure.
.PHONY: tla
tla: $(TLA_TOOLS)
	TLA_TOOLS=$(abspath $(TLA_TOOLS)) ./spec/tla/check.sh

# --- Independent reference decoder (ref/python) ------------------------------

# Needs `pip install cryptography`.
.PHONY: ref-vectors
ref-vectors:
	cd ref/python && python3 test_vectors.py

# Differential test against the Go decoder. COUNT is the number of inputs;
# CONCEPT.md asks for at least 100000, which takes a few minutes.
COUNT ?= 100000

.PHONY: ref-diff
ref-diff:
	cd ref/python && python3 difftest.py --count $(COUNT)

.PHONY: vuln
vuln:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@latest $(PKG)

.PHONY: clean
clean:
	rm -rf bin dist coverage.out
	rm -f spec/tla/*.old spec/tla/states

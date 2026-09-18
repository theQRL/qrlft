BINARY_NAME=qrlft
COVERAGE_FILE=coverage.out
GO_IGNORE_COV=go run github.com/quantumcycle/go-ignore-cov@v0.7.1

# Coverage measures qrlft's own code. internal/ is vendored from go-qrllib
# verbatim and answers to upstream's tests, which ship with it and run under
# `make test` and `make test-race` like everything else. Holding a frozen copy
# to this repository's 100% line would mean editing it, and being able to diff
# it against upstream unchanged is the whole point of keeping it here.
COVER_PKGS=$(shell go list ./... | grep -v '/internal/')

.PHONY: build check verify-modules test test-race test-e2e test-all coverage coverage-html lint lint-workflows clean

check: verify-modules lint test-race coverage lint-workflows

verify-modules:
	go mod verify

build:
	go build -o $(BINARY_NAME) .

test:
	go test ./...

test-race:
	go test -race ./...

test-e2e:
	go test -v ./e2e/...

test-all: test

coverage:
	go test -coverprofile=$(COVERAGE_FILE) -covermode=atomic $(COVER_PKGS)
	$(GO_IGNORE_COV) --file $(COVERAGE_FILE) --root . --require-reason --exclude-regex '/internal/'
	go tool cover -func=$(COVERAGE_FILE)
	@test "$$(go tool cover -func=$(COVERAGE_FILE) | awk '/^total:/ {print $$3}')" = "100.0%" || (echo "coverage must remain at 100.0%" && exit 1)

coverage-html: coverage
	go tool cover -html=$(COVERAGE_FILE) -o coverage.html

lint:
	@which golangci-lint > /dev/null || (echo "golangci-lint not installed. Install with: brew install golangci-lint" && exit 1)
	golangci-lint run

lint-workflows:
	@which actionlint > /dev/null || (echo "actionlint not installed. Install with: brew install actionlint" && exit 1)
	actionlint

clean:
	rm -f $(BINARY_NAME) $(COVERAGE_FILE) coverage.html

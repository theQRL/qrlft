BINARY_NAME=qrlft
COVERAGE_FILE=coverage.out

.PHONY: build test test-e2e test-all coverage coverage-html lint-workflows clean

build:
	go build -o $(BINARY_NAME) .

test:
	go test ./...

test-e2e:
	go test -v ./e2e/...

test-all: test test-e2e

coverage:
	go test -coverprofile=$(COVERAGE_FILE) -covermode=atomic ./...
	go tool cover -func=$(COVERAGE_FILE)

coverage-html: coverage
	go tool cover -html=$(COVERAGE_FILE) -o coverage.html

lint-workflows:
	@which actionlint > /dev/null || (echo "actionlint not installed. Install with: brew install actionlint" && exit 1)
	actionlint

clean:
	rm -f $(BINARY_NAME) $(COVERAGE_FILE) coverage.html

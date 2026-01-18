BINARY_NAME=qrlft

.PHONY: build test clean

build:
	go build -o $(BINARY_NAME) .

test:
	go test ./...

clean:
	rm -f $(BINARY_NAME)

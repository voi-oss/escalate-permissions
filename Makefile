PHONY: all
all: mod lint test

.PHONY: mod
mod:
	go mod vendor
	go mod tidy

.PHONY: lint
lint:
	golangci-lint run --config .golangci.yaml

.PHONY: test
test:
	go test ./...

.PHONY: build test lint run

build:
	go build -trimpath -o bin/auth-gateway ./cmd/auth-gateway

# Tests that need Postgres are skipped unless TEST_DATABASE_URL is set.
test:
	go test -race ./...

lint:
	go vet ./...
	golangci-lint run

run:
	go run ./cmd/auth-gateway

.PHONY: test build build-linux build-linux-amd64 build-linux-arm64 dev down

test:
	go test ./...

build:
	CGO_ENABLED=0 go build -o build/caddy-gatekeeper ./cmd/caddy-gatekeeper

build-linux: build-linux-amd64 build-linux-arm64

build-linux-amd64:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o build/caddy-gatekeeper-linux-amd64 ./cmd/caddy-gatekeeper

build-linux-arm64:
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o build/caddy-gatekeeper-linux-arm64 ./cmd/caddy-gatekeeper

dev:
	docker compose up --build

down:
	docker compose down

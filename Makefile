.PHONY: test build dev down

test:
	go test ./...

build:
	CGO_ENABLED=0 go build -o build/caddy-gatekeeper ./cmd/caddy-gatekeeper

dev:
	docker compose up --build

down:
	docker compose down

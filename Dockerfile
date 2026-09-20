FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/caddy-gatekeeper ./cmd/caddy-gatekeeper

FROM scratch
COPY --from=build /out/caddy-gatekeeper /caddy-gatekeeper
EXPOSE 9080
ENTRYPOINT ["/caddy-gatekeeper"]

# AWS proof-of-concept deployment

Gatekeeper is a static Go binary and can run alongside native Caddy under systemd.

## Build

Build for the target architecture from the repository root:

    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o caddy-gatekeeper ./cmd/caddy-gatekeeper

For Graviton use `GOARCH=arm64`.

If Go is not installed locally, the same build can be run in the project's Go 1.24 container/toolchain.

## Install

Create a dedicated service account and configuration directory, then install:

    sudo useradd --system --no-create-home --shell /usr/sbin/nologin caddy-gatekeeper
    sudo install -m 0755 caddy-gatekeeper /usr/local/bin/caddy-gatekeeper
    sudo install -d -m 0750 /etc/caddy-gatekeeper
    sudo install -m 0640 deploy/gatekeeper.env.example /etc/caddy-gatekeeper/gatekeeper.env
    sudo install -m 0644 deploy/caddy-gatekeeper.service /etc/systemd/system/caddy-gatekeeper.service
    sudo systemctl daemon-reload
    sudo systemctl enable --now caddy-gatekeeper

Edit `/etc/caddy-gatekeeper/gatekeeper.env` before starting the service.

OTP issuance is rate-limited with configurable defaults:

    GATEKEEPER_SITE_RATE_LIMIT=10
    GATEKEEPER_SITE_RATE_WINDOW=10m
    GATEKEEPER_IDENTITY_RATE_LIMIT=2
    GATEKEEPER_IDENTITY_RATE_WINDOW=10m

The site-wide limit is checked first, then the per-identity limit. Changing these values requires only a service restart, not a rebuild.

State-store operations are deliberately bounded so a Valkey/MemoryDB outage fails closed quickly instead of tying up Caddy requests:

    GATEKEEPER_STATE_TIMEOUT=1s
    GATEKEEPER_VALKEY_DIAL_TIMEOUT=750ms
    GATEKEEPER_VALKEY_READ_TIMEOUT=750ms
    GATEKEEPER_VALKEY_WRITE_TIMEOUT=750ms
    GATEKEEPER_VALKEY_POOL_TIMEOUT=750ms

These values are intentionally conservative for a same-VPC MemoryDB deployment and can be changed without rebuilding Gatekeeper.

## Network layout

The authentication listener should normally be loopback-only because Caddy on the same node is its only caller. The management API may be bound to the node's private VPC address when Silverstripe runs elsewhere. Restrict the management port with the instance security group and retain the bearer token as defence in depth.

For an initial real-site test, site configuration can be pushed directly with curl to the private management listener. Silverstripe integration is intentionally not required for this milestone.

## Caddy

Proxy the reserved Gatekeeper UI path and use `forward_auth` only for the paths that should be protected:

    handle_path /.gatekeeper/* {
        reverse_proxy 127.0.0.1:9080
    }

    @gatekeeper_protected path /admin /admin/* /Security/*
    forward_auth @gatekeeper_protected 127.0.0.1:9080 {
        uri /auth/check
    }

The site's normal handlers/reverse proxy continue after Gatekeeper authorises the request.

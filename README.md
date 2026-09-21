# Caddy Gatekeeper

Caddy Gatekeeper is an email OTP access gatekeeper for Caddy. It sits in front of selected routes so unauthenticated traffic never needs to reach the protected application.

This repository is currently an early proof of concept.

## First milestone

The first milestone proves the browser and Caddy flow with as few dependencies as possible:

1. Request /protected.
2. Caddy asks Gatekeeper for authorisation.
3. An untrusted browser is redirected to /.gatekeeper/login.
4. An authorised email address receives a six-digit OTP (currently logged by the development mailer).
5. Entering the OTP creates a trusted-device cookie.
6. The browser returns to the original URL.
7. Subsequent protected requests pass silently.

The current store is intentionally in-memory. Valkey and SMTP/Mailpit are included in the development stack ready for the next milestone, but are not yet used by the application.

## Development

Start the complete local stack:

    docker compose up --build

Then visit:

    http://localhost:8080/protected

The development allow-list contains developer@example.test. After submitting it, inspect the Gatekeeper log for the OTP:

    docker compose logs gatekeeper

Enter the OTP and the browser should return to /protected. The trusted-device cookie has a 30-day sliding inactivity lifetime.

Mailpit is available on port 8025 but is not wired into Gatekeeper yet.

## Local Silverstripe / DDEV

The development Caddyfile currently uses a simple respond handler as the protected upstream. Once the authentication flow is verified, that handler will be replaced with a reverse proxy to a DDEV-hosted Silverstripe site.

Keeping this separate is intentional: Gatekeeper has no dependency on Silverstripe or DDEV.

## Production direction

The intended production topology is native Caddy using forward_auth to a native caddy-gatekeeper Go binary, which will use the existing Valkey and SMTP infrastructure.

The same Go application can be run in a container for development and as a static binary under systemd in production.

## Security status

This is not yet production-ready. Before production use the project will add persistent hashed device credentials, bounded OTP attempts, rate limiting, generic SMTP delivery, site-specific allow-lists, management APIs, audit logging and hardened proxy/header handling.


## Adversarial testing

The repository includes a small HTTP hammer for exercising Gatekeeper without requiring a separate benchmarking package:

```bash
go run ./cmd/gatekeeper-hammer -url http://localhost:8080/admin -n 10000 -c 100
```

This deliberately does not follow redirects, so an unauthenticated protected request returning Gatekeeper's redirect is counted as a successful response. Store-level concurrency tests also race OTP redemption and failed-attempt exhaustion:

```bash
go test -race ./...
```

The race-enabled test run is particularly important: a valid challenge submitted concurrently must succeed exactly once, and concurrent invalid submissions must not bypass the attempt ceiling.


## Site management API

Gatekeeper exposes a separate management listener, configured with `GATEKEEPER_API_LISTEN` (default `:9081`). Keep this listener on an internal interface/security group in production. API requests also require `Authorization: Bearer <GATEKEEPER_API_TOKEN>`.

Site configuration is stored in Valkey. Silverstripe is intended to remain the durable source of truth and can republish all site configuration if the Gatekeeper configuration keys are ever lost.

Create or replace a site:

```bash
curl -i -X PUT http://127.0.0.1:9081/api/v1/sites/demo \
  -H 'Authorization: Bearer development-management-token' \
  -H 'Content-Type: application/json' \
  --data '{
    "hosts": ["localhost"],
    "access_rules": [
      {"type": "email", "value": "developer@example.test"},
      {"type": "domain", "value": "example.test"}
    ]
  }'
```

The API also supports `GET /api/v1/sites`, `GET /api/v1/sites/{id}` and `DELETE /api/v1/sites/{id}`.

When a host has a deployed site configuration, Gatekeeper uses that site's access rules and binds new challenges/trusted devices to that site. A trusted device issued for one configured site is therefore not valid for another site.

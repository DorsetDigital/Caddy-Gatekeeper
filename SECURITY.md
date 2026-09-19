# Security and threat model

Caddy Gatekeeper is an internet-facing authentication boundary. Security-sensitive behaviour should be designed on the assumption that endpoints, headers, cookies, challenge IDs and timing will be deliberately manipulated.

## Current security invariants

- Protected routes fail closed when Gatekeeper cannot make an authentication decision.
- OTP challenges expire after 10 minutes.
- OTP values are generated with crypto/rand and stored as SHA-256 hashes.
- A challenge permits only the configured number of failed verification attempts and is then consumed.
- Successful OTP verification consumes the challenge, preventing replay.
- Trusted-device tokens are cryptographically random.
- Return URLs must be local absolute paths; external and protocol-relative redirects are rejected.
- Authentication responses must not intentionally disclose whether an email address is authorised.

## Threat checklist

### OTP and account discovery
- [x] Short-lived OTP challenges.
- [x] Bounded OTP guesses per challenge.
- [x] One-time challenge consumption after successful verification.
- [x] Cryptographically secure unbiased six-digit OTP generation.
- [x] Hashed OTP storage.
- [x] Make authorised and unauthorised email submissions indistinguishable in status, redirect and visible browser flow.
- [ ] Prevent timing-based account enumeration: SMTP/external delivery must not sit on the synchronous response path for authorised addresses.
- [ ] Keep authorised and unauthorised request paths approximately equivalent in local work; do not rely on artificial fixed response delays as the primary defence.
- [ ] Rate-limit OTP creation by site + email hash.
- [ ] Rate-limit authentication attempts by site + IP and challenge.
- [ ] Invalidate older outstanding challenges when appropriate.
- [ ] Ensure challenge consumption and attempt counting are atomic in Valkey.

### Trusted devices
- [x] Cryptographically random opaque credentials.
- [x] HttpOnly, SameSite cookies; Secure configurable for local HTTP development.
- [ ] Store only hashes of trusted-device credentials.\n- [x] Provide keyed HMAC identity IDs so runtime state need not use plaintext email addresses.
- [ ] Bind credentials to a site/hostname.
- [ ] Sliding inactivity expiry with refresh no more than approximately once per day.
- [ ] Support independent device revocation and revoke-all for a user/site.
- [ ] Never expose credentials in application/access logs.

### Proxy and routing boundary
- [ ] Verify /admin, /admin/, descendants, query strings and all relevant HTTP methods.
- [ ] Test percent encoding, double encoding, case changes, repeated slashes and dot segments.
- [ ] Define which proxy headers Gatekeeper trusts and reject/ignore client-forged values.
- [ ] Ensure an authorisation decision for one host/path cannot be reused for another.
- [ ] Ensure protected upstreams cannot be reached directly around Caddy/Gatekeeper.
- [ ] Verify Caddy behaviour when Gatekeeper is unavailable: protected traffic must fail closed.

### HTTP/application hardening
- [x] Reject external return URLs.
- [x] X-Content-Type-Options, X-Frame-Options and Referrer-Policy headers.
- [ ] Request/body size limits.
- [ ] Appropriate server read/write/header timeouts.
- [ ] CSRF review for state-changing browser endpoints.
- [ ] Prevent sensitive values and credentials entering logs.
- [ ] Validate Host and site identifiers.
- [ ] Review cache headers on authentication responses.

### State and infrastructure
- [ ] Namespace all Valkey keys under gatekeeper:.
- [ ] Prefer noeviction for security state.
- [ ] Treat Valkey failure as fail-closed for protected resources.
- [ ] Configuration source of truth remains the management system; Valkey loss must not destroy configuration.
- [ ] Shared counters/state must work consistently across all Gatekeeper instances.

### Management plane
- [ ] Authenticate and authorise every management API operation.
- [ ] Prevent cross-site/group privilege escalation.
- [ ] Audit access changes and device revocations.
- [ ] Protect management credentials independently from browser authentication credentials.

## Defence in depth outside this project

General Caddy/WAF rate limiting is desirable for broad request/IP abuse and resource protection. Gatekeeper still requires authentication-aware rate limits because it can correlate site, email, challenge and device state across requests and nodes.

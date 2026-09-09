# Auth Proxy

An OpenResty/Nginx authentication boundary for services that share an Auth.js session. It validates Auth.js JWE session cookies before proxying protected requests.

## Security model

The proxy fails closed. A protected request is forwarded only after all of the following checks succeed:

1. The request includes a cookie named by `JWT_SALT` (default: `authjs.session-token`).
2. The proxy sends that JWE, together with the configured secret and salt, to its internal `/verify-jwe` subrequest endpoint.
3. The decrypt service returns a successful payload with a non-empty string `sub` claim.
4. The payload has a numeric `exp` claim that is later than the current time. Expiration is mandatory.
5. When configured, `TOKEN_ISSUER` must exactly match the payload `iss` claim and `TOKEN_AUDIENCE` must match either the string payload `aud` claim or one member of an audience array.

Invalid, missing, expired, or claim-mismatched tokens receive `401`. Missing proxy configuration or an unavailable verification service receives `503`. Unexpected authentication-boundary failures also receive `503`; requests are never forwarded after an authentication error.

### Internal JWE verification

`/verify-jwe` is an exact Nginx `internal` location in every protected virtual host. It is callable only by the Lua subrequest used by the proxy and is not a public decrypt endpoint. Direct external requests do not expose the decrypt service.

### Trusted identity headers

Before any exception or authentication check, the proxy removes caller-supplied identity, credential, routing, and bypass headers. This includes:

- `X-Api-Key`, `X-User-Id`, `X-User-Email`, `X-Remote-User`, `X-Remote-Email`, `X-Auth-User`, `X-Team-Id`, and `X-Organization-Id`
- `X-Forwarded-User`, `X-Forwarded-Email`, `X-Forwarded-Id`, `X-Forwarded-Access-Token`, `X-Forwarded-For`, `X-Forwarded-Host`, and `X-Forwarded-Proto`
- `X-Auth-Request-User`, `X-Auth-Request-Email`, `X-Auth-Request-Access-Token`, `X-Real-IP`, `X-Bypass-Auth`, and the configured local bypass header

After successful JWE validation, the proxy sets only `X-User-Id` from the trusted `sub` claim. The normal proxy configuration then sets its own forwarding headers.

### Deliberate exceptions

- `/slack/events` is the sole unauthenticated application path. The match is exact; `/slack/events/` and all other paths require authentication. Slack signature verification remains the downstream service's responsibility, and this exception does not propagate caller identity.
- Local bypass is disabled by default. It is accepted only when `ALLOW_LOCAL_BYPASS=true`, `LOCAL_BYPASS_VALUE` is non-empty and exactly matches the request's `LOCAL_BYPASS_HEADER`, and the direct peer address is `127.0.0.1` or `::1`. It must not be enabled for remotely sourced requests, and it does not set an identity header.

## Configuration

Copy `.env.example` to a local `.env` file and provide values through the deployment secret manager or local environment. Do not commit a populated `.env` file.

| Variable | Purpose |
| --- | --- |
| `JWT_SECRET` | Required secret used by the JWE decrypt service. The proxy is unavailable when empty. |
| `JWT_SALT` | Auth.js session cookie name and JWE salt. Defaults to `authjs.session-token`. |
| `TOKEN_ISSUER` | Optional expected issuer. Leave empty unless issued tokens include a matching `iss` claim. |
| `TOKEN_AUDIENCE` | Optional expected audience. Leave empty unless issued tokens include a matching `aud` claim. |
| `ALLOW_LOCAL_BYPASS` | Local-development-only bypass switch. Defaults to `false`. |
| `LOCAL_BYPASS_HEADER` | Header checked for the local bypass. Defaults to `X-Local-Auth-Bypass`. |
| `LOCAL_BYPASS_VALUE` | Required non-empty local bypass value. Keep it outside version control. |
| `ENABLE_DB_CHECK` | Must remain `false`; no database verifier is configured, and enabling it fails closed with `503`. |

## Docker boundary validation

Run the repository-provided boundary check from this directory. It builds an isolated local image and verifies that `/verify-jwe` is not public, spoofed headers are stripped, the Slack exception is exact, expired tokens are rejected, and a missing verifier fails closed:

```sh
docker build -t auth-proxy-boundary-test:local . && ./test-auth-boundary.sh
```

This command is a local configuration and boundary check. It is not evidence of deployed-environment certification.

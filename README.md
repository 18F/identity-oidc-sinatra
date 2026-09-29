# identity-oidc-sinatra — Records Agency resource server (reference)

Reference implementation of a **target agency** for Login.gov delegated access, written as a
small Sinatra app in Ruby. It plays two roles for one fictional agency, the "Records Agency":

1. **The agency's own web app** — the existing direct OpenID Connect sign-in (`/`, `/auth/request`,
   `/auth/result`, `/logout`), unchanged in behavior.
2. **The agency's API, a resource server** — `GET /records` and `POST /records` accept the delegated
   access tokens a service provider obtains from Login.gov by RFC 8693 token exchange, confirm them
   with RFC 7662 introspection, enforce scope per route, and record every decision.
3. **The agency-role Attempts API viewer** — polls Login.gov's Attempts API with the agency's
   credentials and joins the delivered events to the API's decisions on `delegation_id`.

Everything served is fictional demo data. Do not use real personal information.

The service provider side of the demo lives in a sibling repository (`identity-sts-sinatra`); the
SAML-consuming agency in `identity-saml-sinatra`.

## How a delegated call is checked

```
Service provider ──► GET /records, Authorization: Bearer <delegated token>        RFC 6750 §2.1
       │
       │   resource server ──► POST /api/openid_connect/introspect                 RFC 7662 §2.1
       │        token=<delegated token>
       │        client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
       │        client_assertion=<RS256 JWT: iss=sub=RESOURCE_IDENTIFIER,        RFC 7523 §3
       │                          aud=introspection_endpoint, jti, iat, exp<=iat+300>
       │   Login.gov ──► {active:true, aud, scope, sub, act:{sub}, client_id, acr, iat, exp, delegation_id}
       │                 or {active:false}
       │
       ├─ not active / aud != RESOURCE_IDENTIFIER / no act ──► 401 WWW-Authenticate: Bearer error="invalid_token"
       ├─ scope lacks the route's value ──────────────────────► 403 error="insufficient_scope"
       ├─ Login.gov unreachable, error, or no introspection_endpoint in discovery ──► 503 (fail closed)
       └─ otherwise ──► 200, log decision {sub, act.sub, delegation_id, scope, route, decision}
```

The code for each step is in [`resource_server.rb`](resource_server.rb), one method per step with the
standard it implements cited above it, so it can be copied into another Ruby API:

| Method | Standard | What it does |
|---|---|---|
| `authorize!(required_scope)` | §6.3 checklist | Runs the steps below in order; halts 401/403/503 |
| `introspection_endpoint` | OIDC Discovery / RFC 8414 §2 | Reads `introspection_endpoint`; absent means Login.gov has delegation off |
| `bearer_token(request)` | RFC 6750 §2.1 | Header form only; query/body forms are refused |
| `id_token?(token)` | §6.3 item 6 | Refuses a JWT-shaped token before any network call |
| `cached_introspection(token)` | INT-8 | Reuses `active: true` for at most `INTROSPECTION_CACHE_SECONDS` |
| `introspect(token, endpoint)` | RFC 7662 §2.1 | Only HTTP 200 + JSON object is an answer; anything else is "unavailable" |
| `rs_client_assertion(audience:)` | RFC 7523 §3, RFC 8725 | `iss`=`sub`=identifier, `aud`=introspection URL, fresh `jti`, `exp` = `iat` + 300, RS256 |
| `scope_granted?(scope, required)` | RFC 6749 §3.3 | Whole-string comparison of `token_exchange:<name>` values |
| `log_decision(...)` | §8.5 | Ring buffer of join fields; never the token |
| `www_authenticate(...)` | RFC 6750 §3 | Challenge header |

Supporting classes: [`introspection_cache.rb`](introspection_cache.rb) (keyed by SHA-256 of the
token, active results only, never past the token's `exp`), [`decision_log.rb`](decision_log.rb),
[`demo_records.rb`](demo_records.rb).

### Routes

| Route | Requires | Returns |
|---|---|---|
| `GET /records` | `token_exchange:records_read` | `{ records: [...], _introspection: {...} }` |
| `POST /records` | `token_exchange:records_write` | 201 `{ record: {...}, _introspection: {...} }`; JSON or form body with `title`, `note` |
| `GET /decisions` | — | Every authorization decision, newest first (also `/decisions.json`) |
| `GET /attempts-api` | — | Attempts events delivered to this agency; `?tab=delegated` groups them by `delegation_id` with the matching API decisions beneath |
| `GET /api/health` | — | Includes `resource_identifier` and the discovered `introspection_endpoint` |

`_introspection` echoes Login.gov's introspection response (identifiers only) so the service
provider UI can show why a call was allowed or refused. **This is a demo affordance; a production
API would not return it.**

The `act` claim marks delegated access (RFC 8693 §4.1). This demo logs the actor with every decision
and shows it in the UI; its example agency policy is the scope check itself: a service provider may
`POST` only if the user approved `records_write`. Login.gov decides which *API* a token is for
(`aud`); the agency decides which *endpoints* each scope reaches.

## Running locally

```
$ make setup       # .env from .env.example, bundle + npm install, copy design system assets
$ make run         # http://localhost:9393
$ make test        # rspec + js tests
$ make lint        # rubocop, bundler-audit, npm audit
```

A local `identity-idp` must be running at `http://localhost:3000` with `token_exchange_enabled: true`
and the fixtures below. If the IdP's discovery document has no `introspection_endpoint`, protected
routes answer 503 with a message saying so.

Try it without a service provider:

```
$ curl -i http://localhost:9393/records
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer realm="https://records-api.agency.localdev"

$ curl -i -H 'Authorization: Bearer <delegated access token from the exchange>' http://localhost:9393/records
```

Then open http://localhost:9393/decisions and http://localhost:9393/attempts-api?tab=delegated.

## Configuration

| Environment variable | Purpose | Default |
|---|---|---|
| `RESOURCE_IDENTIFIER` | This API's identifier (RFC 8707 `resource`); `iss`/`sub` of introspection assertions and expected `aud` of tokens | `https://records-api.agency.localdev` |
| `RS_PRIVATE_KEY_PATH` / `RS_PRIVATE_KEY` | Key that signs introspection assertions (path, or PEM inline) | `./config/rs_demo.key` |
| `INTROSPECTION_CACHE_SECONDS` | Max reuse of an `active: true` answer (Login.gov publishes 60) | `60` |
| `idp_url` | Login.gov base URL (discovery, introspection, Attempts poll) | `http://localhost:3000` |
| `client_id` | The agency SP's issuer: direct sign-in client and Attempts API poll identity | `urn:gov:gsa:openidconnect:sp:records_agency` |
| `redirect_uri` | Base for the direct sign-in redirect URIs | `http://localhost:9393/` |
| `sp_private_key_path` | Key for direct sign-in `private_key_jwt` | `./config/rs_demo.key` |
| `attempts_shared_secret` | Attempts API poll secret for this agency | — (`records-agency-attempts-secret` in `.env.example`) |
| `attempts_private_key_path` | Key that decrypts Attempts events | `RS_PRIVATE_KEY_PATH` |
| `signed_events` | `true` if the IdP signs Attempts events (ES256 inside the JWE) | unset |
| `allow_all_events_plaintext` | `true` to skip redaction of event fields outside `ALLOWED_PLAINTEXT_KEYS` | unset |
| `PKCE`, `semantic_ial_values_enabled`, `eipp_allowed`, `client_id_pkce` | Existing direct sign-in options | see `config.rb` |

Pointing at the sandbox instead of a local IdP is a matter of changing `idp_url`, `client_id`,
`RESOURCE_IDENTIFIER` and the key paths; no code changes.

### Registering with Login.gov (local fixtures)

The agency uses **one key pair** for direct sign-in, introspection and Attempts decryption:
`config/rs_demo.key` / `config/rs_demo.crt` (RSA 2048, self-signed, `CN=records-api.agency.localdev`,
10-year validity). **The key pair is not committed** (`config/*.key`, `config/*.crt` and
`config/*.pem` are git-ignored). `make setup`, `make test`, `rake login:rs_keypair` and the spec
helper generate it when it is missing; `make rs_keypair` regenerates it on demand; `make rs_cert`
prints the certificate PEM. Every developer therefore has their own pair and must copy their own
certificate to the IdP.

In `identity-idp`:

1. Copy `config/rs_demo.crt` to `certs/sp/rs_records_demo.crt` (`make rs_cert` prints it). The IdP
   repository ignores that file too, so this is a per-checkout step, not a commit. Whenever you run
   `make rs_keypair`, copy the new certificate again.
2. In `config/service_providers.localdev.yml`, add the agency SP
   `urn:gov:gsa:openidconnect:sp:records_agency` (friendly name "Records Agency", `agency_id: 2`, IAL2,
   `token_exchange_target: true`, `attribute_bundle: [email]`, redirect URIs `http://localhost:9393/`,
   `http://localhost:9393/auth/result`, `http://localhost:9393/logout`, `certs: [rs_records_demo]`)
   with one resource server, `identifier: https://records-api.agency.localdev`, `token_format: oauth`,
   `certs: [rs_records_demo]`, and two scopes: `records_read` (access type read) and `records_write`
   (read_write). Scope values on the wire are `token_exchange:records_read` and
   `token_exchange:records_write`.
3. In `config/application.yml`, enroll the agency in `allowed_attempts_providers` with issuer
   `urn:gov:gsa:openidconnect:sp:records_agency`, shared secret `records-agency-attempts-secret`
   and the `rs_records_demo` public key, and set `token_exchange_enabled: true`.

## What this app deliberately does not do

- Accept a Login.gov `id_token` as proof of delegation (§6.3 item 6). ID tokens are refused before
  any network call.
- Serve anything when introspection fails, times out, or returns a non-JSON body (§6.3 item 3).
- Cache `active: false`, or keep any token in plaintext (only SHA-256 digests are held).
- Refresh or revoke tokens: those are the service provider's job. Revocation is observed here as
  `active: false` on the next introspection (REF-6).
- DPoP / sender-constrained tokens (Appendix C). Optional and not built.

## Contributing

See [CONTRIBUTING](CONTRIBUTING.md) for additional information.

## Public domain

This project is in the worldwide [public domain](LICENSE.md). As stated in [CONTRIBUTING](CONTRIBUTING.md):

> This project is in the public domain within the United States, and copyright and related rights in the work worldwide are waived through the [CC0 1.0 Universal public domain dedication](https://creativecommons.org/publicdomain/zero/1.0/).
>
> All contributions to this project will be released under the CC0 dedication. By submitting a pull request, you are agreeing to comply with this waiver of copyright interest.

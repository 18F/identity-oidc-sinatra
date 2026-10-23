# Changelog

## Unreleased

### Added

- A “Test document artifacts” page for requesting the `document_images` OIDC
  scope, with identity verification, facial-match-required, and authentication-only options.
- Userinfo checks that distinguish absent, empty, and populated document image
  and metadata claims.
- Front, back, passport, and selfie endpoint checks using the current, missing,
  or invalid bearer token, reporting HTTP status, response headers, and byte counts.
- Bounded server-memory test sessions with a 15-minute expiry and a clear-token action.
  Bearer tokens are not stored in browser session cookies.
- Regression coverage for test-session callbacks, request validation, CSRF,
  token expiry, redirect handling, and a separately configured IdP host.

### Fixed

- `make run` copies installed design-system assets into the public directory before
  starting the app. Repeated copies refresh files without nesting the distribution directory.

### Scope and prerequisites

- These changes affect only the Sinatra sample app. They add no IdP code, database
  migrations, seed data, simulator hooks, or automatic IdP configuration changes.
- Tests use the existing `idp_url`, client ID, callback, and client authentication configuration.
  An IdP containing the document-sharing implementation and its applied migrations
  can be tested without the separate local Socure simulator branch.
- Successful release requires the IdP's sharing flag and partner allow-list, appropriate
  proofing/consent, and retained artifacts. Applied migrations alone do not provide those data.
- Image checks report response metadata; they do not render image content or establish
  complete IdP security/compatibility coverage. Ordinary sign-in defaults are unchanged.

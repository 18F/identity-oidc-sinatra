# identity-openidconnect-sinatra

An example of a Relying Party for OpenID Connect written as a simple Sinatra app in Ruby.

## Running locally

1. Set up the environment with:

  ```
  $ make setup
  ```

2. And run the app server:

  ```
  $ make run
  ```

3. To run specs:

  ```
  $ make test
  ```

## Configuring

1. This sample service provider is configured to run on http://localhost:9292 by default. Optionally, you can assign a custom hostname or port by passing `HOST=` or `PORT=` environment variables when starting the application server. However, when you do this, you also have to make corresponding changes to the `redirect_uri` environment variable and also configure the identity provider appropriately.

2. Some other key environment variables that affect configuration:

   | Environment Variable        | Description                                                                                  | Default                                   |
   |-----------------------------|----------------------------------------------------------------------------------------------|-------------------------------------------|
   | client_id                   | Identifier for this app as configured with the identity provider. Used unless `PKCE` is true | urn:gov:gsa:openidconnect:sp:sinatra      |
   | client_id_pkce              | Identifier for this app as configured with the identity provider. Used if `PKCE` is true     | urn:gov:gsa:openidconnect:sp:sinatra_pkce |
   | eipp_allowed                | Enhanced In Person Proofing allowed                                                          | false                                     |
   | idp_url                     | URL for the identity provider                                                                | http://localhost:3000                     |
   | DPOP                        | With `PKCE`, binds the sign-in and the delegated token to a key held for the sign-in (RFC 9449): `dpop_jkt` on the authorization request and a `DPoP` proof on every token request | false                                     |
   | PKCE                        | Determines if PKCE or private_key_jwt is used to communicate with the identity provider      | false                                     |
   | THIRD_PARTY_TARGET_LINK_ALLOWLIST | Exact origins a service provider may name in `target_link_uri` when it starts a sign-in here through `GET /initiate_login` (space- or comma-separated) | http://localhost:9292 |
   | THIRD_PARTY_SIGN_IN_IAL     | The identity assurance level this agency signs people in at when a third party starts the sign-in | 2                                         |
   | token_exchange_targets      | JSON list of agency applications to delegate to: `issuer` (the `audience`), `scope` (the `token_exchange:` value) and `api` (the `resource`) | one fictitious target                     |
   | semantic_ial_values_enabled | Determines if semantic IAL values can be used in `acr_values`                                | fals                                      |

## Delegated access

Checking "Initiate Broker token exchange" and requesting a `token_exchange:<value>` scope makes the sample act as a
delegated-access actor: after the code exchange it trades the token it received for a delegated access token at Login.gov's
token endpoint (RFC 8693) and offers to send it to the chosen target API. With `DPOP=true` (and `PKCE=true`) the sample
generates a P-256 key per sign-in, names its thumbprint as `dpop_jkt`, sends a DPoP proof with the code exchange and the
token exchange, and, because a key-bound token must travel with a proof, calls the target API itself with the `DPoP`
scheme instead of redirecting the browser.

`GET /api/records` is the agency API's side: it accepts a delegated token in the `Authorization` header, opens it with the
service's private key, verifies Login.gov's signature, accepts only a token Login.gov (`iss`) issued for this service's
`client_id` (`aud`) and, when the token carries `cnf.jkt`, requires the `DPoP` scheme and a proof signed by that key for
this request (RFC 9449 §7.1), refusing the token presented as `Bearer`.

## Third-party-initiated login (the agency side)

`GET /initiate_login` is the login-initiation address this agency registers (OpenID Connect Core 1.0 §4). A service
provider whose delegation request Login.gov refused because the person holds no identity at this agency sends the browser
here with `iss` (Login.gov's URL), `login_hint` (an opaque value it will recognize) and `target_link_uri` (where to return
the person). The agency refuses unless `iss` is the Login.gov it is configured for and the origin of `target_link_uri` is
in `THIRD_PARTY_TARGET_LINK_ALLOWLIST`, then runs its ordinary Login.gov sign-in at `THIRD_PARTY_SIGN_IN_IAL`; the person
already holds a Login.gov session, so no credentials are asked again. When the sign-in completes, or fails, the person is
sent to `target_link_uri` with `login_hint`, `iss` (this agency's client id) and `status` (`signed_in` or `failed`). The
hint is never treated as identity, and the signed-in page says which site started the session.

## Contributing

See [CONTRIBUTING](CONTRIBUTING.md) for additional information.

## Public domain

This project is in the worldwide [public domain](LICENSE.md). As stated in [CONTRIBUTING](CONTRIBUTING.md):

> This project is in the public domain within the United States, and copyright and related rights in the work worldwide are waived through the [CC0 1.0 Universal public domain dedication](https://creativecommons.org/publicdomain/zero/1.0/).
>
> All contributions to this project will be released under the CC0 dedication. By submitting a pull request, you are agreeing to comply with this waiver of copyright interest.

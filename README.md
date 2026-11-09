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
   | PKCE                        | Determines if PKCE or private_key_jwt is used to communicate with the identity provider      | false                                     |
   | third_party_target_link_allowlist | Exact origins an actor application may name in `target_link_uri` when it starts a sign-in here through `GET /initiate_login` (space- or comma-separated) | http://localhost:9292 |
   | third_party_sign_in_ial     | The identity assurance level this target application signs people in at when a third party starts the sign-in | 2                                         |
   | semantic_ial_values_enabled | Determines if semantic IAL values can be used in `acr_values`                                | fals                                      |

## Delegated access

Checking "Initiate Broker token exchange" and requesting a `token_exchange:<value>` scope makes the sinatra demo app act
as a delegated-access actor: after the code exchange it trades the token it received for a delegated access token at
Login.gov's token endpoint (RFC 8693) and offers to send it to the chosen target API.

When Login.gov refuses the exchange with `invalid_target` and an `initiate_login_uri`, it means that the user has not connected their Login.gov account with that
target application yet. A delegation request does not create one. Instead, the actor application requests third-party-initiated login at that address
(OpenID Connect Core 1.0 §4) with `iss`, a fresh `login_hint` and `target_link_uri=/third_party/return`; when the target application
returns the person with the same hint and `status=signed_in`, the app repeats the delegation request exactly as first
made, and the exchange now succeeds. The return is honored once, within ten minutes, and only for the hand-off this browser
session started. A refusal without an address is shown as the delegation's error.

## Encrypted userinfo responses and document images

The identity provider can return data from the userinfo request as a JWE (content type `application/jwt`) instead of
plain JSON. The app detects the content type and decrypts the response with the private key at `sp_private_key_path`,
the same key that signs its `private_key_jwt` client assertion.

The decrypted claims are shown on the home page exactly as plain claims are. With the `document_images` scope (offered
as a checkbox when the identity provider allow-lists this client for it), they include `document_metadata` and
`document_images`, whose values are the URLs of the images (`front`, `back`, `passport`, `selfie`). The "Test document
artifacts" page decrypts the same way and reports `encrypted` with each check.

### Document images

After sign-in the app fetches each URL in `document_images` and shows the image inline with its media type and size.
Each fetch is a `POST` to the URL with the bearer access token in `Authorization` and a `private_key_jwt` client
assertion (`client_assertion` and `client_assertion_type`) whose `aud` is exactly the URL requested. The identity
provider answers with a JWE with content type `application/jose`; its `cty` header names the image's media type. The
app decrypts the JWE with its private key.

Errors are:

- 401 `invalid_client` (assertion missing or invalid),
- 403 (sharing not authorized for this sign-in),
- 404 (no such image yet),
- 500 `server_error` (the client has no usable certificate to encrypt to).

An image that fails is shown as its error beside the others. The images live in the process's memory for one page
view. The test page's image checks make the same request and report the status, the headers, whether the response was
encrypted, and the image's type and size.

## Third-party-initiated login (the target application side)

`GET /initiate_login` is the login-initiation address this sample application registers (OpenID Connect Core 1.0 §4). An
actor application whose delegation request was refused because the person has not connected their account to the target application sends a request
here with `iss` (Login.gov's URL), `login_hint` (an opaque value it will recognize) and `target_link_uri` (where to return
the person). This request is rejected unless `iss` is Login.gov, and the origin of `target_link_uri` is
in `third_party_target_link_allowlist`. Once the request has been validated, the target app then runs the ordinary Login.gov sign-in at `third_party_sign_in_ial`; the user
already holds a Login.gov session, so no credentials are asked again. When the sign-in completes, or fails, the person is
sent to `target_link_uri` with `login_hint`, `iss` (this agency's client id) and `status` (`signed_in` or `failed`). The
hint is never treated as identity, and the signed-in page says which site started the session.

Nothing is delegated and no token is exchanged on this path: it is the agency's own sign-in, with its own tokens, consent
screen, fraud signals and billing, and the single sign-on comes from the person's existing Login.gov session. The two checks
are the ones §4 says a relying party MUST perform before acting on the request. Without the `iss` check, a crafted link
could send the person to an attacker's OpenID Provider and harvest whatever they type there. Without the `target_link_uri`
check, the endpoint would be an open redirector: anyone could craft a link that signs the person in here and then bounces
them to an arbitrary site that looks like a continuation of the flow. The origin of `target_link_uri` is compared against
the allow-list exactly, so the third party may vary the path and query but never the site; `login_hint` and
`target_link_uri` are both bounded in length because they are remembered in the session cookie.

## Contributing

See [CONTRIBUTING](CONTRIBUTING.md) for additional information.

## Public domain

This project is in the worldwide [public domain](LICENSE.md). As stated in [CONTRIBUTING](CONTRIBUTING.md):

> This project is in the public domain within the United States, and copyright and related rights in the work worldwide are waived through the [CC0 1.0 Universal public domain dedication](https://creativecommons.org/publicdomain/zero/1.0/).
>
> All contributions to this project will be released under the CC0 dedication. By submitting a pull request, you are agreeing to comply with this waiver of copyright interest.

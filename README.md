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
   | semantic_ial_values_enabled | Determines if semantic IAL values can be used in `acr_values`                                | fals                                      |

3. Encrypted userinfo responses. When the identity provider is configured to encrypt this client's
   userinfo responses, it answers the userinfo request with one compact JWE (content type
   `application/jwt`) instead of plain JSON. The app detects the content type and decrypts the
   response with the private key at `sp_private_key_path`, the same key that signs its
   `private_key_jwt` client assertion, so nothing needs to be configured here. The decrypted
   claims are shown on the home page exactly as plain claims are. With the `document_images`
   scope (offered as a checkbox when the identity provider allow-lists this client for it) they
   include `document_metadata` and `document_images`, whose values are the URLs of the images
   (`front`, `back`, `passport`, `selfie`). The "Test document artifacts" page decrypts the same
   way and reports `encrypted` with each check.

4. Document images. Right after sign-in the app fetches each URL in `document_images` and shows
   the image inline with its media type and size. The request is a `POST` to that URL with the
   bearer access token in `Authorization` and two form fields, `client_assertion` and
   `client_assertion_type` (`urn:ietf:params:oauth:client-assertion-type:jwt-bearer`): the
   assertion is a `private_key_jwt` signed with the client's key whose `iss` and `sub` are the
   client id and whose `aud` is exactly the URL requested, with `jti`, `iat` and `exp`. It is a
   `POST` because a client assertion is a signed JWT and belongs in the request body, not in a URL
   that proxies and access logs record. The identity provider answers with the image encrypted to
   this client's registered certificate: content type `application/jose`, a compact JWE whose `cty`
   header names the image's media type and whose plaintext is the image bytes; the app decrypts it
   with the same private key. Errors are JSON: 401 `invalid_client` (assertion missing or invalid),
   403 (sharing not authorized for this sign-in), 404 (no such image yet), 500 `server_error`
   (the client has no usable certificate to encrypt to). An image that fails is shown as its error
   beside the others. The images live in the process's memory for one page view, never in the
   session cookie. The test page's image checks make the same request and report the status, the
   headers, whether the response was encrypted, and the image's type and size, never its bytes.

## Contributing

See [CONTRIBUTING](CONTRIBUTING.md) for additional information.

## Public domain

This project is in the worldwide [public domain](LICENSE.md). As stated in [CONTRIBUTING](CONTRIBUTING.md):

> This project is in the public domain within the United States, and copyright and related rights in the work worldwide are waived through the [CC0 1.0 Universal public domain dedication](https://creativecommons.org/publicdomain/zero/1.0/).
>
> All contributions to this project will be released under the CC0 dedication. By submitting a pull request, you are agreeing to comply with this waiver of copyright interest.

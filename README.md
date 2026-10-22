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

## Contributing

See [CONTRIBUTING](CONTRIBUTING.md) for additional information.

## Public domain

This project is in the worldwide [public domain](LICENSE.md). As stated in [CONTRIBUTING](CONTRIBUTING.md):

> This project is in the public domain within the United States, and copyright and related rights in the work worldwide are waived through the [CC0 1.0 Universal public domain dedication](https://creativecommons.org/publicdomain/zero/1.0/).
>
> All contributions to this project will be released under the CC0 dedication. By submitting a pull request, you are agreeing to comply with this waiver of copyright interest.

## Test document artifacts with the local Socure simulator

These steps test the document storage/release stack (#13648–#13651) with synthetic
Socure fixtures. They do not connect to Socure's external sandbox.

### 1. Get both branches

Start with a working local IdP environment (Ruby, Node, PostgreSQL, Redis, and the
standard configuration/certificate links). For first-time setup, follow the
[IdP local development guide](https://github.com/18F/identity-idp/blob/dcl/secure-protocols/document_images_idp/docs/local-development.md).

In your `identity-idp` checkout:

```sh
git fetch origin
git switch dcl/secure-protocols/document_images_idp
bundle install
npm ci
bundle exec rails db:migrate db:seed
npm run build:js_and_css
mkdir -p tmp/pids
```

In your `identity-oidc-sinatra` checkout:

```sh
git fetch origin
git switch dcl/secure-protocols/document_images_sampleapp
make setup
```

### 2. Configure the IdP

Merge these settings into the existing `development` section of the IdP's
`config/application.yml`. Preserve your database, Redis, and other local settings.

```yaml
development:
  document_images_sharing_enabled: true
  document_images_sharing_service_providers: '["urn:gov:gsa:openidconnect:sp:sinatra"]'
  socure_docv_enabled: true
  doc_auth_vendor_default: mock_socure
  doc_auth_selfie_vendor_default: mock_socure
  doc_auth_passport_vendor_default: mock_socure
  doc_auth_passport_selfie_vendor_default: mock_socure
  socure_docv_images_request_endpoint: http://localhost:3000/test/mock_socure/api/5.0/documents/
  socure_docv_webhook_secret_key: local-socure-test-only
```

The webhook value is for localhost testing only. The standard IdP seeds register
the Sinatra client and its `http://localhost:9292/auth/result` callback.

### 3. Start the apps

Keep PostgreSQL and Redis running. Use three separate terminals:

**IdP web server** (from `identity-idp`):

```sh
RAILS_MAX_THREADS=5 bundle exec rackup config.ru --port 3000 --host localhost
```

**IdP worker** (from `identity-idp`):

```sh
bundle exec good_job start
```

**Sample app** (from `identity-oidc-sinatra`):

```sh
idp_url=http://localhost:3000 PKCE=false client_id=urn:gov:gsa:openidconnect:sp:sinatra redirect_uri=http://localhost:9292/ make run
```

Restart both IdP processes after changing configuration. Multiple web threads are
required because the simulator makes HTTP callbacks to the same IdP.

### 4. Run the test

1. Open http://localhost:9292/document-artifacts.
2. Leave **Identity verified** selected and **Request document images** checked.
   Click **Sign in to test**.
3. Create a **new test account** so previous verification does not skip proofing.
   Use a private window or sign out of Login.gov if an existing login is reused.
4. Choose **driver's license/state ID**.
5. At **Test Socure Configuration**, select **License Pass**, then **Continue**.
6. Complete proofing and grant document-sharing consent.
7. Back in the sample app, select **userinfo**, keep **Current test token**, and
   click **Run request**. Then return and check **front** and **back**.

| Check | Expected result |
| --- | --- |
| userinfo / current token | Image URLs and document metadata |
| front or back / current token | HTTP 200, `image/jpeg`, `Cache-Control: no-store` |
| front / missing or invalid token | HTTP 401 |

License Pass supplies synthetic front/back images, not selfie or passport images.
Image checks show status, headers, and byte counts rather than rendering images.
Empty `{}` claims mean sharing is authorized but records are unavailable; retry
userinfo after retrieval completes. Persistently empty claims need investigation.

The sample app retains test tokens in server memory for 15 minutes. Restarting it
clears them but does not sign you out of Login.gov. Sign in again if the checks disappear.

This is a positive-flow smoke test, not full PR acceptance. Separately verify
flag-off compatibility against the pre-change IdP, consent revocation, retention,
account deletion, encryption/key rotation, and cross-user isolation.

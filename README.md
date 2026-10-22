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

## Testing document artifacts and release (IdP PRs #13648 / #13651)

Start against the local IdP (override any sandbox settings in your environment):

```sh
idp_url=http://localhost:3000 make run
```

Open http://localhost:9292/document-artifacts. The page provides:

- Document-sharing sign-in and release checks backed by the #13648 models.
- A release sign-in requesting `document_images`, with IAL1/IAL2 and missing-scope controls.
- Userinfo rechecks that distinguish absent claims, empty objects, and populated claims.
- Front/back/passport/selfie requests with the current, missing, or invalid bearer token.
- HTTP status, content type, cache headers, and byte counts without retaining image bytes.

For #13651, run an IdP containing its full prerequisite stack with migrations applied.
Set `document_images_sharing_enabled: true` and add the exact client ID shown on the
page to `document_images_sharing_service_providers`. Restart the IdP after configuration
changes. Use a synthetic verified user, purpose-specific consent, and synthetic stored
artifacts; this app does not seed data or change IdP configuration. #13648 alone cannot
populate or release images through a browser flow.

Test tokens stay in bounded process-local memory for 15 minutes, referenced by a random
session ID. Restarting the sample app clears them; use one process for the manual test.
IdP expiry may be shorter. Clear the token when done. All checks use fixed paths on
`idp_url`, do not follow redirects, and never send the bearer token to a returned claim URL.
Normal sign-in defaults and the existing PKCE `demo/` are unchanged.

Use the same token to recheck after revoking consent, removing partner eligibility,
expiring a synthetic artifact, or removing its synthetic Redis object. Compare results
with the table on the page and inspect IdP audit logs. Missing/invalid bearer tokens use
the bearer-authentication audit path; authenticated 403/404 image requests use
`document_image_release`. An empty claim alone cannot tell asynchronous retrieval from
expired artifacts or mDL. A 200 plus byte count does not verify image content correctness.

Compare identical flag-off requests against the pre-change IdP, including previously
accepted optional scopes. Do not mark a new rejection as compatible merely because a
new spec expects it. Repeat for supported public, confidential, and legacy configurations.

The release-specific IdP tests are:

```sh
bundle exec rspec spec/controllers/openid_connect/document_images_controller_spec.rb spec/controllers/openid_connect/user_info_controller_spec.rb spec/presenters/openid_connect_user_info_presenter_spec.rb spec/services/openid_connect_attribute_scoper_spec.rb spec/forms/openid_connect_authorize_form_spec.rb
```

Sample-app regression checks (use an installed Ruby matching the bundle):

```sh
idp_url=http://localhost:3000 bundle exec rspec
```

### Prepared local stack

The isolated checkout at `../identity-idp-document-artifacts-test` is pinned to
PR #13651 head `0c34add6386b87912d62d0aeb1b3a6d3e0e4063d` (including its stack).
It uses separate `identity_idp_artifacts_development` and
`identity_idp_artifacts_worker_jobs_development` PostgreSQL databases and Redis on
localhost:16390. Local config enables document sharing for the sample Sinatra client.
It has seeded partner registrations but no pre-created test users.

To restart, run each long-running command in its own terminal:

```sh
cd ../identity-idp-document-artifacts-test
redis-server --port 16390 --bind 127.0.0.1 --save '' --appendonly no
RAILS_MAX_THREADS=5 RBENV_VERSION=3.4.10 rbenv exec bundle exec rackup config.ru --port 3000 --host localhost
RBENV_VERSION=3.4.10 rbenv exec bundle exec good_job start
```

The Redis command is only needed if that instance is stopped. Assets are compiled;
no webpack watch process is needed until frontend sources change. The model and
release checks are documented above; technical walkthroughs are kept off the test page.

### Local Socure flow

The isolated IdP uses `mock_socure`, the repository's Socure simulator, with
`socure_docv_enabled: true`. This exercises Socure-specific webhook, result,
image-retrieval, persistence, and release code using synthetic fixtures. It is not
a connection to the external Socure sandbox and does not test that vendor's capture SDK.
The local-only simulator image route/action was repaired to serve the ZIP expected
by `ImagesRequest`; production result, persistence, and release code is unchanged.
A local webhook secret is configured, and the IdP needs multiple threads because
the simulator calls back into the same server.

Start **Sign in to test**, create a new test account (an already verified account
may skip proofing), and choose a driver's license/state ID. At **Test Socure
Configuration**, select **License Pass**, then **Continue**. Complete the remaining
proofing and sharing-consent steps. On return, request userinfo, then front/back.
Expect populated claims and image responses with HTTP 200. Selfie and passport are
not supplied by the License Pass scenario. Test images come from repository fixtures,
not from the generic mock flow's uploads.

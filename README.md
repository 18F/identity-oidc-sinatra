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

## Load testing

`bin/loadtest` drives simulated users through login.gov IdP flows, always
starting from this relying party, so the whole OpenID Connect round trip is
measured rather than just the IdP's internals.

Three flow types can be run, individually or mixed:

| Flow        | What it exercises                                                   | Creates accounts? |
|-------------|---------------------------------------------------------------------|-------------------|
| `auth_only` | Sign-in at IAL1: password plus SMS one-time code                    | No                |
| `idv`       | Sign-in at IAL2 against an already-proofed user                     | No                |
| `signup`    | Account creation via `prompt=create`, with phone MFA                | Yes               |

`auth_only` and `idv` reuse users seeded once, so repeated runs create no new
accounts. `signup` necessarily registers a new user per run; the addresses are
synthetic and no mail is sent.

### 1. Configure the IdP

The harness needs no changes to identity-idp, but it does rely on a few
settings. Add these to the `development:` block of the IdP's
`config/application.yml`:

```yaml
development:
  # Renders a "CONFIRM NOW" link on the verify-email page carrying the real
  # confirmation token, standing in for clicking a link in an email.
  # Required by the signup flow only.
  enable_load_testing_mode: true

  # Allows prompt=create, which is how the relying party starts registration.
  # Required by the signup flow only.
  allowed_create_prompt_providers: '["urn:gov:gsa:openidconnect.profiles:sp:sso:evelyn"]'
```

These are already the defaults in development and only need attention if your
local configuration overrides them:

| Setting                       | Needed value  | Why                                                                     |
|-------------------------------|---------------|-------------------------------------------------------------------------|
| `telephony_adapter`           | `test`        | Makes the IdP prefill the real one-time code into the page, which is how the harness authenticates without SMS |
| `RAILS_ENV`                   | `development` | The code prefill above is gated on the development environment          |
| `enable_rate_limiting`        | `false`       | Otherwise concurrent runs from one address are throttled                |
| `recaptcha_mock_validator`    | `true`        | The harness submits the mock token and score these forms expect         |
| `openid_connect_redirect`     | either        | The harness handles both the redirect and JavaScript handoff            |

### 2. Seed users for the sign-in flows

From the identity-idp repository. **Seed the verified users first, then the plain
users at an offset**, so the two pools do not overlap: an `idv` run handed an
unproofed user would be diverted into identity verification. The harness refuses
to start if the configured ranges overlap.

```bash
# idv pool: testuser0..testuser9, with an active proofed profile
bundle exec rake dev:random_users NUM_USERS=10 VERIFIED=1 SCRYPT_COST='800$8$1$' PROGRESS=no

# auth_only pool: testuser1000..testuser1019
bundle exec rake dev:random_users NUM_USERS=1020 SCRYPT_COST='800$8$1$' PROGRESS=no
```

Both create users with the password `salty pickles` and a confirmed phone. Do
not change those passwords: `dev:random_users` encrypts each proofed profile's
PII with it.

### 3. Run it

Start the IdP and this relying party, then:

```bash
# Preview what will run without sending any requests
bundle exec ruby bin/loadtest --config config/loadtest.example.yml --plan

# Run the per-flow counts from a config file
cp config/loadtest.example.yml loadtest.yml
bundle exec ruby bin/loadtest --config loadtest.yml

# Or set the counts inline
bundle exec ruby bin/loadtest --flow-runs auth_only=100,idv=50,signup=20 --vus 10
```

### Configuring run counts

The number of runs per flow is the harness's main control, and lives in a config
file. Copy `config/loadtest.example.yml`, which documents every option. Settings
resolve as **command line > `LOADTEST_*` environment variables > config file >
built-in defaults**, so a single run can be adjusted without editing the file.

Useful flags: `--vus` (concurrent virtual users), `--ramp` (stagger their start),
`--csv` / `--json` (write results), `--plan` (dry run), `--verbose` (log every
run, not just failures). `--help` lists them all.

### Output

The summary is printed to standard output: per-flow and per-step latency
(mean, p50, p95, max), throughput, and a breakdown of any failures. Latency
statistics come from successful runs only, since a run that failed early is fast
for the wrong reason.

`--csv` writes **one row per run** (flow, virtual user, identity, status,
duration, failing step, error, and the per-step timings) for external analysis.
`--json` writes the aggregated summary.

The command exits nonzero if any run failed, so it can gate a pipeline as well
as report numbers.

### Notes and limitations

- **One user per concurrent run.** The IdP ends a user's previous session when
  they sign in again, so the harness never hands the same seeded user to two
  runs at once. Virtual users above the pool size queue rather than collide.
- **`idv` does not drive identity proofing.** It signs in users who already have
  a proofed profile, measuring the steady-state cost of a verified sign-in
  (including PII decryption). Driving the proofing wizard itself is out of scope.
- **`signup` leaves its users behind.** Rows accumulate in the IdP's development
  database across runs. They are harmless and obviously synthetic
  (`loadtest+<random>@example.com`); clean up manually if you want to.
- **Run it against local or sandbox environments only.** It creates accounts and
  authenticates repeatedly.

## Contributing


See [CONTRIBUTING](CONTRIBUTING.md) for additional information.

## Public domain

This project is in the worldwide [public domain](LICENSE.md). As stated in [CONTRIBUTING](CONTRIBUTING.md):

> This project is in the public domain within the United States, and copyright and related rights in the work worldwide are waived through the [CC0 1.0 Universal public domain dedication](https://creativecommons.org/publicdomain/zero/1.0/).
>
> All contributions to this project will be released under the CC0 dedication. By submitting a pull request, you are agreeing to comply with this waiver of copyright interest.

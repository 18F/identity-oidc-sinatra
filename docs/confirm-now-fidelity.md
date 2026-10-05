# Fidelity of the "CONFIRM NOW" load-testing link vs. a real email confirmation

**Repository under analysis:** `identity-idp` @ `main` / `62cf38755d`
**Scope:** RP/SP-initiated signup (`prompt=create` carrying a `request_id`) —
the path driven by the `identity-oidc-sinatra` load-test harness
**Method:** static / code-level differential
**Question:** does the `CONFIRM NOW` link (rendered under
`enable_load_testing_mode`) faithfully recreate the data, events, and database
entries that clicking a real confirmation email produces?

---

## Verdict

**Mostly faithful, with one real divergence.**

Both links resolve to the **same route and the same controller action**, so
every analytics event, attempts-API event, database write, and session mutation
performed *by the confirmation action itself* is identical by construction.

The divergence is entirely in **what the two links put in the URL**. The real
email link carries `_request_id` and `locale`; the `CONFIRM NOW` link carries
neither. Because the controller gates one `before_action` on `_request_id`, the
load-testing path **skips SP metadata refresh and the authorization-count
increment**.

For the in-scope SP-initiated flow this is a genuine behavioral difference, but
its practical impact is **narrow and self-correcting** — see
[Practical impact](#practical-impact).

---

## The two links

Both build the same route helper, `sign_up_create_email_confirmation_url`,
mapped at `config/routes.rb:367-368`:

```ruby
get '/sign_up/email/confirm' => 'sign_up/email_confirmations#create',
    as: :sign_up_create_email_confirmation
```

### Real confirmation email
`app/views/user_mailer/email_confirmation_instructions.html.erb:14-19` (and
again as a bare URL at `:35-48`):

```erb
sign_up_create_email_confirmation_url(
  _request_id: @request_id,
  confirmation_token: @token,
  locale: @locale,
)
```

`@request_id`, `@token`, and `@locale` are assigned in
`app/mailers/user_mailer.rb:42-49`.

### CONFIRM NOW link
`app/views/sign_up/emails/show.html.erb:50` (NDS layout) and `:93` (legacy
layout):

```erb
sign_up_create_email_confirmation_url(confirmation_token: EmailAddress.find_with_email(email).confirmation_token)
```

A third instance exists for the add-email flow at
`app/views/users/emails/verify.html.erb:38`. It is out of scope here (not part
of registration) and turned out to be a **worse, functional** bug rather than a
fidelity gap — it targets the wrong controller entirely and never confirms the
email. That is documented separately in
[`confirm-now-fidelity-add-email.md`](./confirm-now-fidelity-add-email.md).

**Delta: `_request_id` and `locale` are absent.**

---

## A. Identical by construction (shared code path)

Everything below runs on `SignUp::EmailConfirmationsController#create` and its
`before_action` chain, keyed only on `confirmation_token`, which both links
carry identically.

| Side effect | Location | Notes |
|---|---|---|
| `user_registration_email_confirmation` analytics event | `email_confirmations_controller.rb:24` | via `log_validator_result` |
| `user_registration_email_confirmed` attempts-API event | `email_confirmations_controller.rb:25-31` | includes `success`, `email`, `failure_reason` |
| Token lookup → `@email_address`, `@user` | `unconfirmed_user_concern.rb:6-10` | `EmailAddress.find_with_confirmation_token` |
| Already-confirmed guard + its events | `unconfirmed_user_concern.rb:12-35` | identical early-exit behavior |
| Token validation (found / not already confirmed / not expired) | `email_confirmation_token_validator.rb:6-12` | identical |
| `session.delete(:needs_to_setup_piv_cac_after_sign_in)` | `email_confirmations_controller.rb:34-36` | `clear_setup_piv_cac_from_sign_in` |
| `session[:user_confirmation_token] = token` | `unconfirmed_user_concern.rb:52-55` | `process_valid_confirmation_token` |
| `session[:sign_in_flow] ||= :create_account` | `email_confirmations_controller.rb:40` | |
| Redirect to `/sign_up/enter_password?confirmation_token=…` | `email_confirmations_controller.rb:41` | |
| `ActiveRecord::RecordNotUnique` → `process_already_confirmed_user` | `email_confirmations_controller.rb:17-18` | identical rescue |

**Conclusion for section A:** no divergence is possible here. The code cannot
distinguish the two callers.

---

## B. Divergence: side effects gated on `_request_id`

`app/controllers/sign_up/email_confirmations_controller.rb:12, 44-52`:

```ruby
before_action :store_sp_metadata_in_session, only: [:create]

def store_sp_metadata_in_session
  return if request_id.blank?          # <-- CONFIRM NOW short-circuits here
  StoreSpMetadataInSession.new(session:, request_id:).call
  bump_auth_count
end

def request_id
  params[:_request_id]
end
```

Because `CONFIRM NOW` omits `_request_id`, **two things do not happen**:

### B1. `session[:sp]` is not refreshed
`StoreSpMetadataInSession#update_session`
(`app/services/store_sp_metadata_in_session.rb:26-33`) would otherwise rewrite:

```ruby
session[:sp] = {
  issuer:, request_url:, request_id:,
  requested_attributes:, acr_values:, vtr:,
}
```

from the `ServiceProviderRequestProxy`. On the `CONFIRM NOW` path, `session[:sp]`
retains whatever the earlier `/openid_connect/authorize` hop stored and is not
re-read from the proxy at confirmation time.

### B2. `bump_auth_count` is skipped
`AuthorizationCountConcern#bump_auth_count`
(`app/controllers/concerns/authorization_count_concern.rb:16-23`) increments
`session[:sp_auth_count][sp_session[:request_id]]`. The real email click
increments it; `CONFIRM NOW` does not.

### Does a real SP-initiated email actually carry `_request_id`?

Yes — this is why the divergence is in scope. The chain:

1. `SignUp::RegistrationsController#request_id` returns `sp_session[:request_id]`
   (`registrations_controller.rb:100-102`).
2. It is passed into the form as `params[:request_id]`
   (`registrations_controller.rb:30`).
3. `RegisterUserEmailForm#send_sign_up_email` forwards it as
   `SendSignUpEmailConfirmation.new(user).call(request_id: email_request_id(request_id))`
   (`register_user_email_form.rb:153`).
4. `email_request_id` returns the id **only if a live proxy exists**
   (`register_user_email_form.rb:211-213`):

   ```ruby
   def email_request_id(request_id)
     request_id if request_id.present? && ServiceProviderRequestProxy.find_by(uuid: request_id)
   end
   ```

5. `SendSignUpEmailConfirmation#send_confirmation_email` passes it to the mailer
   (`send_sign_up_email_confirmation.rb:48-53`), which embeds it in the link.

So for an SP-initiated signup where the proxy is still in Redis, the real email
**does** carry `_request_id`, and `CONFIRM NOW` is missing it.

---

## C. Divergence: `locale`

The real email pins the locale explicitly. `UserMailer` wraps rendering in
`with_user_locale(user)` (`user_mailer.rb:43`,
`app/helpers/locale_helper.rb:9-21`) and sets `@locale = locale_url_param`,
which is `nil` for the default locale and the locale symbol otherwise
(`locale_helper.rb:4-7`).

`CONFIRM NOW` omits `locale`, so the confirmation request is served in whatever
locale the *current browser/harness request* carries, rather than the locale
derived from `user.email_language`.

**Impact:** cosmetic for the harness (which is always `en`, matching
`user[email_language]=en` that it submits). It would matter for any non-English
load test, where the real-email path would render the confirmation in the user's
email language and `CONFIRM NOW` would not.

---

## D. Identical, but easy to misattribute

These are worth stating explicitly so a reader does not credit or blame the
`CONFIRM NOW` link for them.

| Thing | Where it actually happens | Why both paths match |
|---|---|---|
| `User` row created, `accepted_terms_at` set | `register_user_email_form.rb:150-151` (`user.save!`) at **email submission** | Both links are only reachable *after* the same `POST /sign_up/enter_email` |
| `:account_created` event row | `registrations_controller.rb:91` at **email submission** | same |
| `email_addresses.confirmation_token`, `confirmation_sent_at` | `send_sign_up_email_confirmation.rb:41-46` at **send time** | `CONFIRM NOW` reads the same persisted token back out via `EmailAddress.find_with_email(email).confirmation_token` |
| `user_registration_email` analytics + `user_registration_email_submitted` attempts event | `registrations_controller.rb:32-37` | at submission, not confirmation |
| Rate limiting (`reg_unconfirmed_email`) | `register_user_email_form.rb:139`, `:158` | at submission |
| `confirmed_at` on the email address | inside the shared confirm path | section A |

One nuance on the token: the real email embeds the token **as of send time**,
whereas `CONFIRM NOW` renders the token **as of page render**. These are the
same value in the normal flow, because `SendSignUpEmailConfirmation`
persists the token before the verify-email page renders, and reuses an existing
unexpired token rather than regenerating (`send_sign_up_email_confirmation.rb:18-24,
38-40`). A resend after expiry rotates the token, and both links would then
reflect the new one — the email because it was just sent, `CONFIRM NOW` because
it re-reads the record.

---

## Practical impact

For the load-test harness specifically, the missing `bump_auth_count` and
`session[:sp]` refresh are **largely absorbed downstream**, for two reasons:

1. **`session[:sp]` is re-established on the next authorize hop.** After
   password + MFA, the harness returns to
   `GET /openid_connect/authorize`, whose `store_request` `before_action`
   (`openid_connect/authorization_controller.rb:19, 232-239`) runs
   `ServiceProviderRequestHandler`, which calls `StoreSpMetadataInSession`
   itself (`service_provider_request_handler.rb:20-23`). So stale SP metadata
   from the confirm hop is overwritten before it is used for the handoff.

2. **`auth_count` is re-bumped on that same hop.** `bump_auth_count` is also a
   `before_action` on the authorize action
   (`authorization_controller.rb:24`).

Where it *can* still matter:

- **`auth_count` is read for a branch.** `authorization_controller.rb:49`:

  ```ruby
  if auth_count == 1 && first_visit_for_sp?
    track_handoff_analytics(result, user_sp_authorized: false)
    return redirect_to(user_authorization_confirmation_url)
  end
  ```

  The real-email path would have already bumped the count at confirmation, so
  by the time the authorize hop bumps again the count is **2**, and this branch
  is skipped. On the `CONFIRM NOW` path the confirm-hop bump never happened, so
  the authorize hop sets it to **1**, and the branch is taken when
  `first_visit_for_sp?` also holds — routing through
  `/user_authorization_confirmation` and emitting
  `track_handoff_analytics(..., user_sp_authorized: false)` instead of `true`.

  This is consistent with the harness's own experience: `/user_authorization_confirmation`
  is in the load-test harness's `INTERSTITIAL_PATHS` list, i.e. the harness
  already has to clear a screen that a real-email user might not see.

- **Telemetry fidelity.** Any analysis keyed on `sp_auth_count` or on the
  `user_sp_authorized` flag in handoff analytics will see a different shape for
  load-test traffic than for real traffic. That is precisely the sort of
  difference a load test is supposed *not* to introduce.

So: **not a functional break, but a measurable behavioral divergence** that
changes which interstitial appears and what the handoff analytics record.

---

## Existing test coverage (and its gap)

- `spec/features/load_testing/email_sign_up_spec.rb` — exercises `CONFIRM NOW`
  end to end, but only asserts the redirect path and a flash message. It does
  **not** exercise an SP-initiated flow, so the `_request_id` gap is invisible
  to it.
- `spec/views/sign_up/emails/show.html.erb_spec.rb:104-119` — asserts the link
  href as `sign_up_create_email_confirmation_url(confirmation_token: 'some_token')`,
  i.e. it **codifies the current omission**. This spec would need updating
  alongside any fix.
- `spec/views/users/emails/verify.html.erb_spec.rb` — same shape for the
  add-email view.

No spec compares the two confirmation entry points, which is why the divergence
has persisted.

---

## Proposed fix

Make the `CONFIRM NOW` link carry the same parameters the real email does. The
registration views already have the SP request id available via the controller's
session.

### 1. `app/views/sign_up/emails/show.html.erb` (lines 47-53 and 90-96)

```diff
 <% if FeatureManagement.enable_load_testing_mode? && EmailAddress.find_with_email(email) %>
   <%= link_to(
         'CONFIRM NOW',
-        sign_up_create_email_confirmation_url(confirmation_token: EmailAddress.find_with_email(email).confirmation_token),
+        sign_up_create_email_confirmation_url(
+          _request_id: sp_session[:request_id],
+          confirmation_token: EmailAddress.find_with_email(email).confirmation_token,
+        ),
         id: 'confirm-now',
       ) %>
 <% end %>
```

`sp_session` is available to views as a helper on `ApplicationController`
(`application_controller.rb:542-544`). When there is no SP request (a direct,
non-SP signup) `sp_session[:request_id]` is `nil`, the param is omitted from
the generated URL, and the controller's `return if request_id.blank?` guard
behaves exactly as it does today — so this is safe for the non-SP case and
matches the real email, which likewise only carries `_request_id` when one
exists.

### 2. Optionally pin `locale` for full parity

```diff
         sign_up_create_email_confirmation_url(
           _request_id: sp_session[:request_id],
+          locale: locale_url_param,
           confirmation_token: EmailAddress.find_with_email(email).confirmation_token,
         ),
```

`locale_url_param` comes from `LocaleHelper` (`app/helpers/locale_helper.rb:4-7`)
and returns `nil` for the default locale, matching the mailer. This is lower
value than `_request_id` — include it only if locale-sensitive load testing is
a goal.

### 3. Update the specs that encode the current behavior

`spec/views/sign_up/emails/show.html.erb_spec.rb:112-118` asserts the exact
href and must be updated. Worth adding a second context that sets
`session[:sp] = { request_id: 'abc' }` and asserts `_request_id=abc` appears,
so the parity is guarded going forward.

### 4. The add-email view is a separate, worse bug

`app/views/users/emails/verify.html.erb:38` was investigated separately and is
**not** merely missing params: it calls `sign_up_create_email_confirmation_url`
when the real add-email email calls `add_email_confirmation_url`. Those resolve
to different controllers with opposite preconditions, so the link never confirms
the email. See
[`confirm-now-fidelity-add-email.md`](./confirm-now-fidelity-add-email.md) for
the analysis and fix. Do not fold it into this change blindly — it needs its own
route correction, not just extra parameters.

### Non-goal

Do **not** try to make `CONFIRM NOW` emit `bump_auth_count` directly. The whole
point is that both links should hit the controller with the same inputs and let
the existing gate do its job; special-casing the load-testing path would
reintroduce exactly the kind of divergence this report is about.

---

## Validation

### Static re-verification (what this report rests on)

Re-read these call sites in order and confirm the claims:

1. `config/routes.rb:367-368` — both links target one action.
2. `app/views/user_mailer/email_confirmation_instructions.html.erb:14-19` — real
   link params.
3. `app/views/sign_up/emails/show.html.erb:50` and `:93` — CONFIRM NOW params.
4. `app/controllers/sign_up/email_confirmations_controller.rb:44-52` — the
   `request_id.blank?` gate.
5. `app/controllers/concerns/authorization_count_concern.rb:16-23` — what the
   skipped bump would have done.
6. `app/forms/register_user_email_form.rb:211-213` — proof that a real
   SP-initiated email does carry `_request_id`.
7. `app/controllers/openid_connect/authorization_controller.rb:24, 49` — why the
   count is re-bumped later, and the branch that reads it.

### Empirical validation (optional — for a future run)

Requires a local `identity-idp` with `enable_load_testing_mode: true`, a seeded
SP, and Redis (for `ServiceProviderRequestProxy`).

**Setup.** Start an SP-initiated signup so a `request_id` exists:
drive `GET /openid_connect/authorize?...&prompt=create`, then
`POST /sign_up/enter_email`. Stop at `/sign_up/verify_email`.

**Run A — CONFIRM NOW.** Click the `CONFIRM NOW` link. Record:

```ruby
# in rails console, or via a request spec
session[:sp]                                 # => stale (from the authorize hop)
session[:sp_auth_count]                      # => NOT incremented by this hop
Event.where(user_id: user.id).pluck(:event_type)
EmailAddress.find_with_email(email).confirmed_at
```

**Run B — real email link.** Repeat the setup with a fresh email, then extract
the link from the delivered mail and visit it:

```ruby
mail = ActionMailer::Base.deliveries.last
url  = mail.body.to_s[/https?:\/\/\S*sign_up\/email\/confirm\S*/]
# visit url
```

Record the same four values.

**Expected diff:**

| Observation | CONFIRM NOW | Real email link |
|---|---|---|
| `_request_id` in URL | absent | present |
| `session[:sp]` rewritten on this hop | no | yes |
| `session[:sp_auth_count][request_id]` | unchanged | incremented |
| `Event` rows | identical | identical |
| `confirmed_at` set | yes | yes |
| analytics `user_registration_email_confirmation` | emitted | emitted |
| attempts `user_registration_email_confirmed` | emitted | emitted |

**Then confirm the downstream consequence:** continue both runs through
password + MFA to `GET /openid_connect/authorize` and compare whether
`/user_authorization_confirmation` is interposed, and what
`user_sp_authorized` is in the handoff analytics. Per
[Practical impact](#practical-impact), Run A is expected to hit the
`auth_count == 1 && first_visit_for_sp?` branch and Run B is not.

**After applying the proposed fix,** re-run A and expect every row in the table
to match Run B.

---

## Suggested story / PR framing

**Title:** Load-testing `CONFIRM NOW` link omits `_request_id`, diverging from
real email confirmations

**Why it matters:** The link exists so load tests can exercise the real
registration flow without email. For SP-initiated signups it does not, quite:
because it omits `_request_id`, the confirmation request skips
`StoreSpMetadataInSession` and `bump_auth_count`. The flow still completes, but
the authorization count is one lower than a real user's at the same point,
which flips the `auth_count == 1 && first_visit_for_sp?` branch in the OIDC
authorize action — so load-test traffic takes a different interstitial path and
records `user_sp_authorized: false` where real traffic records `true`.

**Scope:** Two `link_to` call sites in
`app/views/sign_up/emails/show.html.erb`. Update
`spec/views/sign_up/emails/show.html.erb_spec.rb`, which currently asserts the
href without `_request_id`.

**Risk:** Low. `sp_session[:request_id]` is `nil` for non-SP signups, in which
case the param is omitted and behavior is unchanged — identical to how the real
email behaves when no SP request exists.

**Related:** the add-email `CONFIRM NOW` link has a *functional* bug (wrong
target controller, never confirms the email) documented in
[`confirm-now-fidelity-add-email.md`](./confirm-now-fidelity-add-email.md).
These could ship together as "make load-testing confirmation links match their
real counterparts," or separately given the different severities.

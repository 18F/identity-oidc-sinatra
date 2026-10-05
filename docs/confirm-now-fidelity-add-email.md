# Fidelity of the add-email "CONFIRM NOW" link vs. a real add-email confirmation

**Repository under analysis:** `identity-idp` @ `main` / `62cf38755d`
**Scope:** the add-email flow — an authenticated user adding a secondary email
address to an existing account
**Method:** static / code-level differential
**Companion document:** [`confirm-now-fidelity.md`](./confirm-now-fidelity.md)
covers the *registration* CONFIRM NOW link, which is a separate and much milder
problem.

---

## Verdict

**Not faithful. The link is broken.**

The add-email `CONFIRM NOW` link points at the **registration** confirmation
controller, not the **add-email** confirmation controller. Those two controllers
have *mutually exclusive* preconditions on user state, and the add-email page is
only ever reached by a user who fails the registration controller's
precondition.

Consequently, clicking the add-email `CONFIRM NOW` link:

- **never confirms the email address** (`confirmed_at` is not set),
- emits a **failure** analytics event mislabeled as a *registration* event,
- emits a **failure** attempts-API event, also mislabeled as registration,
- sets an "already confirmed" flash **error** and bounces to the account page,
- **skips every side effect** the real confirmation performs — the `email_added`
  notification emails and two `PushNotification` events.

This is deterministic, not intermittent. It fails 100% of the time.

A load test that uses this link therefore does not exercise the add-email
confirmation path **at all**. It exercises a guard clause.

A second, independent defect is documented in
[Appendix: unscoped token lookup](#appendix-unscoped-token-lookup).

---

## The two links target different controllers

This is the root of everything below.

### Real add-email confirmation email

`app/mailers/user_mailer.rb:202-215`:

```ruby
def add_email(token:, request_id:, from_select_email_flow: nil)
  with_user_locale(user) do
    ...
    @add_email_url = add_email_confirmation_url(
      confirmation_token: token,
      from_select_email_flow:,
      locale: locale_url_param,
      request_id:,
    )
```

`add_email_confirmation_url` → `config/routes.rb:313`:

```ruby
get '/add/email/confirm' => 'users/email_confirmations#create', as: :add_email_confirmation
```

**Target: `Users::EmailConfirmationsController#create`.**

### CONFIRM NOW link

`app/views/users/emails/verify.html.erb:35-41`:

```erb
<% if FeatureManagement.enable_load_testing_mode? && EmailAddress.find_with_email(@email) %>
  <%= link_to(
        'CONFIRM NOW',
        sign_up_create_email_confirmation_url(confirmation_token: EmailAddress.find_with_email(@email).confirmation_token),
      ) %>
```

`sign_up_create_email_confirmation_url` → `config/routes.rb:367-368`:

```ruby
get '/sign_up/email/confirm' => 'sign_up/email_confirmations#create',
    as: :sign_up_create_email_confirmation
```

**Target: `SignUp::EmailConfirmationsController#create`.**

Different route, different controller, different flow. The link appears to have
been copied from `app/views/sign_up/emails/show.html.erb` without swapping the
route helper.

---

## Why it fails deterministically

The two controllers have **opposite** requirements on whether the token's owner
is already a confirmed user.

### Registration confirm requires an UNCONFIRMED user

`SignUp::EmailConfirmationsController` includes `UnconfirmedUserConcern` and runs
this `before_action` (`email_confirmations_controller.rb:9`):

```ruby
# app/controllers/concerns/unconfirmed_user_concern.rb:12-15
def confirm_user_needs_sign_up_confirmation
  return unless @user&.confirmed?
  process_already_confirmed_user      # <-- bails out
end
```

`@user` comes from the token (`unconfirmed_user_concern.rb:6-10`):

```ruby
@email_address = EmailAddress.find_with_confirmation_token(@confirmation_token)
@user = @email_address&.user
```

### Add-email confirm requires a CONFIRMED user

`Users::EmailConfirmationsController#email_address`
(`users/email_confirmations_controller.rb:18-29`):

```ruby
email_address = EmailAddress.find_with_confirmation_token(...)
if email_address&.user&.confirmed?
  @email_address = email_address
else
  @email_address = nil              # <-- the inverse condition
end
```

### On the add-email page, the user is ALWAYS confirmed

1. `Users::EmailsController` requires full authentication
   (`users/emails_controller.rb:7`: `before_action :confirm_two_factor_authenticated`),
   so `current_user` is a registered, signed-in user.
2. `User#confirmed?` is `confirmed_email_addresses.any?` (`app/models/user.rb:83-85`).
   A registered user necessarily has at least one confirmed email — that is how
   they completed registration.
3. The new `EmailAddress` row is built with `user_id: current_user.id`
   (`app/forms/add_user_email_form.rb:36-44`), so the token resolves back to
   that same confirmed user.

Therefore `@user&.confirmed?` is **always true**, the registration controller's
guard **always fires**, and the request never reaches `create`.

---

## What actually happens when you click it

Execution order in `SignUp::EmailConfirmationsController`
(`email_confirmations_controller.rb:8-12`):

| Step | Code | Result |
|---|---|---|
| 1 | `find_user_with_confirmation_token` (`unconfirmed_user_concern.rb:6-10`) | finds the new unconfirmed `EmailAddress`; `@user` = the existing **confirmed** user |
| 2 | `confirm_user_needs_sign_up_confirmation` (`:12-15`) | `@user.confirmed?` → **true** → `process_already_confirmed_user` |
| 3 | `track_user_already_confirmed_event` (`:24-35`) | emits **`user_registration_email_confirmation(success: false, errors: {email: ['already confirmed']})`** |
| 4 | same | emits **`user_registration_email_confirmed(success: false, failure_reason: {email: [:already_confirmed]})`** |
| 5 | `:19-21` | `flash[:error] = t('devise.confirmations.already_confirmed')` |
| 6 | `:21` | `redirect_to account_url` (the user is signed in) |

The chain halts at step 2. `create` never runs.

### The email is never confirmed

`confirmed_at` is set only in `Users::EmailConfirmationsController#confirm_and_notify`
(`users/email_confirmations_controller.rb:55-62`), which is never reached. The
`EmailAddress` row keeps `confirmed_at: nil` and remains an unconfirmed,
dangling row.

### Telemetry is actively misleading

Steps 3 and 4 do not merely fail to record an add-email confirmation — they
record a **registration** confirmation failure. Any analysis of
`user_registration_email_confirmation` failure rates will be polluted by
add-email load-test traffic, attributed to a flow the user was never in.

---

## Differential: what the real path does that CONFIRM NOW skips

Every row here is a side effect of `Users::EmailConfirmationsController#create`
that the `CONFIRM NOW` path **does not produce**.

| Side effect | Location | CONFIRM NOW |
|---|---|---|
| `add_email_confirmation` analytics event (with `from_select_email_flow`) | `users/email_confirmations_controller.rb:8`; event at `analytics_events.rb:236-250` | **not emitted** |
| `email_address.update!(confirmed_at: Time.zone.now)` | `:56` | **not performed** — the email stays unconfirmed |
| `UserMailer#email_added` to **every** confirmed address on the account | `:57-60` | **not sent** |
| `PushNotification::EmailChangedEvent` delivered to subscribers | `:66-67` | **not delivered** |
| `PushNotification::RecoveryInformationChangedEvent` delivered | `:68-69` | **not delivered** |
| `session[:from_select_email_flow]` set from the param | `:103-105` | **not set** |
| Redirect to `sign_up_select_email_url` (when `request_id` present) or `account_url` | `:42-52` | lands on `account_url` via the *error* path instead |
| Success flash `devise.confirmations.confirmed` | `:43` | replaced by an **error** flash |

And what it produces *instead*, which the real path never does:

| Spurious effect | Location |
|---|---|
| `user_registration_email_confirmation(success: false, …)` | `unconfirmed_user_concern.rb:25-29` |
| `user_registration_email_confirmed(success: false, …)` | `unconfirmed_user_concern.rb:30-34` |
| `flash[:error]` "already confirmed" | `unconfirmed_user_concern.rb:20` |

The two `PushNotification` deliveries are worth calling out specifically: they
are outbound RISC/push notifications to relying parties. A load test that is
supposed to exercise add-email confirmation generates **zero** of them, so any
capacity planning based on such a run would under-count push-notification load
entirely.

---

## Missing URL parameters (secondary)

Even after the route helper is corrected, the link would still omit parameters
the real email carries. Compare `user_mailer.rb:207-212` against
`verify.html.erb:38`:

| Param | Real email | CONFIRM NOW |
|---|---|---|
| `confirmation_token` | yes | yes |
| `request_id` | yes | **missing** |
| `from_select_email_flow` | yes | **missing** |
| `locale` | yes (`locale_url_param`) | **missing** |

Each has a concrete consequence in `Users::EmailConfirmationsController`:

- **`request_id`** selects the post-confirmation destination
  (`:44-48`): with it, `sign_up_select_email_url`; without it, `account_url`.
  `Users::EmailsController#request_id` is `sp_session[:request_id]`
  (`users/emails_controller.rb:101-103`), so it is present whenever the
  add-email flow was entered from an SP.
- **`from_select_email_flow`** is stored in the session (`:103-105`) and
  reported in the analytics event (`:8`). Omitting it silently changes both
  the recorded event and downstream session state.
- **`locale`** pins the response locale, as in the registration case.

Note this is a *superset* of the registration link's omissions: the
registration link is missing `_request_id` and `locale`; this one is missing
`request_id`, `from_select_email_flow`, **and** `locale`, on top of pointing at
the wrong controller.

---

## Existing test coverage (and why this was never caught)

- **No feature spec exercises the add-email `CONFIRM NOW` link.**
  `spec/features/load_testing/` contains exactly one file,
  `email_sign_up_spec.rb`, which covers the *registration* link only. A
  feature spec for add-email would have failed immediately, because the page
  would show an error flash and land on the account page instead of confirming.

- **The view spec codifies the bug.**
  `spec/views/users/emails/verify.html.erb_spec.rb:46-51`:

  ```ruby
  it 'generates the correct link' do
    expect(rendered).to have_link(
      'CONFIRM NOW',
      href: sign_up_create_email_confirmation_url(confirmation_token: 'some_token'),
    )
  end
  ```

  It asserts the *wrong* route helper, and is titled "generates the correct
  link." Any fix must update this spec, and the spec's existence explains why
  the defect survived review: it reads as intentional.

  The same spec file also builds its fixture with
  `create(:email_address, confirmation_token: 'some_token', email: email)` —
  with **no user association**, so the factory's default user is unconfirmed
  and the precondition conflict never surfaces even in principle.

---

## Proposed fix

### 1. Point the link at the add-email confirmation route

`app/views/users/emails/verify.html.erb:35-41`:

```diff
 <% if FeatureManagement.enable_load_testing_mode? && EmailAddress.find_with_email(@email) %>
   <%= link_to(
         'CONFIRM NOW',
-        sign_up_create_email_confirmation_url(confirmation_token: EmailAddress.find_with_email(@email).confirmation_token),
+        add_email_confirmation_url(
+          confirmation_token: EmailAddress.where(user_id: current_user.id)
+            .find_with_email(@email).confirmation_token,
+          from_select_email_flow: @in_select_email_flow,
+          locale: locale_url_param,
+          request_id: sp_session[:request_id],
+        ),
+        id: 'confirm-now',
       ) %>
   <br />
 <% end %>
```

Four changes, each deliberate:

1. **`add_email_confirmation_url`** — the actual fix. Targets
   `Users::EmailConfirmations#create`, whose precondition the user satisfies.
2. **`.where(user_id: current_user.id)`** — see
   [Appendix](#appendix-unscoped-token-lookup); scopes the lookup the way
   `EmailsController#resend` already does (`users/emails_controller.rb:40`).
3. **`from_select_email_flow`, `locale`, `request_id`** — parity with
   `user_mailer.rb:207-212`. `@in_select_email_flow` is already assigned by the
   controller (`users/emails_controller.rb:76`); `locale_url_param` comes from
   `LocaleHelper`; `sp_session` is a view-accessible helper
   (`application_controller.rb:542-544`). All three degrade to `nil` when absent,
   exactly as the mailer does.
4. **`id: 'confirm-now'`** — the registration link has this anchor
   (`sign_up/emails/show.html.erb:51`, `:94`) and the load-test harness scrapes
   by it (`Page.confirm_now_href` prefers `a#confirm-now`). Adding it makes the
   add-email link scrapeable by the same code path, instead of relying on the
   link-text fallback.

### 2. Guard the scoped lookup

The `if` condition calls the unscoped `find_with_email` and the body calls it
again. Both should be scoped, and the double query is avoidable. Consider
hoisting it in the controller instead — `Users::EmailsController#verify`
(`users/emails_controller.rb:74-78`) already assigns `@email`, and could assign
the record:

```ruby
def verify
  @email = session_email
  @in_select_email_flow = in_select_email_flow_param
  @pending_completions_consent = pending_completions_consent?
  if FeatureManagement.enable_load_testing_mode?
    @email_address = EmailAddress.where(user_id: current_user.id).find_with_email(@email)
  end
end
```

This mirrors the scoping in `#resend` and keeps the view to a single
`@email_address.confirmation_token` reference. It is the cleaner shape, but it
moves load-testing concerns into the controller — reviewer's call.

### 3. Update the view spec

`spec/views/users/emails/verify.html.erb_spec.rb:38-52` must change to assert
`add_email_confirmation_url` with the new params. The fixture also needs a
**confirmed** user so it reflects reality:

```ruby
context 'when enable_load_testing_mode? is true and email address found' do
  let(:user) { create(:user, :fully_registered) }

  before do
    allow(FeatureManagement).to receive(:enable_load_testing_mode?).and_return(true)
    allow(view).to receive(:current_user).and_return(user)
    create(:email_address, user:, confirmation_token: 'some_token', email:)
    render
  end

  it 'links to the add-email confirmation route, not the registration one' do
    expect(rendered).to have_link(
      'CONFIRM NOW',
      href: add_email_confirmation_url(confirmation_token: 'some_token'),
    )
  end
end
```

### 4. Add the missing feature spec

This is the regression guard that would have prevented the defect. Mirror
`spec/features/load_testing/email_sign_up_spec.rb` for add-email:

```ruby
# spec/features/load_testing/add_email_spec.rb
require 'rails_helper'

RSpec.feature 'Add email via load-testing link' do
  scenario 'CONFIRM NOW confirms the added address' do
    allow(IdentityConfig.store).to receive(:enable_load_testing_mode).and_return(true)
    user = create(:user, :fully_registered)
    sign_in_and_2fa_user(user)

    visit add_email_path
    fill_in :user_email, with: 'new@example.com'
    click_button t('forms.buttons.submit.default')

    click_link('CONFIRM NOW')

    expect(page).to have_content(t('devise.confirmations.confirmed'))
    expect(EmailAddress.find_with_email('new@example.com').confirmed_at).to be_present
  end
end
```

On current `main` this fails on both expectations: the page shows the
"already confirmed" **error**, and `confirmed_at` is `nil`.

### Non-goal

Do not "fix" this by relaxing the precondition in either controller. The two
guards encode genuinely different flows — registration confirms a *first* email
for an unconfirmed user; add-email confirms an *additional* email for a
confirmed one. The bug is the link, not the guards.

---

## Validation

### Static re-verification

Read these in order:

1. `app/views/users/emails/verify.html.erb:38` — the link uses
   `sign_up_create_email_confirmation_url`.
2. `app/mailers/user_mailer.rb:207-212` — the real email uses
   `add_email_confirmation_url`.
3. `config/routes.rb:313` vs `:367-368` — the two helpers map to different
   controllers.
4. `app/controllers/concerns/unconfirmed_user_concern.rb:12-15` — registration
   confirm bails when the user is confirmed.
5. `app/controllers/users/email_confirmations_controller.rb:18-29` — add-email
   confirm requires the user to be confirmed.
6. `app/controllers/users/emails_controller.rb:7` +
   `app/models/user.rb:83-85` — the add-email page is only reachable by a
   confirmed user, so (4) always fires.
7. `app/controllers/users/email_confirmations_controller.rb:55-70` — the side
   effects that are consequently skipped.

### Empirical validation

Requires a local `identity-idp` with `enable_load_testing_mode: true`.

**Setup.** Sign in as a fully-registered user, go to `/add/email`, submit a new
address, and stop on `/add/email/verify_email`.

**Run A — CONFIRM NOW.** Click the link. Expect:

```ruby
# the email is NOT confirmed
EmailAddress.find_with_email('new@example.com').confirmed_at   # => nil

# wrong-flow failure events were emitted
# grep the analytics log for:
#   'User Registration: Email Confirmation'  success: false, already_confirmed
# and NOT for:
#   'Add Email: Email Confirmation'

# no notification emails went out
ActionMailer::Base.deliveries.map(&:subject)   # => no t('user_mailer.email_added.subject')

# flash is an error, and you land on the account page
```

**Run B — real email link.** Repeat the setup with a fresh address, then visit
the link from the delivered mail:

```ruby
mail = ActionMailer::Base.deliveries.last
url  = mail.body.to_s[/https?:\/\/\S*add\/email\/confirm\S*/]
# visit url
```

Expect the inverse: `confirmed_at` present, `'Add Email: Email Confirmation'`
emitted, `email_added` mail delivered to every confirmed address, two
`PushNotification` deliveries, success flash.

**After the fix,** Run A should match Run B on every observation.

---

## Appendix: unscoped token lookup

Independent of the wrong-route defect, the view's record lookup is not scoped to
the current user. `app/views/users/emails/verify.html.erb:35, 38` both call:

```ruby
EmailAddress.find_with_email(@email)
```

`EmailAddress.find_with_email` is `find_by(email_fingerprint: …)` with **no user
scope** (`app/models/email_address.rb:57-63`). The model itself documents that
duplicates are possible (`:70-72`):

> It is possible for the same email address to exist more than once if it is
> unconfirmed, but only one row with that email address can be confirmed.

So if another user already has an **unconfirmed** row for the same address,
`find_with_email` may return *that* row, and the rendered `CONFIRM NOW` link
would carry **another user's confirmation token**.

By contrast, `Users::EmailsController#resend` scopes correctly
(`users/emails_controller.rb:40`):

```ruby
EmailAddress.where(user_id: current_user.id).find_with_email(session_email)
```

Severity is bounded — the link only renders under `enable_load_testing_mode`,
which is `false` by default (`config/application.yml.default`) and should never
be on in production. Treat it as a correctness bug in a test affordance, not a
production token-disclosure vulnerability. The fix in
[Proposed fix](#proposed-fix) scopes it.

The registration view (`sign_up/emails/show.html.erb:50`, `:93`) has the same
unscoped call. There it is less likely to matter, since the row belongs to a
brand-new unconfirmed user, but it is the same latent shape and could equally
select a different user's unconfirmed row for the same address.

---

## Suggested story / PR framing

**Title:** Add-email `CONFIRM NOW` load-testing link targets the registration
confirmation route and never confirms the email

**Why it matters:** The link at `app/views/users/emails/verify.html.erb:38`
calls `sign_up_create_email_confirmation_url`, but the real add-email
confirmation email calls `add_email_confirmation_url`. These resolve to
different controllers with opposite preconditions on user confirmation state,
and the add-email page is only reachable by a confirmed user — so the
registration controller's `confirm_user_needs_sign_up_confirmation` guard fires
every time. The result: the email is never confirmed, two failure events are
logged against the *registration* flow, and the real path's side effects
(`add_email_confirmation` analytics, `email_added` notifications, and two
`PushNotification` deliveries) never occur. Any load test using this link
measures a guard clause, not the add-email flow.

**Scope:** One `link_to` in `app/views/users/emails/verify.html.erb`. Update
`spec/views/users/emails/verify.html.erb_spec.rb:38-52`, which currently asserts
the wrong route helper under the title "generates the correct link." Add
`spec/features/load_testing/add_email_spec.rb` — there is currently no feature
coverage for this link, which is why the defect persisted.

**Risk:** Low. The change moves the link from a route that always errors to the
route the real email already uses. The added params all degrade to `nil` when
absent, matching the mailer's own behavior.

**Related:** the registration `CONFIRM NOW` link has a milder version of the
same parameter-omission problem — see
[`confirm-now-fidelity.md`](./confirm-now-fidelity.md). The two could ship as
one PR ("make load-testing confirmation links match their real counterparts")
or separately, since this one is a functional bug and that one is a fidelity
gap.

# `platform_authenticator_available` renders a garbage value

**Repository:** `identity-idp`
**Severity:** Low (cosmetic / data hygiene — no functional regression)
**Found by:** OIDC Sinatra load-test harness, tracing a live signup flow against
`idp.evelyn.identitysandbox.gov`

---

## Summary

Three views render the `platform_authenticator_available` hidden input with the
value `"id platform_authenticator_available"` instead of an empty string. The
options hash is passed in the **value** positional argument of
`hidden_field_tag`, so Rails serializes the hash into the field's `value`
attribute.

The field is then submitted with that nonsense value on every POST from those
pages.

---

## Root cause

`hidden_field_tag` has the signature:

```ruby
hidden_field_tag(name, value = nil, options = {})
```

The affected views omit the second positional argument, so the hash binds to
**`value`**, not `options`:

```erb
<%= hidden_field_tag :platform_authenticator_available, id: 'platform_authenticator_available' %>
```

Rails stringifies a Hash value by joining its keys and values with spaces,
producing:

```html
<input type="hidden" name="platform_authenticator_available"
       id="platform_authenticator_available"
       value="id platform_authenticator_available" autocomplete="off" />
```

The pattern generalizes — a two-key hash in the value position renders
`value="id bar class baz"`.

### Affected files

| File | Line |
|---|---|
| `app/views/users/two_factor_authentication_setup/index.html.erb` | 52 |
| `app/views/users/two_factor_authentication_setup/index.html.erb` | 129 |
| `app/views/devise/sessions/new.html.erb` | 181 |
| `app/views/devise/sessions/new.html.erb` | 75-78 (multi-line form of the same call) |

### Already correct

`app/views/sign_up/passwords/new.html.erb:51` and `:78` pass `nil` explicitly
and render correctly:

```erb
<%= hidden_field_tag :platform_authenticator_available, nil, id: 'platform_authenticator_available' %>
```

This asymmetry is itself evidence the omission is unintentional.

---

## Impact

**This is a hygiene bug, not a functional one.** Be precise about this in the
PR, because the obvious-looking consequences turn out not to hold:

### What is actually wrong

The field submits `platform_authenticator_available=id platform_authenticator_available`
on every POST from the affected pages. That value is meaningless, appears in
request logs, and is misleading to anyone debugging the MFA flow — which is
exactly how it was found.

### What is NOT wrong (verified, do not claim these)

- **The `id` attribute is still present.** Rails auto-derives `id` from `name`
  via `sanitize_to_id`, so the rendered tag has
  `id="platform_authenticator_available"` even though the explicit `id:` option
  was consumed as the value. `document.getElementById('platform_authenticator_available')`
  in `app/javascript/packs/platform-authenticator-available.ts:4` works fine.
- **The feature still behaves correctly.** Every consumer compares against the
  literal string `'true'`:

  ```ruby
  # app/controllers/users/two_factor_authentication_setup_controller.rb:39-40
  user_session[:platform_authenticator_available] =
    params[:platform_authenticator_available] == 'true'
  ```

  The garbage value is not `'true'`, so it evaluates to `false` — the same
  result an empty value would give. When a platform authenticator *is* present,
  the JS overwrites the value with `'true'` and the comparison succeeds.

So the behavior is **accidentally correct**: the bug is masked by the fact that
the only value anyone tests for is `'true'`.

### Why fix it anyway

1. The submitted data is wrong and misleading in logs and traces.
2. It is masked only by the `== 'true'` comparison style. Any future consumer
   that treats the field as a tri-state (`present?`, `blank?`, or a cast like
   `ActiveModel::Type::Boolean`) would read the garbage string as truthy and
   silently invert the behavior.
3. The same file already does it correctly two views over, so this is a
   one-character-class fix with no behavior change.

### Consumers of this value (for reviewer context)

| File | Line | Use |
|---|---|---|
| `users/two_factor_authentication_setup_controller.rb` | 39-40 | sets `user_session[...]` from params |
| `users/two_factor_authentication_setup_controller.rb` | 119, 129-130 | passkey auto-prompt eligibility |
| `sign_up/passwords_controller.rb` | 83-84 | sets `user_session[...]` from params |
| `users/sessions_controller.rb` | 212-213 | sets `user_session[...]` from params |
| `concerns/mfa_setup_concern.rb` | 166 | `recommend_webauthn_platform_for_sms_user?` |
| `two_factor_authentication/otp_verification_controller.rb` | 112 | `confirm_eligible_for_platform_upsell?` |
| `users/two_factor_authentication_controller.rb` | 385 | `redirect_url` branch on `== false` |

Note line 385 branches on `== false` specifically, and line 112 is a bare
truthiness check on the **session** value (not the param), so neither is
affected by the param's rendered value — but both illustrate that the
tri-state risk in point 2 above is not hypothetical in this codebase.

---

## The fix

Pass `nil` explicitly in the value position, matching
`sign_up/passwords/new.html.erb`.

### `app/views/users/two_factor_authentication_setup/index.html.erb` (lines 52 and 129)

```diff
-<%= hidden_field_tag :platform_authenticator_available, id: 'platform_authenticator_available' %>
+<%= hidden_field_tag :platform_authenticator_available, nil, id: 'platform_authenticator_available' %>
```

### `app/views/devise/sessions/new.html.erb` (line 181)

```diff
-<%= hidden_field_tag :platform_authenticator_available, id: 'platform_authenticator_available' %>
+<%= hidden_field_tag :platform_authenticator_available, nil, id: 'platform_authenticator_available' %>
```

### `app/views/devise/sessions/new.html.erb` (lines 75-78, multi-line form)

```diff
 <%= hidden_field_tag(
       :platform_authenticator_available,
+      nil,
       id: 'platform_authenticator_available',
     ) %>
```

Four call sites, one change each. No controller, JS, or behavior changes.

---

## How to validate it is really a bug

Four independent checks, in increasing cost. Validation A alone is sufficient
proof of the rendering defect.

### Validation A — Prove the rendering in isolation (no Rails app boot)

Requires only `actionview` and `nokogiri`.

```ruby
require "action_view"
require "nokogiri"

class Probe
  include ActionView::Helpers::FormTagHelper
  include ActionView::Helpers::TagHelper
end

v = Probe.new

buggy   = v.hidden_field_tag(:platform_authenticator_available, id: 'platform_authenticator_available')
correct = v.hidden_field_tag(:platform_authenticator_available, nil, id: 'platform_authenticator_available')

b = Nokogiri::HTML(buggy).at_css("input")
c = Nokogiri::HTML(correct).at_css("input")

puts "buggy   value=#{b['value'].inspect}  id=#{b['id'].inspect}"
puts "correct value=#{c['value'].inspect}  id=#{c['id'].inspect}"
```

**Observed output (actionview 8.1.4):**

```
buggy   value="id platform_authenticator_available"  id="platform_authenticator_available"
correct value=nil                                    id="platform_authenticator_available"
```

**Pass condition for "this is a bug":** the first call renders
`value="id platform_authenticator_available"`; the second renders no value.
Both retain the `id` attribute — confirming the defect is the value only.

### Validation B — Prove it in the rendered view (view spec)

`spec/views/users/two_factor_authentication_setup/index.html.erb_spec.rb:39-41`
already asserts the field exists, but asserts nothing about its value. Tighten
it:

```ruby
it 'renders the platform authenticator hidden field with no preset value' do
  expect(rendered).to have_css('input#platform_authenticator_available', visible: false)

  field = Nokogiri::HTML(rendered.to_s).at_css('input#platform_authenticator_available')
  expect(field['value'].to_s).to eq('')
end
```

**Pass condition:** fails on `main` with
`"id platform_authenticator_available"`, passes after the fix.

Add the equivalent to the `devise/sessions/new.html.erb` view spec. Both of
these are worth keeping as regression guards — the existing specs pass today
*because* they only check for presence, which is why this slipped through.

### Validation C — Observe the value in the browser

On `/authentication_methods_setup` or the sign-in page, in the console:

```js
document.querySelector('input[name="platform_authenticator_available"]').value
// main:      "id platform_authenticator_available"
// after fix: ""
```

Also confirm the JS path is unaffected (it should return the element both
before and after):

```js
document.getElementById('platform_authenticator_available')  // => <input>, not null
```

### Validation D — Live traffic evidence (already captured)

Captured from the OIDC Sinatra load-test harness against
`idp.evelyn.identitysandbox.gov`, on the POST to
`/authentication_methods_setup`:

```
trace: POST https://idp.evelyn.identitysandbox.gov/authentication_methods_setup -> 302
trace:   location: https://idp.evelyn.identitysandbox.gov/phone_setup
trace:   params: _method=patch&authenticity_token=...&platform_authenticator_available=id platform_authenticator_available&two_factor_options_form[selection][]=phone
```

And from the same run, the POST to `/sign_up/create_password` — rendered by the
**correct** view — for contrast:

```
trace:   params: ...&platform_authenticator_available=&password_form[password]=...
```

Same field, same flow, two adjacent requests: garbage from the buggy view,
empty from the correct one. This is real traffic from a deployed sandbox,
independent of any unit reproduction.

---

## Downstream note

The load-test harness in `identity-oidc-sinatra` now normalizes this field when
scraping forms for replay (`lib/loadtest/page.rb`, `BOOLEAN_HIDDEN_FIELDS`),
coercing anything that is not literally `'true'` to `'false'`. That workaround
is correct regardless of whether this bug is fixed, and will keep working after
the fix lands — it preserves a genuine `'true'` and normalizes everything else.

The harness workaround is deliberately a *normalization*, not a parse of the
garbage string, so it does not depend on the specific malformed value.

---

## Suggested story / PR framing

**Title:** Fix `platform_authenticator_available` hidden field rendering a
serialized options hash as its value

**Why now:** Found while tracing a live signup flow. The field submits
`platform_authenticator_available=id platform_authenticator_available` on every
POST from the MFA setup and sign-in pages. Behavior is unaffected today because
every consumer compares against the literal `'true'`, but the submitted data is
wrong, it pollutes request logs, and it is one tri-state check away from
becoming a real defect.

**Scope:** Four `hidden_field_tag` call sites across two views. Add value
assertions to the two existing view specs, which currently only assert the
field's presence — the reason this was not caught.

**Risk:** Minimal. The rendered `id` and `name` are unchanged, the JS continues
to find and set the element, and the value changes from a string that is not
`'true'` to a string that is also not `'true'`.

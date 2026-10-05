# frozen_string_literal: true

require_relative 'base'

module LoginGov
  module OidcSinatra
    module Loadtest
      module Flows
        # Full account creation, started from the RP.
        #
        # By default this mirrors what a real user does: land on the IdP's
        # sign-in page (the RP sends no `prompt`, so the IdP routes an
        # unauthenticated user there -- OpenidConnect::AuthorizationController
        # #redirect_to_sign_in_or_create) and click "Create an account" through
        # to /sign_up/enter_email.
        #
        # Set `short_circuit_to_registration: true` in the signup config to skip
        # the sign-in page instead, by sending `prompt=create` directly (the
        # RP sets this when `initiate_registration` is present -- app.rb). The
        # IdP honors that prompt value by redirecting straight to
        # /sign_up/enter_email (same controller, #initiate_user_registration?),
        # so this is a strictly shorter path through the same code, useful for
        # isolating registration cost from the sign-in page's.
        #
        # Unlike the sign-in flows this creates a new IdP user per run. Two IdP
        # settings make it possible without real email or SMS:
        #
        #   * `enable_load_testing_mode: true` renders a "CONFIRM NOW" link on
        #     the verify-email page carrying the real confirmation token, which
        #     stands in for clicking a link in an email.
        #   * `telephony_adapter: test` (development default) makes the IdP
        #     prefill the real OTP into the phone-confirmation page.
        #
        # The short-circuit path also requires the SP to be allow-listed for
        # prompt=create via `allowed_create_prompt_providers`, otherwise the
        # authorize request is rejected. See the README for all three settings.
        class Signup < Base
          def self.flow_type
            'signup'
          end

          def run(user:)
            response = step('rp_auth_request') { begin_signup }
            response = step('submit_email') { submit_email(response, user.fetch(:email)) }
            response = step('confirm_email') { confirm_email(response) }
            response = step('create_password') do
              create_password(response, user.fetch(:password))
            end
            response = step('select_mfa') { select_phone_mfa(response) }
            response = step('submit_phone') { submit_phone(response, user.fetch(:phone)) }
            response = step('otp_submit') { submit_otp(response) }
            finish_at_rp(response)
          end

          private

          def begin_signup
            if flow_settings.fetch('short_circuit_to_registration')
              begin_registration_directly
            else
              begin_via_sign_in_page
            end
          end

          # Send `prompt=create`, which the IdP honors by redirecting straight
          # to /sign_up/enter_email, skipping the sign-in page entirely.
          def begin_registration_directly
            begin_at_rp(initiate_registration: '1', 'requested_scopes[]' => %w[email x509])
          end

          # GET the RP with no `prompt`, landing on the IdP sign-in page, then
          # click "Create an account" through to /sign_up/enter_email -- the
          # path a real user who has not registered yet actually takes.
          def begin_via_sign_in_page
            response = begin_at_rp('requested_scopes[]' => %w[email x509])

            href = Page.create_account_href(response.body)
            if href.nil?
              raise Error.new("no \"Create an account\" link on #{response.uri}")
            end

            followed = http.get(http.absolutize(href, base: response.uri))
            http.follow_redirects(followed).last
          end

          # POST /sign_up/enter_email
          #
          # `terms_accepted` is required by RegisterUserEmailForm. The current
          # markup carries it as a hidden input, so scraping the form picks it up
          # automatically; it is set explicitly as well because the legacy layout
          # renders it as an unchecked checkbox (which would not be scraped).
          def submit_email(response, email)
            form = Page.find_form(response.body, path: '/sign_up/enter_email')
            raise Error.new("no registration form on #{response.uri}") if form.nil?

            params = {
              'user[email]' => email,
              'user[terms_accepted]' => '1',
              'user[email_language]' => 'en',
            }.merge(Page.mock_recaptcha_fields(response.body, scope: 'user'))

            submitted = submit(form, base: response.uri, params: params)
            http.follow_redirects(submitted).last
          end

          # Follow the load-testing CONFIRM NOW link in place of an email click.
          def confirm_email(response)
            href = Page.confirm_now_href(response.body)
            if href.nil?
              message = "no CONFIRM NOW link on #{response.uri} — set " \
                        "enable_load_testing_mode: true on the IdP"
              raise Error.new(message)
            end

            confirmed = http.get(http.absolutize(href, base: response.uri))
            http.follow_redirects(confirmed).last
          end

          # POST /sign_up/create_password
          #
          # The confirmation token is carried in a hidden field on the form, so
          # scraping it avoids having to thread the token through from the
          # previous step.
          def create_password(response, password)
            form = Page.find_form(response.body, path: '/sign_up/create_password')
            raise Error.new("no password form on #{response.uri}") if form.nil?

            submitted = submit(
              form,
              base: response.uri,
              params: {
                'password_form[password]' => password,
                'password_form[password_confirmation]' => password,
              },
            )
            http.follow_redirects(submitted).last
          end

          # PATCH /authentication_methods_setup selecting phone.
          #
          # Phone is chosen deliberately over backup codes: it is the method most
          # real users pick, and its confirmation step exercises the OTP
          # delivery and verification path that the sign-in flows also hit.
          #
          # The IdP renders the methods as a checkbox group and permits
          # `selection` as an array (TwoFactorAuthenticationSetupController),
          # so the value is submitted as a one-element array under
          # `selection[]`, matching what a browser sends with one box ticked.
          def select_phone_mfa(response)
            form = Page.find_form(response.body, path: '/authentication_methods_setup')
            raise Error.new("no MFA selection form on #{response.uri}") if form.nil?

            submitted = submit(
              form,
              base: response.uri,
              params: { 'two_factor_options_form[selection][]' => ['phone'] },
            )
            http.follow_redirects(submitted).last
          end

          # POST /phone_setup, which sends the OTP and redirects to the
          # confirmation page where the code is prefilled.
          def submit_phone(response, phone)
            form = Page.find_form(response.body, path: '/phone_setup')
            raise Error.new("no phone setup form on #{response.uri}") if form.nil?

            params = {
              'new_phone_form[phone]' => phone,
              'new_phone_form[international_code]' => 'US',
              'new_phone_form[otp_delivery_preference]' => 'sms',
              'new_phone_form[otp_make_default_number]' => 'false',
            }.merge(Page.mock_recaptcha_fields(response.body, scope: 'new_phone_form'))

            submitted = submit(form, base: response.uri, params: params)
            http.follow_redirects(submitted).last
          end
        end
      end
    end
  end
end

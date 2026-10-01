# frozen_string_literal: true

require_relative 'base'

module LoginGov
  module OidcSinatra
    module Loadtest
      module Flows
        # Full account creation, started from the RP with prompt=create.
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
        # It also requires the SP to be allow-listed for prompt=create via
        # `allowed_create_prompt_providers`, otherwise the authorize request is
        # rejected. See the README for all three settings.
        class Signup < Base
          def self.flow_type
            'signup'
          end

          def run(user:)
            response = step('rp_auth_request') do
              begin_at_rp(
                initiate_registration: '1',
                'requested_scopes[]' => %w[email x509],
              )
            end
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

          # PATCH /authentication_methods_setup with selection=phone.
          #
          # Phone is chosen deliberately over backup codes: it is the method most
          # real users pick, and its confirmation step exercises the OTP
          # delivery and verification path that the sign-in flows also hit.
          def select_phone_mfa(response)
            form = Page.find_form(response.body, path: '/authentication_methods_setup')
            raise Error.new("no MFA selection form on #{response.uri}") if form.nil?

            submitted = submit(
              form,
              base: response.uri,
              params: { 'two_factor_options_form[selection]' => 'phone' },
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

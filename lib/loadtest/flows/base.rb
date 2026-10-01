# frozen_string_literal: true

require 'uri'

require_relative '../errors'
require_relative '../page'

module LoginGov
  module OidcSinatra
    module Loadtest
      module Flows
        # Shared machinery for every flow.
        #
        # Subclasses implement #run, calling the helpers here. The helpers hold
        # the knowledge that is common to all flows and most likely to drift with
        # the IdP: how the OIDC handoff is delivered, which interstitial screens
        # can appear after authentication, and how a run is judged successful.
        class Base
          # Interstitial screens the IdP can interpose between authentication and
          # the SP handoff. Each is cleared by replaying its own form, so the
          # harness measures the same number of round-trips a browser would make.
          #
          # Ordering does not matter (the loop re-examines each page), but the
          # list must stay exhaustive: an unrecognized screen surfaces as a run
          # failure naming the path, rather than a silent hang.
          INTERSTITIAL_PATHS = [
            # "You are already signed in as X — continue?" Shown once per
            # session per SP (authorization_confirmation_controller.rb).
            '/user_authorization_confirmation',
            # The "agree and continue" consent screen. Shown on a user's first
            # authorize against an SP, then skipped for a year
            # (ServiceProviderIdentity::CONSENT_EXPIRATION).
            '/sign_up/completed',
            # "Add a second MFA method" nudges. Skippable.
            '/second_mfa_reminder',
            '/webauthn_platform_recommended',
            '/auth_method_confirmation/skip',
            '/backup_code_reminder',
          ].freeze

          # Hidden params that mark the "yes, add another method" button on the
          # reminder screens. The harness always wants the other button.
          OPT_IN_PARAMS = %w[add_method].freeze

          # A single interstitial should clear in one request; allow a few so a
          # chain of distinct screens resolves, but fail rather than loop.
          MAX_INTERSTITIALS = 6

          attr_reader :config, :http, :recorder

          def initialize(config:, http:, recorder:)
            @config = config
            @http = http
            @recorder = recorder
          end

          # @return [String] the flow type name used in config and output
          def self.flow_type
            raise NotImplementedError.new("#{self} must define .flow_type")
          end

          # @param user [Hash] the identity assigned to this run
          # @return [void] raises Error on failure
          def run(user:)
            raise NotImplementedError.new("#{self.class} must implement #run")
          end

          private

          def flow_settings
            config.flows.fetch(self.class.flow_type)
          end

          # Time a named step and record it. Every HTTP interaction in a flow
          # goes through this so the CSV has a row-level breakdown.
          def step(name)
            started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
            result = yield
            recorder.record_step(name: name, duration_ms: elapsed_ms(started))
            result
          rescue StandardError => e
            recorder.record_step(name: name, duration_ms: elapsed_ms(started), error: e.message)
            raise
          end

          def elapsed_ms(started)
            ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - started) * 1000).round(2)
          end

          # Start the flow where a real user would: at the RP, not the IdP.
          #
          # @param params [Hash] query params for the RP's /auth/request
          # @return [Response] the first non-redirect IdP page
          def begin_at_rp(params)
            query = URI.encode_www_form(params)
            response = http.get("#{config.rp_url}/auth/request?#{query}")
            http.follow_redirects(response).last
          end

          # Clear any interstitial screens, then complete the OIDC handoff back
          # to the RP and verify the RP accepted the authorization code.
          #
          # @param response [Response] the page the IdP landed on post-auth
          # @return [void]
          def finish_at_rp(response)
            response = step('interstitials') { clear_interstitials(response) }
            response = step('handoff') { follow_handoff(response) }
            step('rp_result') { assert_rp_success(response) }
          end

          # Replay interstitial forms until the response is either the handoff or
          # something unrecognized.
          def clear_interstitials(response)
            MAX_INTERSTITIALS.times do
              path = INTERSTITIAL_PATHS.find do |candidate|
                Page.form_action?(response.body, candidate)
              end
              return response if path.nil?

              response = submit_interstitial(response, path: path)
            end

            raise Error.new(
              "interstitial screens did not clear after #{MAX_INTERSTITIALS} attempts",
            )
          end

          def submit_interstitial(response, path:)
            form = Page.find_form(response.body, path: path, without_params: OPT_IN_PARAMS) ||
                   Page.find_form(response.body, path: path)
            raise Error.new("could not replay interstitial form for #{path}") if form.nil?

            submitted = submit(form, base: response.uri)
            http.follow_redirects(submitted).last
          end

          # Submit a scraped form, honoring Rails' `_method` override.
          def submit(form, base:, params: {})
            url = http.absolutize(form.action, base: base)
            body = form.params.merge(stringify_keys(params))

            case form.method
            when 'patch' then http.patch(url, params: body)
            when 'post', 'put', 'delete' then http.post(url, params: body)
            else http.get(url)
            end
          end

          # Complete the IdP -> RP handoff.
          #
          # The IdP delivers this two different ways depending on
          # `openid_connect_redirect`: a plain 302 (`server_side`, used in
          # production) or an HTML page with a `data-click-immediate` anchor
          # (`client_side_js`, the non-production default). Supporting both means
          # the harness runs against an unmodified dev IdP.
          def follow_handoff(response)
            href = Page.click_immediate_href(response.body)
            if href
              response = http.get(http.absolutize(href, base: response.uri))
              response = http.follow_redirects(response).last
            end

            response
          end

          # The RP is the source of truth for success: it only renders userinfo
          # after exchanging the code and validating state and nonce.
          def assert_rp_success(response)
            body = response.body

            if Page.rp_userinfo?(body)
              return response
            end

            detail = Page.error_text(body) || "unexpected final page: #{response.uri}"
            raise Error.new("RP did not report a successful sign-in (#{detail})")
          end

          # Sign in an existing user: email + password, then the prefilled OTP.
          # Shared by auth_only and idv, which differ only in the acr_values the
          # RP requests.
          def sign_in(response, email:, password:)
            response = step('sign_in_submit') { submit_sign_in(response, email, password) }
            step('otp_submit') { submit_otp(response) }
          end

          def submit_sign_in(response, email, password)
            unless Page.field?(response.body, 'user[email]')
              detail = Page.error_text(response.body) || response.uri
              raise Error.new("expected a sign-in form, got #{detail}")
            end

            params = {
              'user[email]' => email,
              'user[password]' => password,
              'authenticity_token' => Page.csrf_token(response.body),
            }.merge(Page.mock_recaptcha_fields(response.body, scope: 'user'))

            # The sign-in form posts to the IdP root (routes.rb: `post '/' =>
            # 'users/sessions#create'`), so there is nothing to scrape from the
            # action attribute.
            submitted = http.post("#{config.idp_url}/", params: params)
            http.follow_redirects(submitted).last
          end

          # Read the one-time code off the page and submit it.
          #
          # This depends on `FeatureManagement.prefill_otp_codes?` being true on
          # the IdP, which it is in development with `telephony_adapter: test`.
          # The failure message names that requirement because a blank field is
          # otherwise an opaque dead end.
          def submit_otp(response)
            otp = Page.prefilled_otp(response.body)
            if otp.nil?
              message = "no prefilled one-time code on #{response.uri} — the IdP must run in " \
                        "development with telephony_adapter: test so " \
                        "FeatureManagement.prefill_otp_codes? is true"
              raise Error.new(message)
            end

            # The OTP view uses `simple_form_for('')`, so the form has no useful
            # action attribute; locate it by the field it owns instead.
            form = Page.form_for_field(response.body, 'code')
            raise Error.new("no OTP form on #{response.uri}") if form.nil?

            # An empty action posts back to the current URL.
            base = response.uri
            form.action = base.to_s if form.action.empty?

            submitted = submit(
              form,
              base: base,
              params: { 'code' => otp, 'remember_device' => '0' },
            )
            http.follow_redirects(submitted).last
          end

          def stringify_keys(hash)
            hash.to_h { |key, value| [key.to_s, value.to_s] }
          end
        end
      end
    end
  end
end

# frozen_string_literal: true

require 'nokogiri'

require_relative 'errors'

module LoginGov
  module OidcSinatra
    module Loadtest
      # Pure functions for pulling what the harness needs out of IdP HTML.
      #
      # These are the most brittle part of the harness: they encode assumptions
      # about IdP markup. They are kept side-effect free and separated from the
      # HTTP layer precisely so they can be unit tested against fixture HTML
      # without a running IdP (see spec/loadtest/page_spec.rb).
      module Page
        # A replayable form scraped from a page. `params` holds the hidden
        # inputs (CSRF token, Rails `_method`, button_to params) so a caller can
        # merge its own visible-field values on top.
        Form = Struct.new(:action, :method, :params, keyword_init: true)

        class << self
          def parse(html)
            Nokogiri::HTML(html.to_s)
          end

          # Rails is configured with `per_form_csrf_tokens = true`
          # (identity-idp config/application.rb), so each form carries its own
          # token and tokens cannot be reused across endpoints. Callers must
          # therefore GET the page that owns a form before POSTing to it.
          #
          # @param action_includes [String, nil] when several forms are present,
          #   pick the one whose action contains this substring.
          # @return [String] the authenticity_token value
          def csrf_token(html, action_includes: nil)
            doc = parse(html)
            inputs = doc.css('input[name="authenticity_token"]')

            if action_includes
              scoped = inputs.select do |input|
                input.ancestors('form').first&.[]('action').to_s.include?(action_includes)
              end
              inputs = scoped if scoped.any?
            end

            token = inputs.first&.[]('value')
            raise Error.new('no authenticity_token found on page') if token.to_s.empty?

            token
          end

          # The one-time code, read straight off the page.
          #
          # In development with `telephony_adapter: test`, the IdP renders the
          # real OTP into the code field via
          # `FeatureManagement.prefill_otp_codes?` (see identity-idp
          # app/controllers/two_factor_authentication/otp_verification_controller.rb
          # `direct_otp_code`). That is what makes a scripted sign-in possible
          # with no SMS and no out-of-band channel. If this returns nil, the
          # prefill feature is off and the harness cannot proceed.
          #
          # @return [String, nil]
          def prefilled_otp(html)
            doc = parse(html)
            value = doc.at_css('input#code')&.[]('value')
            value = doc.at_css('input[name="code"]')&.[]('value') if value.to_s.empty?
            return nil if value.to_s.empty?

            value.strip
          end

          # The load-testing-only "CONFIRM NOW" link, which stands in for
          # clicking a link in a confirmation email. Rendered only when
          # `enable_load_testing_mode` is true (identity-idp
          # app/views/sign_up/emails/show.html.erb).
          #
          # @return [String, nil] href, or nil when the flag is off
          def confirm_now_href(html)
            doc = parse(html)
            href = doc.at_css('a#confirm-now')&.[]('href')
            href = doc.css('a').find { |a| a.text.strip == 'CONFIRM NOW' }&.[]('href') if href.nil?
            href
          end

          # The OIDC handoff target when the IdP is configured with
          # `openid_connect_redirect: client_side_js` (the non-production
          # default). Instead of a 302, the IdP renders a page whose anchor
          # carries `data-click-immediate` and the real redirect URI.
          #
          # @return [String, nil]
          def click_immediate_href(html)
            parse(html).at_css('a[data-click-immediate]')&.[]('href')
          end

          # Every form on the page, reduced to what is needed to replay it.
          #
          # Interstitial screens are recognized by form action rather than by
          # visible copy, because copy is translated and changes often while
          # routes are stable. Hidden inputs are captured verbatim so Rails'
          # `_method` override and `button_to` params survive the replay.
          #
          # @return [Array<Form>]
          def forms(html)
            parse(html).css('form').map { |element| form_from(element) }
          end

          # Find the single form that submits to `path`.
          #
          # Several screens render two buttons to the same route (for example
          # "add another method" vs "skip"), distinguished only by a hidden
          # param. `without_params` lets a caller say "the plain one".
          #
          # @param path [String] substring of the form action
          # @param method [String, nil] restrict to this HTTP method
          # @param without_params [Array<String>] reject forms carrying these
          # @return [Form, nil]
          def find_form(html, path:, method: nil, without_params: [])
            forms(html).find do |form|
              next false unless form.action.include?(path)
              next false if method && form.method != method
              next false if without_params.any? { |name| form.params.key?(name) }

              true
            end
          end

          # Find the form that owns a given input.
          #
          # More robust than matching on the action attribute when a view uses
          # `simple_form_for('')`, which emits a form with no (or a
          # context-dependent) action. The one-time-code page does exactly that,
          # so it is located by its `code` field instead.
          #
          # @return [Form, nil]
          def form_for_field(html, name)
            doc = parse(html)
            input = doc.at_css(%(input[name="#{name}"]))
            element = input&.ancestors('form')&.first
            return nil if element.nil?

            form_from(element)
          end

          # Whether a page renders an input with the given name. Used to assert
          # the harness is on the page it thinks it is before POSTing to it.
          def field?(html, name)
            !parse(html).at_css(%(input[name="#{name}"], select[name="#{name}"])).nil?
          end

          # Whether a page contains a form that submits to the given path. Used
          # to recognize interstitial screens without relying on translated copy.
          def form_action?(html, path)
            forms(html).any? { |form| form.action.include?(path) }
          end

          # The reCAPTCHA fields the IdP's mock validator expects.
          #
          # When `recaptcha_mock_validator` is on, forms render a hidden
          # `recaptcha_token` of 'mock_token' plus a visible mock score field
          # (identity-idp app/components/captcha_submit_button_component.html.erb).
          # The harness mirrors that rather than skipping the fields, so it works
          # whether or not the mock validator is enabled.
          #
          # @param scope [String] the form object name, e.g. 'user'
          # @return [Hash] params to merge into a POST body
          def mock_recaptcha_fields(html, scope:)
            doc = parse(html)
            return {} if doc.at_css(%(input[name="#{scope}[recaptcha_token]"])).nil?

            {
              "#{scope}[recaptcha_token]" => 'mock_token',
              "#{scope}[recaptcha_mock_score]" => '1.0',
            }
          end

          # Best-effort extraction of IdP error copy, for failure diagnostics.
          # @return [String, nil]
          def error_text(html)
            doc = parse(html)
            node = doc.at_css('.usa-alert--error, .usa-error-message')
            node&.text&.strip&.gsub(/\s+/, ' ')
          end

          # The RP's own success signal: index.erb renders "Received user info:"
          # only when a userinfo response is in the session.
          def rp_userinfo?(html)
            html.to_s.include?('Received user info:')
          end

          private

          # Reduce a <form> element to a replayable Form.
          #
          # Rails emits `_method` as a hidden input for verbs browsers cannot
          # send, so the effective method comes from that when present.
          def form_from(element)
            params = element.css('input[type="hidden"]').
              to_h { |input| [input['name'].to_s, input['value'].to_s] }.
              reject { |name, _value| name.empty? }

            Form.new(
              action: element['action'].to_s,
              method: (params['_method'] || element['method'] || 'get').to_s.downcase,
              params: params,
            )
          end
        end
      end
    end
  end
end

# frozen_string_literal: true

require_relative 'base'

module LoginGov
  module OidcSinatra
    module Loadtest
      module Flows
        # Identity-verified sign-in with facial match required (IAL2 biometric).
        #
        # Requests `ial=facial-match-required`, which the IdP maps to
        # `urn:acr.login.gov:verified-facial-match-required`. The IdP decrypts
        # the user's proofed PII and returns all verified attributes.
        #
        # Requires users seeded by `rake dev:random_users VERIFIED=1`, which
        # writes an active, verified Profile directly rather than running doc
        # auth. The harness therefore does not drive the proofing wizard — it
        # measures the steady-state cost of an already-proofed sign-in with
        # facial match.
        #
        # The seeded password must not be changed: `rake dev:random_users`
        # encrypts the profile PII with it, and the IdP would otherwise bounce
        # the request to re-capture the password.
        class IdvFacialMatch < Base
          def self.flow_type
            'idv_facial_match'
          end

          def run(user:)
            response = step('rp_auth_request') do
              begin_at_rp(
                ial: 'facial-match-required',
                'requested_scopes[]' => %w[
                  all_emails locale ial aal profile given_name family_name
                  address phone birthdate social_security_number profile:verified_at
                ],
              )
            end
            response = sign_in(response, email: user.fetch(:email), password: user.fetch(:password))
            finish_at_rp(response)
          end
        end
      end
    end
  end
end

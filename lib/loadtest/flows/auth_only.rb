# frozen_string_literal: true

require_relative 'base'

module LoginGov
  module OidcSinatra
    module Loadtest
      module Flows
        # Authentication-only sign-in (IAL1).
        #
        # Exercises the most common path: an existing, confirmed user with a
        # confirmed phone signs in with password + SMS OTP and is handed back to
        # the RP. No identity proofing is involved.
        #
        # Requires users seeded by `rake dev:random_users` (without VERIFIED).
        class AuthOnly < Base
          def self.flow_type
            'auth_only'
          end

          def run(user:)
            response = step('rp_auth_request') do
              begin_at_rp(ial: '1', 'requested_scopes[]' => %w[email x509])
            end
            response = sign_in(response, email: user.fetch(:email), password: user.fetch(:password))
            finish_at_rp(response)
          end
        end
      end
    end
  end
end

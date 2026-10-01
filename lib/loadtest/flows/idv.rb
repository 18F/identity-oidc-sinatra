# frozen_string_literal: true

require_relative 'base'

module LoginGov
  module OidcSinatra
    module Loadtest
      module Flows
        # Identity-verified sign-in (IAL2).
        #
        # Same authentication steps as auth_only, but the RP requests an
        # identity-verified ACR, so the IdP additionally decrypts the user's
        # proofed PII and returns verified attributes. That decryption is the
        # point of this flow: it is real per-request work that auth_only does not
        # measure.
        #
        # Requires users seeded by `rake dev:random_users VERIFIED=1`, which
        # writes an active, verified Profile directly rather than running doc
        # auth. The harness therefore does not drive the proofing wizard — it
        # measures the steady-state cost of an already-proofed sign-in.
        #
        # The seeded password must not be changed: `rake dev:random_users`
        # encrypts the profile PII with it, and the IdP would otherwise bounce
        # the request to re-capture the password.
        class Idv < Base
          def self.flow_type
            'idv'
          end

          def run(user:)
            response = step('rp_auth_request') { begin_at_rp(ial: '2') }
            response = sign_in(response, email: user.fetch(:email), password: user.fetch(:password))
            finish_at_rp(response)
          end
        end
      end
    end
  end
end

module LoginGov
  module OidcSinatra
    # One source of identity claims for both ways a user reaches this agency.
    #
    # Direct sign-in: the agency's web app calls the userinfo endpoint with the
    # access token it obtained itself and receives the user's claims (OpenID
    # Connect Core 1.0 §5.3).
    #
    # Delegated access: a service provider presents a delegated token to the
    # agency's API. The API does NOT call userinfo with that token. Userinfo is
    # authenticated only by the bearer token itself, so Login.gov keeps
    # delegated tokens out of it; instead the introspection response (RFC 7662
    # §2.2), which this resource server authenticates to with its own key,
    # carries the same claims under the same names and in the same formats as
    # userinfo would (`sub`, `iss`, `email`, `email_verified`, `all_emails`,
    # `given_name`, `family_name`, `birthdate`, `social_security_number`,
    # `address`, `phone`, `phone_verified`, `verified_at`, `ial`, `aal`,
    # `x509_*`), limited to the agency's configured attribute bundle, next to
    # the token members (`active`, `aud`, `scope`, `act`, `client_id`, `acr`,
    # `iat`, `exp`, `delegation_id`, `token_type`).
    #
    # Because the two responses agree on claim names, the same helpers below
    # (and the identity_claims.erb partial) render either one, and the agency
    # code that consumes claims cannot tell which path the user came in by.
    #
    # Mixed into the Sinatra app with `helpers IdentityClaims`; relies on
    # `maybe_redact_ssn`.
    module IdentityClaims
      # Members of an introspection response that describe the token rather
      # than the user. Everything else in the response is an identity claim.
      # `sub` is both: the user's pairwise identifier for this agency and the
      # token's subject, so it is kept on both sides.
      # `cnf` (RFC 7800, RFC 9449 §6) names the key a DPoP-bound token is tied
      # to; it describes the token, not the user, so it is echoed with the other
      # token members and never shown as an identity claim.
      TOKEN_MEMBERS = %w[
        active aud scope sub act client_id acr iat exp nbf jti token_type
        delegation_id attributes cnf
      ].freeze

      # Value of `attributes` when the user's Login.gov session has ended:
      # Login.gov then releases identifiers and email only, no other attribute.
      IDENTIFIERS_ONLY = 'identifiers_only'

      IDENTIFIERS_ONLY_NOTICE =
        'Identifiers only: the user\'s Login.gov session has ended, so Login.gov released ' \
        'identifiers and email with this token and no other attribute. To receive identity ' \
        'attributes again, the service provider must send the user back through Login.gov.'

      # The user's identity claims from either a userinfo response or an
      # introspection response, with the SSN redacted the same way the direct
      # sign-in page redacts it.
      #
      # @param [Hash, nil] source userinfo body or introspection body
      # @return [Hash{String => Object}] claim name => value, in source order
      def identity_claims(source)
        return {} unless source.is_a?(Hash)

        source.each_with_object({}) do |(name, value), claims|
          name = name.to_s
          next if TOKEN_MEMBERS.include?(name) && name != 'sub'

          value = maybe_redact_ssn(value) if name == 'social_security_number'
          claims[name] = value
        end
      end

      # The token-only part of an introspection response (identifiers, no
      # attributes) for echoing to the caller and for the decision log.
      # @param [Hash, nil] introspection
      # @return [Hash{String => Object}]
      def introspection_metadata(introspection)
        return {} unless introspection.is_a?(Hash)

        introspection.each_with_object({}) do |(name, value), members|
          members[name.to_s] = value if TOKEN_MEMBERS.include?(name.to_s)
        end
      end

      # True when Login.gov marked the response as identifiers only because the
      # user's Login.gov session has ended.
      # @param [Hash, nil] source
      def identifiers_only?(source)
        source.is_a?(Hash) && (source['attributes'] || source[:attributes]) == IDENTIFIERS_ONLY
      end
    end
  end
end

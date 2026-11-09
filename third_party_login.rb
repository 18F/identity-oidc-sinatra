# frozen_string_literal: true

require 'uri'

module LoginGov
  module OidcSinatra
    # Relying-party side of OpenID Connect Third-Party-Initiated Login (OIDC Core 1.0 §4)
    module ThirdPartyLogin
      LOGIN_HINT_MAX_LENGTH = 128
      TARGET_LINK_URI_MAX_LENGTH = 2048

      # Raised for a request §4 says must be refused. The message is safe to show.
      class InvalidInitiation < StandardError; end

      # @return [Hash] `login_hint` and `target_link_uri`, both validated
      # @raise [InvalidInitiation]
      def validate_third_party_initiation!(params)
        verify_third_party_issuer!(params['iss'])
        {
          login_hint: normalize_login_hint(params['login_hint']),
          target_link_uri: verify_target_link_uri!(params['target_link_uri']),
        }
      end

      def verify_third_party_issuer!(iss)
        raise InvalidInitiation.new('iss is required') if iss.to_s.strip.empty?
        return iss if same_issuer?(iss, config.idp_url)

        raise InvalidInitiation.new('iss is not the OpenID Provider this agency trusts')
      end

      # Issuer identifiers are URLs (OpenID Connect Discovery §3); a trailing
      # slash is the only variation tolerated, so `https://idp.example` and
      # `https://idp.example/` compare equal and nothing else does.
      def same_issuer?(candidate, trusted)
        candidate.to_s.strip.chomp('/') == trusted.to_s.strip.chomp('/')
      end

      # @return [String] the URI exactly as supplied, once its origin is allowed
      def verify_target_link_uri!(target_link_uri)
        if target_link_uri.to_s.strip.empty?
          raise InvalidInitiation.new('target_link_uri is required')
        end
        if target_link_uri.length > TARGET_LINK_URI_MAX_LENGTH
          raise InvalidInitiation.new('target_link_uri is too long')
        end

        uri = parse_http_uri(target_link_uri)
        raise InvalidInitiation.new('target_link_uri is not an absolute http(s) URL') if uri.nil?

        allowed = config.third_party_target_link_allowlist.any? do |origin|
          origin_of(uri) == origin
        end
        return target_link_uri if allowed

        raise InvalidInitiation.new('target_link_uri is not an allowed return location')
      end

      # The hint is opaque: this app stores it and gives it back, nothing more.
      # It is still bounded in size (see LOGIN_HINT_MAX_LENGTH)
      def normalize_login_hint(login_hint)
        hint = login_hint.to_s.strip
        return nil if hint.empty?
        raise InvalidInitiation.new('login_hint is too long') if hint.length > LOGIN_HINT_MAX_LENGTH

        hint
      end

      # Keeps the hand-off in the session for exactly one sign-in.
      def remember_third_party_handoff(login_hint:, target_link_uri:)
        session[:third_party_login_hint] = login_hint
        session[:third_party_target_link_uri] = target_link_uri
      end

      def third_party_handoff_pending?
        !session[:third_party_target_link_uri].to_s.empty?
      end

      # Removes and returns the pending hand-off, so it is honored at most once:
      # a later, unrelated sign-in must not bounce the user back to the third
      # party again.
      def take_third_party_handoff
        target = session.delete(:third_party_target_link_uri)
        hint = session.delete(:third_party_login_hint)
        return nil if target.to_s.empty?

        { login_hint: hint, target_link_uri: target }
      end

      # Where to send the user after the sign-in the hand-off started has ended.
      # @param status [String] `signed_in` or `failed`
      def third_party_return_url(handoff, status:)
        uri = URI.parse(handoff[:target_link_uri])
        existing = URI.decode_www_form(uri.query.to_s)
        additions = [['iss', client_id], ['status', status]]
        additions.unshift(['login_hint', handoff[:login_hint]]) if handoff[:login_hint]
        uri.query = URI.encode_www_form(existing + additions)
        uri.to_s
      end

      private

      def parse_http_uri(value)
        uri = URI.parse(value.to_s)
        uri.is_a?(URI::HTTP) && !uri.host.to_s.empty? ? uri : nil
      rescue URI::InvalidURIError
        nil
      end

      # scheme://host[:port] with the default port dropped, lower-cased, so the
      # comparison is against the origin and only the origin.
      def origin_of(uri)
        port = uri.port == uri.default_port ? '' : ":#{uri.port}"
        "#{uri.scheme.downcase}://#{uri.host.downcase}#{port}"
      end
    end
  end
end

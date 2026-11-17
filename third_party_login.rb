# frozen_string_literal: true

require 'securerandom'
require 'uri'

module LoginGov
  module OidcSinatra
    # Relying-party side of OpenID Connect Third-Party-Initiated Login (OIDC Core 1.0 §4)
    module ThirdPartyLogin
      LOGIN_HINT_MAX_LENGTH = 128
      TARGET_LINK_URI_MAX_LENGTH = 2048

      class InvalidInitiation < StandardError; end

      # Actor side: this app sends the browser to another app's login-initiation endpoint.
      def start_actor_third_party_login(initiate_login_uri, immediately_begin_delegation: true)
        login_hint = SecureRandom.uuid

        session[:handoff_login_hint] = login_hint
        session[:handoff_started_at] = Time.now.to_i
        session[:handoff_immediately_begin_delegation] = immediately_begin_delegation

        uri = URI.parse(initiate_login_uri)
        uri.query = actor_third_party_initiation_query(uri.query, login_hint)

        settings.logger.info("no identity at the agency; third-party-initiated login at #{uri}")

        redirect to(uri.to_s)
      end

      def actor_third_party_return_path(handoff)
        return '/delegated_exchange' unless handoff[:immediately_begin_delegation]

        query = handoff[:auth_request_query]
        return '/delegated_exchange/request' if query.to_s.empty?

        "/delegated_exchange/request?#{query}"
      end

      def actor_third_party_initiation_query(existing_query, login_hint)
        URI.encode_www_form(
          URI.decode_www_form(existing_query.to_s) + [
            ['iss', config.idp_url],
            ['login_hint', login_hint],
            ['target_link_uri', File.join(config.redirect_uri, 'third_party/return')],
          ],
        )
      end

      # Removes and returns the pending hand-off so it is honored at most once.
      def handle_third_party_handoff
        login_hint = session.delete(:handoff_login_hint)
        started_at = session.delete(:handoff_started_at)
        auth_request_query = session.delete(:auth_request_query)
        immediately_begin_delegation = session.delete( :handoff_immediately_begin_delegation)

        return nil if login_hint.nil?

        {
          login_hint:,
          started_at: started_at.to_i,
          auth_request_query:,
          immediately_begin_delegation:,
        }
      end

      # Target side: this app receives a third-party initiated login request from another app.
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

      # `https://idp.example` and  `https://idp.example/` compare equal
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

      def normalize_login_hint(login_hint)
        hint = login_hint.to_s.strip

        return nil if hint.empty?
        raise InvalidInitiation.new('login_hint is too long') if hint.length > LOGIN_HINT_MAX_LENGTH

        hint
      end

      # Keeps the target-side hand-off in the session for exactly one sign-in.
      def remember_target_third_party_handoff(login_hint:, target_link_uri:)
        session[:third_party_login_hint] = login_hint
        session[:third_party_target_link_uri] = target_link_uri
      end

      # Removes and returns the pending target-side hand-off, so it is honored at most once
      def take_target_third_party_handoff
        target = session.delete(:third_party_target_link_uri)
        hint = session.delete(:third_party_login_hint)
        return nil if target.to_s.empty?

        { login_hint: hint, target_link_uri: target }
      end

      # Where to send the user after the target-side sign-in the hand-off started has ended.
      # @param status [String] `signed_in` or `failed`
      def target_third_party_return_url(handoff, status:)
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

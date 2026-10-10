# frozen_string_literal: true

require 'uri'

module LoginGov
  module OidcSinatra
    # Relying-party side of OpenID Connect Third-Party-Initiated Login
    # (OpenID Connect Core 1.0 §4,
    # https://openid.net/specs/openid-connect-core-1_0.html#ThirdPartyInitiatedLogin).
    #
    # A third party that is not this agency (MyBenefits Assistant in the reference
    # setup) sends the user's browser to this app's login initiation endpoint
    # with three query parameters:
    #
    #   iss              which OpenID Provider to sign the user in with
    #   login_hint       an opaque string the third party will recognize later
    #   target_link_uri  where to send the user once sign-in has completed
    #
    # This app then runs its ordinary Login.gov authorization code flow. The
    # user already has a Login.gov session from signing in to the third party,
    # so Login.gov signs them in without asking for credentials again; that
    # single sign-on is the whole point of the pattern. Nothing is delegated and
    # no token is exchanged: this is the agency's own sign-in, with its own
    # tokens, consent screen, fraud signals and billing. The agency learns who
    # the user is from Login.gov alone; the hint is never treated as identity.
    #
    # §4 names two checks the relying party MUST perform before acting on the
    # request, and both are implemented here:
    #
    #   * `iss` MUST be an issuer this app trusts. Otherwise a link crafted by
    #     an attacker could send the user to an attacker-controlled OpenID
    #     Provider and harvest whatever they type there.
    #   * `target_link_uri` MUST be verified, or the endpoint becomes an open
    #     redirector: anyone could craft a link that signs the user in here and
    #     then bounces them to an arbitrary site that looks like a continuation
    #     of the flow.
    #
    # Mixed into the Sinatra app with `helpers ThirdPartyLogin`; relies on
    # `config`, `session` and `params`.
    module ThirdPartyLogin
      # §4 places no limit on `login_hint`, but it is remembered in the session
      # cookie and echoed back in a URL, so an upper bound keeps both small and
      # keeps an attacker from stuffing arbitrary data through the flow.
      LOGIN_HINT_MAX_LENGTH = 128

      # Raised for a request §4 says must be refused. The message is safe to show.
      class InvalidInitiation < StandardError; end

      # Runs the §4 relying-party checks on the initiation request and returns
      # the validated values. Order matters: the issuer is checked first because
      # a request for an untrusted OpenID Provider must not be acted on at all,
      # not even to the extent of inspecting its other parameters.
      #
      # @return [Hash] `login_hint` and `target_link_uri`, both validated
      # @raise [InvalidInitiation]
      def validate_third_party_initiation!(params)
        verify_third_party_issuer!(params['iss'])
        {
          login_hint: normalize_login_hint(params['login_hint']),
          target_link_uri: verify_target_link_uri!(params['target_link_uri']),
        }
      end

      # §4: "The RP MUST verify that the `iss` is one it trusts." This app is
      # configured for exactly one OpenID Provider, Login.gov, so the only
      # acceptable value is that issuer. A different issuer would mean sending
      # the user to sign in somewhere else, which is the attack this check stops.
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

      # §4: "RPs MUST verify the value of the target_link_uri to prevent being
      # used as an open redirector to external sites." Only the URL's origin is
      # compared, against an allow-list of exact origins from configuration, so
      # the third party may vary the path and query (the page the user was on)
      # but never the site the user is returned to. No wildcard matching.
      #
      # @return [String] the URI exactly as supplied, once its origin is allowed
      def verify_target_link_uri!(target_link_uri)
        if target_link_uri.to_s.strip.empty?
          raise InvalidInitiation.new('target_link_uri is required')
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
      # It is still bounded in size (see LOGIN_HINT_MAX_LENGTH) and reduced to a
      # plain string so it cannot carry structure into the session.
      def normalize_login_hint(login_hint)
        hint = login_hint.to_s.strip
        return nil if hint.empty?
        raise InvalidInitiation.new('login_hint is too long') if hint.length > LOGIN_HINT_MAX_LENGTH

        hint
      end

      # Keeps the hand-off in the session for exactly one sign-in. Flat keys
      # rather than a nested hash so the values survive any session coder.
      def remember_third_party_handoff(login_hint:, target_link_uri:)
        session[:third_party_login_hint] = login_hint
        session[:third_party_target_link_uri] = target_link_uri
      end

      # True while a hand-off is waiting for the sign-in it started to finish.
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
      # §4 only says to return the user to `target_link_uri`; the three query
      # parameters are this reference setup's convention so the third party can
      # match the return to the request it made (`login_hint`), see which agency
      # is returning the user (`iss`, this app's client identifier) and whether
      # the sign-in succeeded (`status`). The hint is echoed exactly as received.
      #
      # @param status [String] `signed_in` or `failed`
      def third_party_return_url(handoff, status:)
        uri = URI.parse(handoff[:target_link_uri])
        existing = URI.decode_www_form(uri.query.to_s)
        additions = [['iss', config.client_id], ['status', status]]
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

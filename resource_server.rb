require 'base64'
require 'faraday'
require 'json'
require 'jwt'
require 'securerandom'
require_relative './introspection_cache'
require_relative './decision_log'

module LoginGov
  module OidcSinatra
    # Resource server helpers: everything an agency API needs to accept a
    # Login.gov delegated access token. One method per protocol step, in the
    # order a request flows through them, so the code can be copied as-is.
    #
    #   authorize!(required_scope)
    #     -> introspection_endpoint         (OpenID Connect Discovery / RFC 8414 §2)
    #     -> bearer_token                   (RFC 6750 §2.1)
    #     -> reject_id_token!               (§6.3 item 6)
    #     -> cached_introspection           (RFC 7662; INT-8 cache window)
    #     -> introspect                     (RFC 7662 §2.1)
    #        -> rs_client_assertion         (RFC 7523 §3, RFC 8725)
    #     -> check active / aud / scope     (RFC 7662 §2.2; §6.3 items 4-5)
    #     -> log_decision                   (§8.5 join key: delegation_id)
    #
    # Mixed into the Sinatra app with `helpers ResourceServer`; relies on
    # `config`, `openid_configuration`, `request`, `halt` and `settings.logger`.
    module ResourceServer
      JWT_CLIENT_ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
      # RFC 7523 §3 (4) and INT-6: `exp` at most 5 minutes after `iat`.
      CLIENT_ASSERTION_LIFETIME_SECONDS = 300
      # Fail closed (§6.3 item 3): a slow IdP must not turn into an open door.
      INTROSPECTION_TIMEOUT_SECONDS = 5

      # Raised when Login.gov cannot be reached or answers unexpectedly. Callers
      # respond 503 and serve nothing.
      class IntrospectionUnavailable < StandardError; end

      # Gate a route on a delegated token carrying `required_scope`.
      # Sets @introspection for the route body. Halts with 401/403/503 otherwise.
      #
      # @param [String] required_scope full wire value, e.g. "token_exchange:records_read"
      def authorize!(required_scope)
        content_type :json
        route = "#{request.request_method} #{request.path_info}"

        begin
          endpoint = introspection_endpoint
        rescue IntrospectionUnavailable => e
          settings.logger.warn("discovery unavailable: #{e.message}")
          log_decision(nil, route:, decision: 'unavailable', reason: 'discovery_unavailable',
                            required_scope:)
          halt 503, json_error_response(
            'temporarily_unavailable',
            'Could not read the Login.gov discovery document; the request was not served.',
          )
        end
        unless endpoint
          log_decision(nil, route:, decision: 'unavailable', reason: 'introspection_not_advertised',
                            required_scope:)
          halt 503, json_error_response(
            'temporarily_unavailable',
            'Login.gov discovery does not advertise introspection_endpoint ' \
            '(token_exchange_enabled is off at the IdP); refusing all delegated requests.',
          )
        end

        # RFC 6750 §2.1 — the token arrives only in the Authorization header.
        token = bearer_token(request)
        unless token
          log_decision(nil, route:, decision: 'denied', reason: 'missing_token', required_scope:)
          halt 401, www_authenticate('Bearer'), ''
        end

        # §6.3 item 6 — an id_token is proof of sign-in to the service provider,
        # never proof of delegation to this API.
        if id_token?(token)
          log_decision(nil, route:, decision: 'denied', reason: 'id_token_presented',
                            required_scope:)
          halt 401, www_authenticate('Bearer', error: 'invalid_token'),
               json_error_response('invalid_token', 'An ID token is not a delegated access token.')
        end

        # RFC 7662 — ask Login.gov; reuse an `active: true` answer for at most
        # the published window (INT-8).
        begin
          @introspection = cached_introspection(token) || introspect(token, endpoint)
        rescue IntrospectionUnavailable => e
          settings.logger.warn("introspection unavailable: #{e.message}")
          log_decision(nil, route:, decision: 'unavailable', reason: 'introspection_failed',
                            required_scope:)
          halt 503, json_error_response(
            'temporarily_unavailable',
            'Could not confirm the token with Login.gov; the request was not served.',
          )
        end

        # RFC 7662 §2.2 — `active: false` is the only signal for expired,
        # revoked, unknown, or someone-else's tokens (INT-3). Revocation is
        # observed here, not by any callback (REF-6).
        unless @introspection['active'] == true
          log_decision(@introspection, route:, decision: 'denied', reason: 'invalid_token',
                                       required_scope:)
          halt 401, www_authenticate('Bearer', error: 'invalid_token'),
               json_error_response('invalid_token', 'The token is not active.')
        end

        # RFC 7662 §2.2 `aud` / RFC 8707 — the token must have been issued for
        # this API. Login.gov already enforces caller == aud (INT-2); checking
        # again costs nothing and protects against misconfiguration.
        unless @introspection['aud'] == config.resource_identifier
          log_decision(@introspection, route:, decision: 'denied', reason: 'wrong_audience',
                                       required_scope:)
          halt 401, www_authenticate('Bearer', error: 'invalid_token'),
               json_error_response('invalid_token', 'The token was issued for a different API.')
        end

        # RFC 8693 §4.1 — `act` marks delegated access. INT-4 makes it mandatory
        # on every delegated token; treat its absence as a token this API does
        # not understand. Agency policy for delegated callers is expressed
        # through the scope check below (§6.3 item 5): a service provider may
        # write only if the user approved the write scope.
        actor = @introspection.dig('act', 'sub')
        unless actor
          log_decision(@introspection, route:, decision: 'denied', reason: 'missing_act',
                                       required_scope:)
          halt 401, www_authenticate('Bearer', error: 'invalid_token'),
               json_error_response('invalid_token', 'The token does not carry an act claim.')
        end
        settings.logger.info(
          "delegated access: actor=#{actor} sub=#{@introspection['sub']} " \
          "delegation_id=#{@introspection['delegation_id']} route=#{route}",
        )

        # §6.3 item 4 — Login.gov decided which API; the agency decides which
        # endpoint. Scope values are compared as full strings (RFC 6749 §3.3).
        unless scope_granted?(@introspection['scope'], required_scope)
          log_decision(@introspection, route:, decision: 'denied', reason: 'insufficient_scope',
                                       required_scope:)
          halt 403, www_authenticate('Bearer', error: 'insufficient_scope', scope: required_scope),
               json_error_response('insufficient_scope',
                                   "This endpoint requires #{required_scope}.")
        end

        log_decision(@introspection, route:, decision: 'allowed', required_scope:)
        @introspection
      end

      # OpenID Connect Discovery 1.0 / RFC 8414 §2 — `introspection_endpoint` is
      # advertised only while Login.gov has delegated access enabled (DISC-5).
      # @return [String, nil] nil when the document lacks the key
      # @raise [IntrospectionUnavailable] when the document cannot be read
      def introspection_endpoint
        openid_configuration['introspection_endpoint']
      rescue AppError, Faraday::Error, Errno::ECONNREFUSED => e
        raise IntrospectionUnavailable.new(e.message)
      end

      # RFC 6750 §2.1 — Authorization: Bearer b64token. Returns nil for any
      # other scheme or a malformed header; the query and body forms (§2.2,
      # §2.3) are deliberately not accepted.
      # @return [String, nil]
      def bearer_token(request)
        header = request.env['HTTP_AUTHORIZATION'].to_s
        match = /\ABearer[ ]+(?<token>[A-Za-z0-9\-._~+\/]+=*)\z/.match(header.strip)
        match && match[:token]
      end

      # A Login.gov delegated access token is opaque; an id_token is a signed JWT
      # (RFC 7519). Three base64url segments whose middle decodes to a JSON
      # object with `iss` and `aud` is an ID token (or another self-contained
      # token) and is refused before any network call.
      def id_token?(token)
        segments = token.split('.')
        return false unless segments.length == 3

        payload = JSON.parse(Base64.urlsafe_decode64(segments[1]))
        payload.is_a?(Hash) && payload.key?('iss') && payload.key?('aud')
      rescue ArgumentError, JSON::ParserError
        false
      end

      # INT-8 — reuse a prior `active: true` for at most the published window.
      # @return [Hash, nil]
      def cached_introspection(token)
        IntrospectionCache.instance.fetch(token)
      end

      # RFC 7662 §2.1 — POST the token plus this resource server's own
      # private_key_jwt credential (RFC 7523 §2.2) to the introspection endpoint.
      # Only 200 with a JSON body is a valid answer; everything else is
      # "unavailable" so the caller fails closed.
      #
      # @param [String] token the bearer token exactly as presented
      # @param [String] endpoint `introspection_endpoint` from discovery
      # @return [Hash] the introspection response
      def introspect(token, endpoint)
        body = {
          token: token,
          client_assertion_type: JWT_CLIENT_ASSERTION_TYPE,
          client_assertion: rs_client_assertion(audience: endpoint),
        }

        response = Faraday.new(request: {
          timeout: INTROSPECTION_TIMEOUT_SECONDS,
          open_timeout: INTROSPECTION_TIMEOUT_SECONDS,
        }).post(endpoint, body)

        unless response.status == 200
          raise IntrospectionUnavailable.new("introspection returned HTTP #{response.status}")
        end

        introspection = JSON.parse(response.body)
        raise IntrospectionUnavailable.new('introspection body is not an object') unless
          introspection.is_a?(Hash)

        IntrospectionCache.instance.store(
          token, introspection, ttl_seconds: config.introspection_cache_seconds
        )
        introspection
      rescue Faraday::Error, JSON::ParserError => e
        raise IntrospectionUnavailable.new(e.message)
      end

      # RFC 7523 §3 client assertion, as tightened by INT-6 / RFC 8725:
      # `iss` = `sub` = this resource server's identifier (not the agency's
      # client_id), `aud` = the introspection URL, `exp` required and at most
      # 5 minutes after `iat`, fresh `jti` per call, RS256 pinned.
      # @return [String] compact JWS
      def rs_client_assertion(audience:)
        now = Time.now.to_i
        payload = {
          iss: config.resource_identifier,
          sub: config.resource_identifier,
          aud: audience,
          iat: now,
          exp: now + CLIENT_ASSERTION_LIFETIME_SECONDS,
          jti: SecureRandom.uuid,
        }
        JWT.encode(payload, config.rs_private_key, 'RS256')
      end

      # RFC 6749 §3.3 — scope is a space-delimited list; compare whole values.
      def scope_granted?(scope, required_scope)
        scope.to_s.split.include?(required_scope)
      end

      # §8.5 — record what the agency will later join to Attempts events on
      # `delegation_id`. Never logs the token.
      def log_decision(introspection, route:, decision:, reason: nil, required_scope: nil)
        DecisionLog.instance.record(
          introspection:, route:, decision:, reason:, required_scope:,
        )
      end

      # RFC 6750 §3 — WWW-Authenticate challenge.
      # @return [Hash] headers
      def www_authenticate(scheme, error: nil, scope: nil)
        parts = ["realm=\"#{config.resource_identifier}\""]
        parts << "error=\"#{error}\"" if error
        parts << "scope=\"#{scope}\"" if scope
        {
          'WWW-Authenticate' => "#{scheme} #{parts.join(', ')}",
          'Content-Type' => 'application/json',
        }
      end

      # RFC 6750 §3.1 style JSON error body.
      def json_error_response(error, description)
        { error: error, error_description: description }.to_json
      end
    end
  end
end

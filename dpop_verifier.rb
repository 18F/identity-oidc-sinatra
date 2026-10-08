require 'base64'
require 'digest'
require 'json'
require 'jwt'
require 'openssl'
require 'uri'
require_relative './dpop_replay_cache'

module LoginGov
  module OidcSinatra
    # Verifies an RFC 9449 DPoP proof presented with a key-bound delegated
    # access token, so that only the party holding the private key the token
    # was bound to can use it (a stolen token is useless without the key).
    #
    # Login.gov tells this API that a token is bound by returning
    # `cnf: { jkt: <RFC 7638 thumbprint> }` from introspection. For such a token
    # every request must carry a `DPoP` header: a JWS signed by the bound key,
    # whose claims tie it to this exact request (method, URL, time) and to this
    # exact token (`ath`). The checks below are RFC 9449 §4.3, one per method,
    # in the order the RFC lists them, so an agency can copy the class or lift a
    # single step.
    #
    #   parse               §4.2  compact JWS with typ dpop+jwt and an embedded public jwk
    #   check_algorithm     §4.3 (5)  asymmetric algorithm from the allow-list; never none/HMAC
    #   check_public_key    §4.3 (6)  jwk carries no private members
    #   verify_signature    §4.3 (7)  signature verifies with the embedded jwk
    #   check_method        §4.3 (8)  htm equals the HTTP method of this request
    #   check_url           §4.3 (9)  htu equals this request's URL without query or fragment
    #   check_issued_at     §4.3 (10) iat within the acceptance window
    #   check_replay        §4.3 (11) jti not seen before
    #   check_access_token  §4.3 (12) ath is the SHA-256 of the presented token
    #   check_key_binding   §4.3 (13) thumbprint of jwk equals cnf.jkt from introspection
    #
    # Any failure raises InvalidProof with a reason suitable for an
    # RFC 6750 §3.1 / RFC 9449 §7.1 `error_description`.
    class DpopVerifier
      class InvalidProof < StandardError; end

      # RFC 9449 §4.2: the proof's media type.
      PROOF_TYPE = 'dpop+jwt'.freeze
      # Algorithms accepted by default. Both are asymmetric; RFC 9449 §4.2
      # forbids `none` and symmetric (HMAC) algorithms because the verifier has
      # no shared secret with the key holder.
      DEFAULT_ALLOWED_ALGS = %w[ES256 RS256].freeze
      # Default tolerance on `iat` in either direction (clock skew plus network).
      DEFAULT_IAT_LEEWAY_SECONDS = 60
      # JWK members that are private key material (RFC 7518 §6.2.2, §6.3.2,
      # §6.4). Their presence means the proof carried a private key, which is
      # never acceptable and suggests a leaked key.
      PRIVATE_JWK_MEMBERS = %w[d p q dp dq qi oth k].freeze
      # RFC 7638 §3.2: the members that go into the thumbprint, per key type.
      THUMBPRINT_MEMBERS = {
        'EC' => %w[crv kty x y],
        'RSA' => %w[e kty n],
      }.freeze

      attr_reader :payload, :header

      # @param [String, nil] proof the DPoP request header value
      # @param [String] method the HTTP method of the request being authorized
      # @param [String] url the URL of the request as this server sees it
      # @param [String] access_token the token exactly as presented
      # @param [String] expected_jkt `cnf.jkt` from Login.gov's introspection
      # @param [Array<String>] allowed_algs
      # @param [Integer] iat_leeway_seconds
      # @param [DpopReplayCache] replay_cache
      # @param [Time] now
      def initialize(proof:, method:, url:, access_token:, expected_jkt:,
                     allowed_algs: DEFAULT_ALLOWED_ALGS,
                     iat_leeway_seconds: DEFAULT_IAT_LEEWAY_SECONDS,
                     replay_cache: DpopReplayCache.instance,
                     now: Time.now)
        @proof = proof
        @method = method.to_s
        @url = url.to_s
        @access_token = access_token.to_s
        @expected_jkt = expected_jkt.to_s
        @allowed_algs = Array(allowed_algs).map(&:to_s)
        @iat_leeway = Integer(iat_leeway_seconds)
        @replay_cache = replay_cache
        @now = now
      end

      # Runs every check in order. Returns self so the caller can read the
      # verified payload.
      def verify!
        parse
        check_algorithm
        check_public_key
        verify_signature
        check_method
        check_url
        check_issued_at
        check_replay
        check_access_token
        check_key_binding
        self
      end

      # RFC 7638 thumbprint of a public JWK: SHA-256 over the canonical JSON of
      # the required members only, in lexicographic order, base64url without
      # padding. Computed here rather than trusting a `kid` the client chose.
      #
      # @param [Hash] jwk with string keys
      # @return [String]
      def self.thumbprint(jwk)
        members = THUMBPRINT_MEMBERS.fetch(jwk['kty']) do
          raise InvalidProof.new("unsupported jwk kty #{jwk['kty'].inspect}")
        end
        canonical = members.map { |m| [m, jwk.fetch(m)] }.to_h
        Base64.urlsafe_encode64(Digest::SHA256.digest(JSON.generate(canonical)), padding: false)
      rescue KeyError => e
        raise InvalidProof.new("jwk is missing #{e.key}")
      end

      # RFC 9449 §4.3 (12): `ath` is the base64url (no padding) SHA-256 hash of
      # the ASCII access token value.
      def self.access_token_hash(access_token)
        Base64.urlsafe_encode64(Digest::SHA256.digest(access_token.to_s), padding: false)
      end

      private

      # --- step: parse (§4.2) ----------------------------------------------

      # Decode the compact JWS without verifying yet, so the embedded public key
      # can be read. Exactly three segments; `typ` must be dpop+jwt; the header
      # must carry a `jwk` object. Nothing in the payload is trusted until
      # verify_signature has passed.
      def parse
        raise InvalidProof.new('DPoP header is missing') if @proof.nil? || @proof.strip.empty?
        raise InvalidProof.new('DPoP header must be a single compact JWS') if
          @proof.include?(',') || @proof.count('.') != 2

        @payload, @header = JWT.decode(@proof, nil, false)
        raise InvalidProof.new('proof typ must be dpop+jwt') unless @header['typ'] == PROOF_TYPE

        @jwk = @header['jwk']
        raise InvalidProof.new('proof header has no jwk') unless @jwk.is_a?(Hash)
      rescue JWT::DecodeError => e
        raise InvalidProof.new("proof is not a valid JWS: #{e.message}")
      end

      # --- step: algorithm (§4.3 step 5) -----------------------------------

      def check_algorithm
        alg = @header['alg'].to_s
        return if @allowed_algs.include?(alg) && alg != 'none' && !alg.start_with?('HS')

        raise InvalidProof.new("proof alg #{alg.inspect} is not accepted")
      end

      # --- step: public key only (§4.3 step 6) -----------------------------

      def check_public_key
        private_members = @jwk.keys.map(&:to_s) & PRIVATE_JWK_MEMBERS
        return if private_members.empty?

        raise InvalidProof.new('proof jwk must not contain private key members')
      end

      # --- step: signature (§4.3 step 7) -----------------------------------

      # Verify with the key embedded in the proof itself. That key is trusted
      # only because check_key_binding later ties its thumbprint to the
      # `cnf.jkt` Login.gov returned for the token.
      def verify_signature
        public_key = JWT::JWK.import(@jwk).public_key
        JWT.decode(@proof, public_key, true, algorithm: @header['alg'])
      rescue JWT::DecodeError, JWT::JWKError, OpenSSL::PKey::PKeyError, ArgumentError => e
        raise InvalidProof.new("proof signature does not verify: #{e.message}")
      end

      # --- step: method (§4.3 step 8) --------------------------------------

      def check_method
        return if @payload['htm'].is_a?(String) && @payload['htm'].upcase == @method.upcase

        raise InvalidProof.new('proof htm does not match the request method')
      end

      # --- step: URL (§4.3 step 9) -----------------------------------------

      # `htu` is compared to this request's URL with query and fragment
      # removed, scheme and host case-insensitively. The URL comes from the
      # request as the app sees it, so behind a TLS-terminating gateway the app
      # must honor X-Forwarded-Proto / X-Forwarded-Host (Rack does) or the
      # client's https URL will never match.
      def check_url
        htu = @payload['htu']
        raise InvalidProof.new('proof htu is missing') unless htu.is_a?(String)

        return if normalize_url(htu) == normalize_url(@url)

        raise InvalidProof.new('proof htu does not match the request URL')
      end

      def normalize_url(value)
        uri = URI.parse(value)
        if uri.scheme.nil? || uri.host.nil?
          raise InvalidProof.new('proof htu is not an absolute URL')
        end

        scheme = uri.scheme.downcase
        default_port = scheme == 'https' ? 443 : 80
        port = (uri.port.nil? || uri.port == default_port) ? '' : ":#{uri.port}"
        path = uri.path.empty? ? '/' : uri.path
        "#{scheme}://#{uri.host.downcase}#{port}#{path}"
      rescue URI::InvalidURIError
        raise InvalidProof.new('proof htu is not a valid URL')
      end

      # --- step: issued at (§4.3 step 10) ----------------------------------

      def check_issued_at
        iat = @payload['iat']
        raise InvalidProof.new('proof iat must be an integer') unless iat.is_a?(Integer)

        return if (iat - @now.to_i).abs <= @iat_leeway

        raise InvalidProof.new('proof iat is outside the acceptance window')
      end

      # --- step: replay (§4.3 step 11) -------------------------------------

      # Remember the jti until the proof's iat would be refused anyway.
      def check_replay
        jti = @payload['jti']
        raise InvalidProof.new('proof jti is missing') unless jti.is_a?(String) && !jti.empty?

        expires_at = Time.at(@payload['iat'] + @iat_leeway)
        return if @replay_cache.first_use?(jti, expires_at: expires_at)

        raise InvalidProof.new('proof jti has already been used')
      end

      # --- step: access token hash (§4.3 step 12) --------------------------

      def check_access_token
        return if @payload['ath'] == self.class.access_token_hash(@access_token)

        raise InvalidProof.new('proof ath does not match the presented access token')
      end

      # --- step: key binding (§4.3 step 13) --------------------------------

      def check_key_binding
        return if self.class.thumbprint(@jwk) == @expected_jkt

        raise InvalidProof.new('proof key does not match the key the token is bound to')
      end
    end
  end
end

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
      #
      # The order matters. Nothing read from the proof is trusted until
      # verify_signature has passed, so the structural checks (parse, alg, no
      # private key) come first and every claim check comes after. check_replay
      # is deliberately late: recording a jti is a side effect, and a proof that
      # fails on signature, method, URL or time must not be able to burn a jti
      # the real key holder is about to present. check_key_binding is last so
      # the error a caller sees for a well-formed proof signed by the wrong key
      # says "wrong key", not something misleading from an earlier step.
      def verify!
        parse               # §4.2: shape and typ; reads the embedded jwk (untrusted so far)
        check_algorithm     # §4.3 (5): asymmetric, on the allow-list
        check_public_key    # §4.3 (6): the jwk carries no private members
        verify_signature    # §4.3 (7): from here on the payload is authentic
        check_method        # §4.3 (8): bound to this HTTP method
        check_url           # §4.3 (9): bound to this URL
        check_issued_at     # §4.3 (10): fresh
        check_replay        # §4.3 (11): first presentation of this jti
        check_access_token  # §4.3 (12): bound to the token actually presented
        check_key_binding   # §4.3 (13): the signing key is the one Login.gov bound the token to
        self
      end

      # RFC 7638 thumbprint of a public JWK: SHA-256 over the canonical JSON of
      # the required members only, in lexicographic order, base64url without
      # padding. Computed here rather than trusting a `kid` the client chose.
      #
      # @param [Hash] jwk with string keys
      # @return [String]
      def self.thumbprint(jwk)
        # Which members count depends on the key type (EC: crv, kty, x, y;
        # RSA: e, kty, n). Anything else the client put in the jwk (kid, use,
        # alg, x5c) is excluded on purpose: a thumbprint computed over extra
        # members would differ from the one Login.gov stored at exchange time
        # and would also let a client forge a "match" by adjusting those fields.
        members = THUMBPRINT_MEMBERS.fetch(jwk['kty']) do
          raise InvalidProof.new("unsupported jwk kty #{jwk['kty'].inspect}")
        end
        # RFC 7638 §3: the members in lexicographic order (THUMBPRINT_MEMBERS is
        # already sorted), serialized with no whitespace, then SHA-256,
        # base64url without padding. JSON.generate emits exactly that compact form.
        canonical = members.map { |m| [m, jwk.fetch(m)] }.to_h
        Base64.urlsafe_encode64(Digest::SHA256.digest(JSON.generate(canonical)), padding: false)
      rescue KeyError => e
        # A jwk missing a required member cannot be the key the token was bound to.
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
        # RFC 9449 §4.1 allows exactly one DPoP header. Rack joins repeated
        # headers with a comma, and a compact JWS has exactly two dots, so
        # either sign means more than one proof (or garbage) was sent.
        raise InvalidProof.new('DPoP header must be a single compact JWS') if
          @proof.include?(',') || @proof.count('.') != 2

        # Decode without verification (third argument false): the key to verify
        # with is inside the header, so it has to be read before it can be
        # checked. Everything read here is treated as untrusted input.
        @payload, @header = JWT.decode(@proof, nil, false)
        # §4.2: typ pins the token to its purpose so a JWS minted for something
        # else (an ID token, a client assertion) can never pass as a proof.
        raise InvalidProof.new('proof typ must be dpop+jwt') unless @header['typ'] == PROOF_TYPE

        @jwk = @header['jwk']
        raise InvalidProof.new('proof header has no jwk') unless @jwk.is_a?(Hash)
      rescue JWT::DecodeError => e
        raise InvalidProof.new("proof is not a valid JWS: #{e.message}")
      end

      # --- step: algorithm (§4.3 step 5) -----------------------------------

      def check_algorithm
        alg = @header['alg'].to_s
        # The allow-list is operator configuration; `none` and HS* are refused
        # even if someone lists them. With `none` there is no signature at all,
        # and with HMAC the "key" in the jwk would be the shared secret, so any
        # holder of the proof could mint another one.
        return if @allowed_algs.include?(alg) && alg != 'none' && !alg.start_with?('HS')

        raise InvalidProof.new("proof alg #{alg.inspect} is not accepted")
      end

      # --- step: public key only (§4.3 step 6) -----------------------------

      def check_public_key
        # Intersect the jwk's member names with the known private-key members.
        # A non-empty result means the client leaked its private key in the
        # proof; the proof is refused rather than silently stripped.
        private_members = @jwk.keys.map(&:to_s) & PRIVATE_JWK_MEMBERS
        return if private_members.empty?

        raise InvalidProof.new('proof jwk must not contain private key members')
      end

      # --- step: signature (§4.3 step 7) -----------------------------------

      # Verify with the key embedded in the proof itself. That key is trusted
      # only because check_key_binding later ties its thumbprint to the
      # `cnf.jkt` Login.gov returned for the token.
      def verify_signature
        # Build an OpenSSL key from the jwk and verify the JWS with it, pinning
        # the algorithm to the one already allow-listed above (so the library
        # cannot be talked into a different algorithm by the header).
        public_key = JWT::JWK.import(@jwk).public_key
        JWT.decode(@proof, public_key, true, algorithm: @header['alg'])
      rescue JWT::DecodeError, JWT::JWKError, OpenSSL::PKey::PKeyError, ArgumentError => e
        raise InvalidProof.new("proof signature does not verify: #{e.message}")
      end

      # --- step: method (§4.3 step 8) --------------------------------------

      def check_method
        # HTTP methods are case-sensitive on the wire but conventionally upper
        # case; compare case-insensitively so "get" and "GET" agree.
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

      # Both sides of the comparison go through the same normalization so that
      # differences a client cannot control (an explicit :443, upper-case host,
      # a trailing query string) do not cause false refusals, while anything
      # that changes the resource (scheme, host, non-default port, path) does.
      def normalize_url(value)
        uri = URI.parse(value)
        # §4.3 (9) requires an absolute URL; a bare path says nothing about
        # which server the proof was meant for.
        if uri.scheme.nil? || uri.host.nil?
          raise InvalidProof.new('proof htu is not an absolute URL')
        end

        scheme = uri.scheme.downcase
        # Drop the port when it is the scheme's default so "https://h/p" and
        # "https://h:443/p" compare equal; keep any other port.
        default_port = scheme == 'https' ? 443 : 80
        port = (uri.port.nil? || uri.port == default_port) ? '' : ":#{uri.port}"
        path = uri.path.empty? ? '/' : uri.path
        # Query and fragment are intentionally omitted (§4.3 (9)); rebuilding
        # from parts is how they are stripped.
        "#{scheme}://#{uri.host.downcase}#{port}#{path}"
      rescue URI::InvalidURIError
        raise InvalidProof.new('proof htu is not a valid URL')
      end

      # --- step: issued at (§4.3 step 10) ----------------------------------

      def check_issued_at
        iat = @payload['iat']
        raise InvalidProof.new('proof iat must be an integer') unless iat.is_a?(Integer)

        # Accept iat within the leeway on either side of now: behind covers
        # network delay, ahead covers a client clock running fast. Outside the
        # window the proof is stale (or pre-dated) and could be a replay the
        # jti cache has already forgotten.
        return if (iat - @now.to_i).abs <= @iat_leeway

        raise InvalidProof.new('proof iat is outside the acceptance window')
      end

      # --- step: replay (§4.3 step 11) -------------------------------------

      # Remember the jti until the proof's iat would be refused anyway.
      def check_replay
        jti = @payload['jti']
        raise InvalidProof.new('proof jti is missing') unless jti.is_a?(String) && !jti.empty?

        # Remember the jti exactly as long as check_issued_at would still accept
        # this proof; after that the iat check refuses it anyway, so the cache
        # never has to hold more than one leeway window of proofs.
        expires_at = Time.at(@payload['iat'] + @iat_leeway)
        return if @replay_cache.first_use?(jti, expires_at: expires_at)

        raise InvalidProof.new('proof jti has already been used')
      end

      # --- step: access token hash (§4.3 step 12) --------------------------

      def check_access_token
        # Hash the token exactly as it arrived in the Authorization header; any
        # re-encoding would produce a different digest. A proof lifted from a
        # request for one token cannot be reused with another.
        return if @payload['ath'] == self.class.access_token_hash(@access_token)

        raise InvalidProof.new('proof ath does not match the presented access token')
      end

      # --- step: key binding (§4.3 step 13) --------------------------------

      def check_key_binding
        # The signature proved the caller holds the private half of @jwk; this
        # step proves @jwk is the key Login.gov bound the token to. Without it a
        # thief could present a stolen token with a proof from their own key.
        return if self.class.thumbprint(@jwk) == @expected_jkt

        raise InvalidProof.new('proof key does not match the key the token is bound to')
      end
    end
  end
end

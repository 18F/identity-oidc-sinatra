# frozen_string_literal: true

require 'digest'
require 'jwt'
require 'openssl'
require 'securerandom'
require 'time'
require 'uri'

module LoginGov
  module OidcSinatra
    # RFC 9449 (DPoP) for both roles this sample plays.
    #
    # As the actor, the sample holds a P-256 key for the sign-in, names its thumbprint as dpop_jkt
    # on the authorization request, and signs one proof per request to Login.gov's token endpoint:
    # for the code exchange, and for the token exchange with `ath` over the subject token it
    # presents. Login.gov binds the delegated access token to that key and reports it as `cnf.jkt`.
    #
    # As the agency API, the sample verifies the proof that accompanies a delegated token: the proof
    # is for this request's method and URL, is recent, carries `ath` over the token exactly as
    # presented, and is signed by the key whose thumbprint the token's `cnf.jkt` names. A token with
    # `cnf` presented without a proof, or as a Bearer token, is refused.
    module Dpop
      PROOF_TYPE = 'dpop+jwt'
      ALLOWED_ALGORITHMS = %w[ES256 RS256].freeze
      MAX_AGE_SECONDS = 300

      class ProofError < StandardError; end

      def self.generate_key
        OpenSSL::PKey::EC.generate('prime256v1')
      end

      def self.key_from_pem(pem)
        OpenSSL::PKey::EC.new(pem)
      end

      # The public half of the key as a JWK, the form the proof header carries.
      def self.public_jwk(key)
        JWT::JWK.new(key).export
      end

      # RFC 7638 thumbprint: what the authorization request names as dpop_jkt and what Login.gov
      # puts in the delegated token's cnf.jkt.
      def self.thumbprint(key)
        JWT::JWK::Thumbprint.new(JWT::JWK.new(key)).generate
      end

      # RFC 9449 §4.2 `ath`: base64url, unpadded, SHA-256 of the token as presented.
      def self.token_hash(access_token)
        Base64.urlsafe_encode64(Digest::SHA256.digest(access_token.to_s), padding: false)
      end

      # A proof for one request: method, URL, a fresh jti and the current time, plus `ath` when a
      # token accompanies the request. Signed ES256 by the key, whose public half rides in the
      # header so the verifier can check the signature before trusting anything else.
      def self.proof(key:, method:, url:, access_token: nil)
        payload = {
          jti: SecureRandom.urlsafe_base64(16),
          htm: method.to_s.upcase,
          htu: url,
          iat: Time.now.to_i,
        }
        payload[:ath] = token_hash(access_token) if access_token
        JWT.encode(payload, key, 'ES256', typ: PROOF_TYPE, jwk: public_jwk(key))
      end

      # The agency-side check, in the order RFC 9449 §4.3 lists it. Returns the thumbprint of the
      # proof key; raises ProofError with the reason otherwise. This sample keeps no record of seen
      # jti values; a deployed agency API must, so a captured proof cannot be replayed within the
      # acceptance window.
      def self.verify_proof(proof:, method:, url:, access_token:, expected_thumbprint:)
        raise ProofError.new('DPoP proof missing') if proof.to_s.empty?

        header = unverified_header(proof)
        raise ProofError.new('DPoP proof typ must be dpop+jwt') unless header['typ'] == PROOF_TYPE
        unless ALLOWED_ALGORITHMS.include?(header['alg'])
          raise ProofError.new('DPoP proof alg must be ES256 or RS256')
        end

        jwk = import_public_key(header['jwk'])
        payload = JWT.decode(
          proof, jwk.verify_key, true,
          algorithm: header['alg'], required_claims: %w[jti htm htu iat],
          verify_iat: false, verify_expiration: false
        ).first

        check(payload['htm'] == method.to_s.upcase, 'DPoP proof htm does not match')
        check(normalize_url(payload['htu']) == normalize_url(url), 'DPoP proof htu does not match')
        check(recent?(payload['iat']), 'DPoP proof iat is outside the acceptance window')
        check(payload['ath'] == token_hash(access_token), 'DPoP proof ath does not match the token')

        thumbprint = thumbprint(jwk.verify_key)
        check(
          thumbprint == expected_thumbprint,
          'DPoP proof is signed by a key other than the one the token is bound to',
        )

        thumbprint
      rescue JWT::DecodeError => e
        raise ProofError.new("DPoP proof could not be verified: #{e.message}")
      end

      def self.check(condition, message)
        raise ProofError.new(message) unless condition
      end

      def self.unverified_header(proof)
        _payload, header = JWT.decode(proof, nil, false)
        header
      end

      def self.import_public_key(jwk_params)
        raise ProofError.new('DPoP proof carries no jwk header') unless jwk_params.is_a?(Hash)
        jwk = JWT::JWK.new(jwk_params.transform_keys(&:to_sym).except(:kid))
        raise ProofError.new('DPoP proof jwk must be a public key') if jwk.private?
        jwk
      rescue JWT::JWKError, ArgumentError, OpenSSL::PKey::PKeyError => e
        raise ProofError.new("DPoP proof jwk is invalid: #{e.message}")
      end

      # htu is compared without query or fragment, with scheme and host lowercased, default ports
      # dropped and a trailing slash ignored (RFC 9449 §4.3).
      def self.normalize_url(url)
        uri = URI.parse(url.to_s)
        return nil unless uri.is_a?(URI::HTTP) && uri.host

        port = uri.port == uri.default_port ? '' : ":#{uri.port}"
        path = uri.path.empty? ? '/' : uri.path
        "#{uri.scheme.downcase}://#{uri.host.downcase}#{port}#{path.chomp('/')}"
      rescue URI::InvalidURIError
        nil
      end

      def self.recent?(iat)
        iat.is_a?(Integer) && (Time.now.to_i - iat).abs <= MAX_AGE_SECONDS
      end
    end
  end
end

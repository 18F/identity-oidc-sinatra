# frozen_string_literal: true

require 'digest'
require 'jwt'
require 'openssl'
require 'securerandom'
require 'time'
require 'uri'

module LoginGov
  module OidcSinatra
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

      def self.public_jwk(key)
        JWT::JWK.new(key).export
      end

      def self.thumbprint(key)
        JWT::JWK::Thumbprint.new(JWT::JWK.new(key)).generate
      end

      # RFC 9449 §4.2: `ath` is the unpadded base64url SHA-256 of the token as presented.
      def self.token_hash(access_token)
        Base64.urlsafe_encode64(Digest::SHA256.digest(access_token.to_s), padding: false)
      end

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

      # The checks of RFC 9449 §4.3 in its order; the sample keeps no record of seen jti values.
      def self.verify_proof(proof:, method:, url:, access_token:, expected_thumbprint:)
        raise ProofError.new('DPoP proof missing') if proof.to_s.empty?

        header = unverified_header(proof)
        raise ProofError.new('DPoP proof typ must be dpop+jwt') unless header['typ'] == PROOF_TYPE
        unless ALLOWED_ALGORITHMS.include?(header['alg'])
          raise ProofError.new("DPoP proof alg must be one of #{ALLOWED_ALGORITHMS.join(', ')}")
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

      # RFC 9449 §4.3: htu is compared without query, fragment, default port or trailing slash.
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

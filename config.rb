# frozen_string_literal: true

require 'json'
require 'aws-sdk-secretsmanager'
require 'yaml'

module LoginGov
  module OidcSinatra
    # Class holding configuration for this sample app. Defaults come from
    # .env via `#default_config`
    class Config
      def initialize()
        @config = default_config
      end

      def attempts_shared_secret
        @config.fetch('attempts_shared_secret')
      end

      # RFC 8707 resource indicator for this API; also `iss`/`sub` of the
      # introspection client assertion (RFC 7523 §3) and the expected `aud`
      # of every delegated token (RFC 7662 §2.2).
      def resource_identifier
        @config.fetch('resource_identifier')
      end

      # Upper bound on how long an `active: true` introspection result may be
      # reused before asking Login.gov again (Login.gov publishes 60 seconds).
      def introspection_cache_seconds
        Integer(@config.fetch('introspection_cache_seconds'))
      end

      # RFC 9449 §4.2 — JWS algorithms accepted on a DPoP proof. Asymmetric
      # only; advertised in the DPoP challenge (§7.1).
      # @return [Array<String>]
      def dpop_allowed_algs
        # Space-separated in the environment (DPOP_ALLOWED_ALGS="ES256 RS256"),
        # the same form the challenge header uses.
        @config.fetch('dpop_allowed_algs').to_s.split
      end

      # RFC 9449 §4.3 (10) — tolerance on a proof's `iat`, in seconds, either side of now.
      def dpop_iat_leeway_seconds
        Integer(@config.fetch('dpop_iat_leeway_seconds'))
      end

      # @return [OpenSSL::PKey::RSA] key that signs introspection assertions
      def rs_private_key
        return @rs_private_key if @rs_private_key

        key = ENV['RS_PRIVATE_KEY'] || get_sp_private_key_raw(@config.fetch('rs_private_key_path'))
        @rs_private_key = OpenSSL::PKey::RSA.new(key)
      end

      # @return [OpenSSL::PKey::RSA] key that decrypts Attempts API events
      # delivered to this agency (its public key is the agency's SP cert).
      def attempts_private_key
        return @attempts_private_key if @attempts_private_key

        key = ENV['attempts_private_key'] ||
              get_sp_private_key_raw(@config.fetch('attempts_private_key_path'))
        @attempts_private_key = OpenSSL::PKey::RSA.new(key)
      end

      def attempts_url
        "#{idp_url}/api/attempts/poll"
      end

      def allow_all_events_plaintext
        @config.fetch('allow_all_events_plaintext') == 'true'
      end

      def idp_url
        @config.fetch('idp_url')
      end

      def acr_values
        @config.fetch('acr_values')
      end

      def redirect_uri
        @config.fetch('redirect_uri')
      end

      def client_id
        @config.fetch('client_id')
      end

      def client_id_pkce
        @config.fetch('client_id_pkce')
      end

      def mock_irs_client_id
        @config.fetch('mock_irs_client_id')
      end

      def redact_ssn?
        @config.fetch('redact_ssn')
      end

      def signed_events?
        @config.fetch('signed_events') == 'true'
      end

      def cache_oidc_config?
        @config.fetch('cache_oidc_config')
      end

      def eipp_allowed?
        @config.fetch('eipp_allowed')
      end

      # @return [OpenSSL::PKey::RSA]
      def sp_private_key
        return @sp_private_key if @sp_private_key

        key = ENV['sp_private_key'] || get_sp_private_key_raw(@config.fetch('sp_private_key_path'))
        @sp_private_key = OpenSSL::PKey::RSA.new(key)
      end

      # Define the default configuration values.
      #
      # @return [Hash]
      #
      def default_config
        data = {
          'acr_values' => ENV['acr_values'] || 'http://idmanagement.gov/ns/assurance/ial/1',
          'client_id' => ENV['client_id'] || 'urn:gov:gsa:openidconnect:sp:records_agency',
          'client_id_pkce' => ENV['client_id_pkce'] || 'urn:gov:gsa:openidconnect:sp:sinatra_pkce',
          'mock_irs_client_id' => ENV['mock_irs_client_id'] ||
                                  'urn:gov:gsa:openidconnect:sp:mock_irs',
          'redirect_uri' => ENV['redirect_uri'] || 'http://localhost:9393/',
          'sp_private_key_path' => ENV['sp_private_key_path'] || './config/rs_demo.key',
          'resource_identifier' => ENV['RESOURCE_IDENTIFIER'] ||
                                   'https://records-api.agency.localdev',
          'rs_private_key_path' => ENV['RS_PRIVATE_KEY_PATH'] || './config/rs_demo.key',
          'introspection_cache_seconds' => ENV['INTROSPECTION_CACHE_SECONDS'] || '60',
          'dpop_allowed_algs' => ENV['DPOP_ALLOWED_ALGS'] || 'ES256 RS256',
          'dpop_iat_leeway_seconds' => ENV['DPOP_IAT_LEEWAY_SECONDS'] || '60',
          'attempts_private_key_path' => ENV['attempts_private_key_path'] ||
                                         ENV['RS_PRIVATE_KEY_PATH'] || './config/rs_demo.key',
          'redact_ssn' => true,
          'cache_oidc_config' => true,
          'eipp_allowed' => ENV.fetch('eipp_allowed', 'false') == 'true',
          'attempts_shared_secret' => ENV['attempts_shared_secret'],
          'allow_all_events_plaintext' => ENV['allow_all_events_plaintext'],
          'signed_events' => ENV['signed_events'],
        }

        # EC2 deployment defaults

        env = ENV['idp_environment'] || 'int'
        domain = ENV['idp_domain'] || 'identitysandbox.gov'

        data['idp_url'] = ENV.fetch('idp_url', nil)
        unless data['idp_url']
          if env == 'prod'
            data['idp_url'] = "https://secure.#{domain}"
          else
            data['idp_url'] = "https://idp.#{env}.#{domain}"
          end
        end
        data['sp_private_key'] = ENV.fetch('sp_private_key', nil)

        data
      end

      private

      def get_sp_private_key_raw(path)
        if path.start_with?('aws-secretsmanager:')
          secret_id = path.split(':', 2).fetch(1)
          opts = {}
          smc = Aws::SecretsManager::Client.new(opts)
          begin
            return smc.get_secret_value(secret_id: secret_id).secret_string
          rescue Aws::SecretsManager::Errors::ResourceNotFoundException
            if ENV['deployed']
              raise
            end
          end

          warn "#{secret_id.inspect}: not found in AWS Secrets Manager, using demo key"
          get_sp_private_key_raw(demo_private_key_path)
        else
          File.read(path)
        end
      end

      def demo_private_key_path
        "#{File.dirname(__FILE__)}/config/rs_demo.key"
      end
    end
  end
end

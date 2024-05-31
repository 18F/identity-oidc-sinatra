# frozen_string_literal: true

require 'json'
require 'aws-sdk-secretsmanager'
require 'yaml'

module LoginGov
  module OidcSinatra
    # Class holding configuration for this sample app. Defaults come from
    # `#default_config`, with keys overridden by data from
    # `config/application.yml` if it exists.
    class Config
      # @param [String] config_file Location of application.yml
      def initialize(config_file: nil)
        @config = default_config

        config_file ||= "#{File.dirname(__FILE__)}/config/application.yml"
        if File.exist?(config_file)
          # STDERR.puts("Loading config from #{config_file.inspect}")
          @config.merge!(YAML.safe_load(File.read(config_file)))
        end
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

      def mock_irs_client_id
        @config.fetch('mock_irs_client_id')
      end

      def redact_ssn?
        @config.fetch('redact_ssn')
      end

      def cache_oidc_config?
        @config.fetch('cache_oidc_config')
      end

      def vtr_disabled?
        @config.fetch('vtr_disabled')
      end

      # @return [OpenSSL::PKey::RSA]
      def sp_private_key
        return @sp_private_key if @sp_private_key

        key = ENV['sp_private_key'] || get_sp_private_key_raw(@config.fetch('sp_private_key_path'))
        @sp_private_key = OpenSSL::PKey::RSA.new(key)
      end

      # Define the default configuration values. If application.yml exists, those
      # values will be merged in overriding defaults.
      #
      # @return [Hash]
      #
      def default_config
        data = {
          'acr_values' => ENV['acr_values'] || 'http://idmanagement.gov/ns/assurance/ial/1',
          'client_id' => ENV['client_id'] || 'urn:gov:gsa:openidconnect:sp:sinatra',
          'mock_irs_client_id' => ENV['mock_irs_client_id'] ||
                                  'urn:gov:gsa:openidconnect:sp:mock_irs',
          'redirect_uri' => ENV['redirect_uri'] || 'http://localhost:9292/',
          'sp_private_key_path' => ENV['sp_private_key_path'] || './config/demo_sp.key',
          'redact_ssn' => true,
          'cache_oidc_config' => true,
          'vtr_disabled' => ENV.fetch('vtr_disabled', 'false') == 'true',
          'eipp_allowed' => ENV.fetch('eipp_allowed', 'false') == 'true',
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
        "#{File.dirname(__FILE__)}/config/demo_sp.key"
      end
    end
  end
end

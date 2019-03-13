# frozen_string_literal: true

require 'json'
require 'login_gov/hostdata'
require 'aws-sdk-secretsmanager'

module LoginGov::OidcSinatra
  # Class holding configuration for this sample app. Defaults come from
  # `#default_config`, with keys overridden by data from
  # `config/application.yml` if it exists.
  class Config
    # @param [String] config_file Location of application.yml
    def initialize(config_file: nil)
      @config = default_config

      config_file ||= File.dirname(__FILE__) + '/config/application.yml'

      if File.exist?(config_file)
        STDERR.puts("Loading config from #{config_file.inspect}")
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

    def redact_ssn?
      @config.fetch('redact_ssn')
    end

    # @return [OpenSSL::PKey::RSA]
    def sp_private_key
      return @sp_private_key if @sp_private_key

      key = get_sp_private_key_raw(@config.fetch('sp_private_key_path'))
      @sp_private_key = OpenSSL::PKey::RSA.new(key)
    end

    # Define the default configuration values. If application.yml exists, those
    # values will be merged in overriding defaults.
    #
    # @return [Hash]
    #
    def default_config
      data = {
        'acr_values' => 'http://idmanagement.gov/ns/assurance/loa/1',
        'client_id' => 'urn:gov:gsa:openidconnect:sp:sinatra',
      }

      if LoginGov::Hostdata.in_datacenter?
        # EC2 deployment defaults
        if LoginGov::Hostdata.env == 'prod'
          data['idp_url'] = "https://secure.#{LoginGov::Hostdata.domain}"
        else
          data['idp_url'] = "https://idp.#{LoginGov::Hostdata.env}.#{LoginGov::Hostdata.domain}"
        end
        data['redirect_uri'] = "https://sp-oidc-sinatra.#{LoginGov::Hostdata.env}.#{LoginGov::Hostdata.domain}/"
        data['sp_private_key_path'] = "aws-secretsmanager:#{LoginGov::Hostdata.env}/sp-oidc-sinatra/oidc.key"
        data['redact_ssn'] = true
      else
        # local dev defaults
        data['idp_url'] = 'http://localhost:3000'
        data['redirect_uri'] = 'http://localhost:9292/'
        data['sp_private_key_path'] = demo_private_key_path
        data['redact_ssn'] = false
      end

      data
    end

    private

    def get_sp_private_key_raw(path)
      if path.start_with?('aws-secretsmanager:')
        secret_id = path.split(':', 2).fetch(1)

        # Set region using EC2 metadata if we're in EC2
        if LoginGov::Hostdata.in_datacenter?
          ec2 = LoginGov::Hostdata::EC2.load
          opts = {region: ec2.region}
        else
          opts = {}
        end

        smc = Aws::SecretsManager::Client.new(opts)
        begin
          return smc.get_secret_value(secret_id: secret_id).secret_string
        rescue Aws::SecretsManager::Errors::ResourceNotFoundException
          if LoginGov::Hostdata.domain == 'login.gov' || LoginGov::Hostdata.env == 'prod'
            raise
          end
        end

        STDERR.puts "#{secret_id.inspect}: not found in AWS Secrets Manager, using demo key"
        get_sp_private_key_raw(demo_private_key_path)
      else
        File.read(path)
      end
    end

    def demo_private_key_path
      if LoginGov::Hostdata.domain == 'login.gov' || LoginGov::Hostdata.env == 'prod'
        raise 'Refusing to use demo key in production'
      end
      File.dirname(__FILE__) + '/config/demo_sp.key'
    end
  end
end

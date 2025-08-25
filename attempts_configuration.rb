require 'faraday'
require_relative './config'

module LoginGov
  module OidcSinatra
    class AttemptsConfiguration
      def self.cached
        @cached ||= live
      end

      def self.live
        config = Config.new
        begin
          response = Faraday.get(URI.join(config.idp_url, '/.well-known/ssf-configuration'))

          if response.status == 200
            JSON.parse(response.body).with_indifferent_access
          else
            msg = 'Error: Unable to retrieve Attempts API configuration from IdP.'
            msg += " #{config.idp_url} responded with #{response.status}."

            raise AppError.new(msg)
          end
        end
      end

      def self.cached_attempts_public_key(attempts_config)
        @cached_attempts_public_key ||= live_attempts_public_key(attempts_config)
      end

      def self.live_attempts_public_key(attempts_config)
        certs_response = JSON.parse(
          Faraday.get(attempts_config[:jwks_uri]).body,
        ).with_indifferent_access

        JWT::JWK.import(certs_response[:keys].first).keypair
      end
    end
  end
end

require 'faraday'
require_relative './config'

module LoginGov
  module OidcSinatra
    class OpenidConfiguration
      def self.cached
        @config ||= live
      end

      def self.live
        config = Config.new
        begin
          response = Faraday.get(URI.join(config.idp_url, '/.well-known/openid-configuration'))

          if response.status == 200
            JSON.parse(response.body).with_indifferent_access
          else
            msg = 'Error: Unable to retrieve OIDC configuration from IdP.'
            msg += " #{config.idp_url} responded with #{response.status}."

            if response.status == 401
              msg += ' Perhaps we need to reimplement HTTP Basic Auth.'
            end

            raise AppError.new(msg)
          end
        end
      end

      def self.cached_idp_public_key(openid_configuration)
        @idp_public_key ||= live_idp_public_key(openid_configuration)
      end

      def self.live_idp_public_key(openid_configuration)
        certs_response = JSON.parse(
          Faraday.get(openid_configuration[:jwks_uri]).body
        ).with_indifferent_access

        JSON::JWK.new(certs_response[:keys].first).to_key
      end
    end
  end
end

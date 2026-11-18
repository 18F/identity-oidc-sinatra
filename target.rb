# frozen_string_literal: true

module LoginGov
  module OidcSinatra
    class Target
      attr_reader :issuer, :api, :initiate_login_uri

      def self.from_config(config)
        new(
          issuer: config.fetch('issuer'),
          api: config.fetch('api'),
          initiate_login_uri: config['initiate_login_uri'],
        )
      end

      def initialize(issuer:, api:, initiate_login_uri: nil)
        @issuer = issuer
        @api = api
        @initiate_login_uri = initiate_login_uri
      end

      def resource
        api
      end
    end
  end
end

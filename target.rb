# frozen_string_literal: true

module LoginGov
  module OidcSinatra
    class Target
      attr_reader :issuer, :api

      def self.from_config(config)
        new(
          issuer: config.fetch('issuer'),
          api: config.fetch('api'),
        )
      end

      def initialize(issuer:, api:)
        @issuer = issuer
        @api = api
      end

      def resource
        api
      end
    end
  end
end

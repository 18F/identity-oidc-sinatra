require 'time'

module LoginGov
  module OidcSinatra
    # In-memory ring buffer of authorization decisions made by the resource server.
    #
    # Each entry records what the agency needs to join an API call to Login.gov's
    # Attempts API events (both carry the same `delegation_id`): the user's `sub`,
    # the acting service provider
    # (`act.sub`, RFC 8693 §4.1), the `delegation_id`, the token's `scope`, the
    # route called, the decision and the time. Tokens are never stored.
    # Each entry also keeps the identity claims the introspection response
    # carried (`claims`, SSN already redacted) and `session_live`, false when
    # Login.gov released identifiers and email only because the user's sign-in
    # had ended, so GET /decisions can show what the API learned about the user
    # on that call.
    # A production API would write the identifiers to its audit log and keep
    # the claims out of it; the buffer exists so the demo can show every
    # decision on GET /decisions.
    class DecisionLog
      DEFAULT_CAPACITY = 500

      def self.instance
        @instance ||= new
      end

      def initialize(capacity: DEFAULT_CAPACITY)
        @capacity = capacity
        @entries = []
        @mutex = Mutex.new
      end

      # @param [Hash, nil] introspection the RFC 7662 response (nil when no token
      #   was presented or introspection was unavailable)
      # @param [String] route e.g. "GET /records"
      # @param [String] decision e.g. "allowed", "denied", "unavailable"
      # @param [String, nil] reason e.g. "invalid_token", "insufficient_scope"
      # @param [String, nil] required_scope the scope the route required
      # @param [Hash] claims identity claims read from the introspection response
      def record(introspection:, route:, decision:, reason: nil, required_scope: nil, claims: {})
        introspection ||= {}
        entry = {
          'time' => Time.now.utc.iso8601,
          'route' => route,
          'decision' => decision,
          'reason' => reason,
          'required_scope' => required_scope,
          'sub' => introspection['sub'],
          'actor' => introspection.dig('act', 'sub'),
          'client_id' => introspection['client_id'],
          'delegation_id' => introspection['delegation_id'],
          'scope' => introspection['scope'],
          'aud' => introspection['aud'],
          'session_live' => introspection['session_live'],
          # RFC 9449: thumbprint of the key the token is bound to, when Login.gov
          # bound it; nil for a plain bearer token. Recorded so an operator can
          # see on /decisions which calls were key-bound and tell a refused
          # proof from an unbound token.
          'bound_key' => introspection.dig('cnf', 'jkt'),
          'claims' => claims,
        }
        @mutex.synchronize do
          @entries << entry
          @entries.shift(@entries.size - @capacity) if @entries.size > @capacity
        end
        entry
      end

      # @return [Array<Hash>] newest first
      def entries
        @mutex.synchronize { @entries.reverse }
      end

      # @return [Array<Hash>] decisions carrying the given delegation_id, newest first
      def for_delegation(delegation_id)
        return [] if delegation_id.nil?

        entries.select { |e| e['delegation_id'] == delegation_id }
      end

      def clear
        @mutex.synchronize { @entries.clear }
      end
    end
  end
end

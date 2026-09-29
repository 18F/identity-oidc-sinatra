require 'digest'

module LoginGov
  module OidcSinatra
    # Short-lived cache of `active: true` introspection results (RFC 7662).
    #
    # INT-8: Login.gov publishes a maximum window (60 seconds) during which a
    # resource server may reuse an `active: true` answer before re-introspecting.
    # Entries are keyed by the SHA-256 digest of the token so the plaintext token
    # is never stored. Inactive results are not cached: re-asking is cheap and
    # keeps the resource server failing closed.
    class IntrospectionCache
      Entry = Struct.new(:introspection, :expires_at)

      def self.instance
        @instance ||= new
      end

      def initialize(clock: -> { Time.now })
        @clock = clock
        @entries = {}
        @mutex = Mutex.new
      end

      # @param [String] token the bearer token exactly as presented
      # @return [Hash, nil] the cached introspection response, or nil
      def fetch(token)
        key = digest(token)
        @mutex.synchronize do
          entry = @entries[key]
          return nil unless entry
          if entry.expires_at <= @clock.call
            @entries.delete(key)
            return nil
          end
          entry.introspection
        end
      end

      # Store an `active: true` result for at most `ttl_seconds`, and never past
      # the token's own `exp`.
      def store(token, introspection, ttl_seconds:)
        return unless introspection['active'] == true

        now = @clock.call
        expires_at = now + ttl_seconds
        token_exp = introspection['exp']
        expires_at = [expires_at, Time.at(token_exp.to_i)].min if token_exp
        return if expires_at <= now

        @mutex.synchronize { @entries[digest(token)] = Entry.new(introspection, expires_at) }
      end

      def clear
        @mutex.synchronize { @entries.clear }
      end

      def size
        @mutex.synchronize { @entries.size }
      end

      private

      def digest(token)
        Digest::SHA256.hexdigest(token.to_s)
      end
    end
  end
end

module LoginGov
  module OidcSinatra
    # Remembers the `jti` of every DPoP proof this resource server has accepted
    # (RFC 9449 §4.3 step 11 / §11.1) so a captured proof cannot be presented a
    # second time within its acceptance window.
    #
    # Entries are keyed by the proof's `jti` and dropped once the proof's `iat`
    # is too old to be accepted anyway, so the cache never grows past the
    # proofs that are still replayable. In-memory and per process; a
    # multi-instance deployment would back this with a shared store keyed the
    # same way.
    class DpopReplayCache
      def self.instance
        @instance ||= new
      end

      def initialize(clock: -> { Time.now })
        @clock = clock
        @seen = {}
        @mutex = Mutex.new
      end

      # @param [String] jti the proof's unique identifier
      # @param [Time] expires_at when the proof can no longer be accepted (its
      #   `iat` plus the leeway); the entry can be dropped then
      # @return [Boolean] true if this is the first time the jti has been seen
      def first_use?(jti, expires_at:)
        @mutex.synchronize do
          purge_expired
          return false if @seen.key?(jti)

          @seen[jti] = expires_at
          true
        end
      end

      def size
        @mutex.synchronize { @seen.size }
      end

      def clear
        @mutex.synchronize { @seen.clear }
      end

      private

      def purge_expired
        now = @clock.call
        @seen.delete_if { |_jti, expires_at| expires_at <= now }
      end
    end
  end
end

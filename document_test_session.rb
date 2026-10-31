# frozen_string_literal: true

require 'securerandom'

module LoginGov::OidcSinatra
  # Process-local values that must not travel in the browser's session cookie: bearer tokens
  # for the test page, and the document images shown once on the home page.
  class DocumentTestSession
    TTL = 900
    LIMIT = 100
    @entries = {}
    @mutex = Mutex.new

    class << self
      def put(token)
        @mutex.synchronize do
          prune
          @entries.shift while @entries.size >= LIMIT
          id = SecureRandom.hex(32)
          @entries[id] = [token, Time.now + TTL]
          id
        end
      end

      def get(id)
        @mutex.synchronize do
          prune
          @entries[id]&.first
        end
      end

      def delete(id)
        @mutex.synchronize { @entries.delete(id) }
      end

      private

      def prune
        @entries.delete_if { |_, entry| entry.last <= Time.now }
      end
    end
  end
end

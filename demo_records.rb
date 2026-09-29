require 'digest'
require 'securerandom'
require 'time'

module LoginGov
  module OidcSinatra
    # Obviously fictional "records" served by the demo resource server, keyed by
    # the user's pairwise `sub` for this agency. Login.gov computes `sub` per
    # agency, so a user who signs in to the agency directly and one whose
    # service provider calls this API with a delegated token get the same
    # `sub` and therefore the same records. Nothing here is real:
    # the seed records are derived from a hash of `sub` and live only in memory.
    class DemoRecords
      def self.instance
        @instance ||= new
      end

      def initialize
        @records = {}
        @mutex = Mutex.new
      end

      # @param [String] sub the user's pairwise identifier for this agency
      # @return [Array<Hash>]
      def for_sub(sub)
        @mutex.synchronize { (@records[sub] ||= seed_records(sub)).dup }
      end

      # @param [String] sub
      # @param [Hash] attributes caller-supplied fields (title, note)
      # @return [Hash] the created record
      def create(sub, attributes)
        title = attributes['title'].to_s.strip
        title = 'Untitled demo record' if title.empty?
        record = {
          'id' => "DEMO-#{SecureRandom.hex(4).upcase}",
          'title' => title,
          'note' => attributes['note'].to_s,
          'created_at' => Time.now.utc.iso8601,
          'fictional' => true,
        }
        @mutex.synchronize do
          (@records[sub] ||= seed_records(sub)) << record
        end
        record
      end

      def clear
        @mutex.synchronize { @records.clear }
      end

      private

      def seed_records(sub)
        tag = Digest::SHA256.hexdigest(sub.to_s)[0, 6].upcase
        [
          {
            'id' => "DEMO-#{tag}-1",
            'title' => 'Sample records request (fictional)',
            'note' => 'Placeholder data for the delegated access demo. Not a real record.',
            'created_at' => '2026-01-01T00:00:00Z',
            'fictional' => true,
          },
          {
            'id' => "DEMO-#{tag}-2",
            'title' => 'Sample correspondence (fictional)',
            'note' => 'Generated from a hash of the pairwise identifier so every user sees ' \
                      'different fake records.',
            'created_at' => '2026-02-01T00:00:00Z',
            'fictional' => true,
          },
        ]
      end
    end
  end
end

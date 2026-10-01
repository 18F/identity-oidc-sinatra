# frozen_string_literal: true

module LoginGov
  module OidcSinatra
    module Loadtest
      # A deliberately minimal, per-virtual-user cookie store.
      #
      # It is NOT a general-purpose RFC 6265 implementation. It keeps cookies
      # keyed by (host, name) so that the Sinatra RP's session cookie and the
      # IdP's session cookie never clobber each other, which is the only
      # cross-domain concern this harness has. Attributes other than the name
      # and value are ignored on purpose: the harness runs for seconds, so
      # Expires/Max-Age pruning would add complexity without changing behavior.
      class CookieJar
        def initialize
          @jars = {}
          @mutex = Mutex.new
        end

        # Record every cookie from a response's Set-Cookie headers.
        #
        # @param host [String] the host the response came from
        # @param set_cookie_values [Array<String>] raw Set-Cookie header values
        def store(host:, set_cookie_values:)
          Array(set_cookie_values).each do |raw|
            name, value = parse(raw)
            next if name.nil?

            @mutex.synchronize do
              jar = (@jars[host] ||= {})
              # A deleted cookie comes back with an empty value; drop it so we
              # do not send `name=` on later requests.
              value.empty? ? jar.delete(name) : jar[name] = value
            end
          end
        end

        # @param host [String] the host a request is about to be sent to
        # @return [String, nil] a Cookie header value, or nil when none apply
        def header_for(host:)
          pairs = @mutex.synchronize { (@jars[host] || {}).map { |k, v| "#{k}=#{v}" } }
          return nil if pairs.empty?

          pairs.join('; ')
        end

        private

        # @return [Array(String, String), Array(nil, nil)]
        def parse(raw)
          pair = raw.to_s.split(';', 2).first.to_s.strip
          return [nil, nil] if pair.empty?

          name, _, value = pair.partition('=')
          name = name.strip
          return [nil, nil] if name.empty?

          [name, value.strip]
        end
      end
    end
  end
end

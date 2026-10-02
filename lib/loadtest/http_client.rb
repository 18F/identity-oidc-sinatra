# frozen_string_literal: true

require 'net/http'
require 'uri'

require_relative 'cookie_jar'
require_relative 'errors'

module LoginGov
  module OidcSinatra
    module Loadtest
      # A single HTTP response plus the timing the harness cares about.
      Response = Struct.new(:status, :headers, :body, :uri, :duration_ms, keyword_init: true) do
        def redirect?
          (300..399).cover?(status)
        end

        def success?
          (200..299).cover?(status)
        end

        def location
          headers['location']
        end
      end

      # Per-virtual-user HTTP client.
      #
      # Three behaviors here are deliberate and load-test specific:
      #
      # 1. Redirects are NOT followed automatically. The harness needs to
      #    inspect each hop to detect interstitial screens (consent, MFA
      #    reminders) and to tell a server-side handoff (302 to the RP) apart
      #    from the client_side_js handoff (an HTML page with an anchor).
      # 2. Every request's wall-clock duration is recorded so the scheduler can
      #    attribute latency to a named step.
      # 3. Connections are not pooled or kept alive. A real browser would reuse
      #    them; doing so here would under-report the cost the IdP pays for new
      #    TLS/TCP setup and would complicate thread safety for no benefit at
      #    the concurrency levels this harness targets.
      class HttpClient
        # Guard against a misconfigured flow looping forever between redirects.
        MAX_REDIRECTS = 10

        # Serializes trace output so concurrent virtual users do not interleave
        # partial lines on stderr.
        TRACE_MUTEX = Mutex.new
        private_constant :TRACE_MUTEX

        # Opt-in on-wire tracing, enabled with LOADTEST_TRACE=1.
        #
        # The harness is a chain of scraped forms and manual redirects, so when a
        # live IdP diverges from what a flow expects the only useful evidence is
        # the request/response sequence itself: which verb went where, with which
        # params, and what status and Location came back. Reconstructing that
        # from a browser is unreliable because the redirect that follows a form
        # POST replaces the entry being inspected.
        #
        # Off by default: a load test writes one line per request, which would
        # otherwise dominate output and skew timings at any real concurrency.
        def self.trace?
          !ENV['LOADTEST_TRACE'].to_s.strip.empty?
        end

        attr_reader :cookie_jar

        def initialize(timeout_seconds: 30, user_agent: 'identity-oidc-sinatra-loadtest')
          @cookie_jar = CookieJar.new
          @timeout_seconds = timeout_seconds
          @user_agent = user_agent
        end

        # @return [Response]
        def get(url, headers: {})
          request(Net::HTTP::Get, url, headers: headers)
        end

        # @param params [Hash] form-encoded body params
        # @return [Response]
        def post(url, params: {}, headers: {})
          request(Net::HTTP::Post, url, params: params, headers: headers)
        end

        # Rails routes some actions to PATCH only (e.g. the MFA setup
        # selection), so the harness needs more than GET/POST.
        # @return [Response]
        def patch(url, params: {}, headers: {})
          request(Net::HTTP::Patch, url, params: params, headers: headers)
        end

        # Follow `Location` headers until a non-redirect response, returning
        # every hop so callers can inspect the chain.
        #
        # @return [Array<Response>] in request order; the last is non-redirect
        def follow_redirects(response, limit: MAX_REDIRECTS)
          chain = [response]
          hops = 0

          while chain.last.redirect? && chain.last.location
            if hops >= limit
              raise Error.new("exceeded #{limit} redirects (last: #{chain.last.location})")
            end

            chain << get(absolutize(chain.last.location, base: chain.last.uri))
            hops += 1
          end

          chain
        end

        # Resolve a possibly-relative Location/href against the URI it came from.
        # @return [String]
        def absolutize(location, base:)
          URI.join(base.to_s, location.to_s).to_s
        end

        private

        def request(request_class, url, params: nil, headers: {})
          uri = URI.parse(url)
          req = build_request(request_class, uri, params: params, headers: headers)

          started = monotonic_now
          response = perform(uri, req)
          duration_ms = ((monotonic_now - started) * 1000).round(2)

          @cookie_jar.store(host: uri.host, set_cookie_values: response.get_fields('set-cookie'))

          result = Response.new(
            status: response.code.to_i,
            headers: downcased_headers(response),
            body: response.body.to_s,
            uri: uri,
            duration_ms: duration_ms,
          )

          trace(req.method, uri, params, result) if self.class.trace?

          result
        end

        # One line per request: verb, URL, status, Location, and the params sent.
        #
        # Params are printed as the flattened pairs actually written to the body,
        # not the caller's hash, because the encoding of nested and array keys
        # (`form[selection][]`) is itself a common source of divergence from what
        # the IdP expects.
        def trace(method, uri, params, result)
          pairs = params ? stringify_form_data(params) : []
          body = pairs.map { |name, value| "#{name}=#{value}" }.join('&')

          TRACE_MUTEX.synchronize do
            warn "trace: #{method} #{uri} -> #{result.status}"
            warn "trace:   location: #{result.location}" if result.location
            warn "trace:   params: #{body}" unless body.empty?
          end
        end

        def build_request(request_class, uri, params:, headers:)
          req = request_class.new(uri)
          req['User-Agent'] = @user_agent
          # Ask for HTML explicitly: some IdP endpoints vary their response on
          # Accept, and the harness always wants the browser-equivalent page.
          req['Accept'] = 'text/html,application/xhtml+xml'

          cookie = @cookie_jar.header_for(host: uri.host)
          req['Cookie'] = cookie if cookie

          headers.each { |key, value| req[key] = value }
          req.set_form_data(stringify_form_data(params)) if params

          req
        end

        def perform(uri, req)
          Net::HTTP.start(
            uri.host,
            uri.port,
            use_ssl: uri.scheme == 'https',
            open_timeout: @timeout_seconds,
            read_timeout: @timeout_seconds,
          ) { |http| http.request(req) }
        rescue SystemCallError, Net::OpenTimeout, Net::ReadTimeout, IOError => e
          raise Error.new("#{req.method} #{uri} failed: #{e.class}: #{e.message}")
        end

        # Rails form params are nested (`user[email]`), and `set_form_data`
        # wants flat string pairs, so flatten one level of hash nesting.
        #
        # Array values become repeated pairs under the same key. Rails parses
        # repeated `name[]` pairs into an array, which is how checkbox groups
        # such as the MFA selection are submitted; collapsing them with #to_s
        # would send the literal inspect output instead.
        def stringify_form_data(params)
          params.each_with_object([]) do |(key, value), pairs|
            case value
            when Hash
              value.each { |nested_key, nested| pairs << ["#{key}[#{nested_key}]", nested.to_s] }
            when Array
              value.each { |element| pairs << [key.to_s, element.to_s] }
            else
              pairs << [key.to_s, value.to_s]
            end
          end
        end

        def downcased_headers(response)
          response.each_header.to_h { |key, value| [key.downcase, value] }
        end

        def monotonic_now
          Process.clock_gettime(Process::CLOCK_MONOTONIC)
        end
      end
    end
  end
end

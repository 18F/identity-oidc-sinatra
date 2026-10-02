require 'stringio'
require 'uri'

require_relative 'spec_helper'
require_relative 'support/stub_server'
require_relative '../../lib/loadtest/http_client'

# Exercises HttpClient against real sockets. Cookie handling, redirect
# following, and form encoding are the parts a fake transport cannot verify,
# and they are exactly what the harness depends on to hold a session across the
# relying party and the IdP.
RSpec.describe LoginGov::OidcSinatra::Loadtest::HttpClient do
  subject(:client) { described_class.new(timeout_seconds: 5) }

  after { server&.shutdown }

  let(:server) { nil }

  describe 'basic requests' do
    let(:server) do
      StubServer.new { |_request| [200, {}, 'hello'] }
    end

    it 'returns the response body' do
      expect(client.get(server.base_url).body).to eq('hello')
    end

    it 'returns the status' do
      expect(client.get(server.base_url).status).to eq(200)
    end

    it 'measures how long the request took' do
      expect(client.get(server.base_url).duration_ms).to be > 0
    end

    it 'identifies itself in the User-Agent so traffic is attributable' do
      client.get(server.base_url)

      expect(server.requests.first.headers.fetch('user-agent')).to include('loadtest')
    end
  end

  describe 'form submission' do
    let(:server) do
      StubServer.new { |_request| [200, {}, 'ok'] }
    end

    it 'form-encodes POST parameters' do
      client.post(server.base_url, params: { 'user[email]' => 'a@example.com' })

      expect(server.requests.first.params).to eq('user[email]' => 'a@example.com')
    end

    it 'flattens nested hashes into Rails-style bracket names' do
      client.post(server.base_url, params: { 'user' => { 'email' => 'a@example.com' } })

      expect(server.requests.first.params).to eq('user[email]' => 'a@example.com')
    end

    it 'supports PATCH, which some IdP routes require' do
      client.patch(server.base_url, params: { 'a' => 'b' })

      expect(server.requests.first.method).to eq('PATCH')
    end

    # Rails turns repeated `name[]` pairs into an array, which is how a checkbox
    # group such as the MFA method selection is submitted. Collapsing the value
    # with #to_s would send the literal inspect output instead.
    it 'repeats the key for array values, as Rails expects for checkbox groups' do
      client.post(
        server.base_url,
        params: { 'form[selection][]' => %w[phone backup_code] },
      )

      expect(URI.decode_www_form(server.requests.first.body)).to eq(
        [['form[selection][]', 'phone'], ['form[selection][]', 'backup_code']],
      )
    end

    it 'sends a single-element array as one pair' do
      client.post(server.base_url, params: { 'form[selection][]' => ['phone'] })

      expect(URI.decode_www_form(server.requests.first.body)).to eq(
        [['form[selection][]', 'phone']],
      )
    end
  end

  describe 'tracing' do
    let(:server) do
      StubServer.new { |_request| [302, { 'Location' => '/next' }, ''] }
    end

    around do |example|
      original = ENV.fetch('LOADTEST_TRACE', nil)
      ENV['LOADTEST_TRACE'] = '1'
      example.run
      ENV['LOADTEST_TRACE'] = original
    end

    it 'reports the verb, status, Location, and submitted params' do
      output = capture_stderr do
        client.post(server.base_url, params: { 'form[selection][]' => ['phone'] })
      end

      expect(output).to include('POST', '302', 'location: /next')
      expect(output).to include('params: form[selection][]=phone')
    end

    it 'stays silent when the trace flag is unset' do
      ENV.delete('LOADTEST_TRACE')

      output = capture_stderr { client.post(server.base_url, params: { 'a' => 'b' }) }

      expect(output).to be_empty
    end

    def capture_stderr
      original = $stderr
      $stderr = StringIO.new
      yield
      $stderr.string
    ensure
      $stderr = original
    end
  end

  describe 'cookies' do
    let(:server) do
      StubServer.new do |request|
        if request.path == '/set'
          [200, { 'Set-Cookie' => '_session=abc; path=/; HttpOnly' }, 'set']
        else
          [200, {}, request.cookie.to_s]
        end
      end
    end

    it 'replays a cookie the server set' do
      client.get("#{server.base_url}/set")

      expect(client.get("#{server.base_url}/echo").body).to eq('_session=abc')
    end

    it 'keeps separate jars per client, so runs cannot share a session' do
      # A leaked session would let one run satisfy the next run's authorize
      # request and silently skip authentication.
      client.get("#{server.base_url}/set")
      other = described_class.new(timeout_seconds: 5)

      expect(other.get("#{server.base_url}/echo").body).to eq('')
    end
  end

  describe 'redirects' do
    let(:server) do
      StubServer.new do |request|
        case request.path
        when '/start' then [302, { 'Location' => '/middle' }, '']
        when '/middle' then [302, { 'Location' => '/end' }, '']
        else [200, {}, 'arrived']
        end
      end
    end

    it 'does not follow redirects automatically' do
      # Flows must inspect each hop to recognize interstitial screens and to
      # tell a redirect handoff apart from the JavaScript one.
      response = client.get("#{server.base_url}/start")

      expect(response.status).to eq(302)
      expect(response).to be_redirect
    end

    it 'follows a redirect chain when asked, returning every hop' do
      chain = client.follow_redirects(client.get("#{server.base_url}/start"))

      expect(chain.length).to eq(3)
      expect(chain.last.body).to eq('arrived')
    end

    it 'resolves relative Location headers against the current URL' do
      chain = client.follow_redirects(client.get("#{server.base_url}/start"))

      expect(chain.last.uri.path).to eq('/end')
    end
  end

  describe 'redirect loops' do
    let(:server) do
      StubServer.new { |_request| [302, { 'Location' => '/loop' }, ''] }
    end

    it 'gives up rather than looping forever' do
      expect { client.follow_redirects(client.get("#{server.base_url}/loop"), limit: 3) }.
        to raise_error(LoginGov::OidcSinatra::Loadtest::Error, /exceeded 3 redirects/)
    end
  end

  describe 'transport failures' do
    it 'raises a harness error, not a bare socket error' do
      # The scheduler catches harness errors per run; a raw SystemCallError would
      # be reported as an unexpected crash instead of a flow failure.
      closed_port = begin
        probe = TCPServer.new('127.0.0.1', 0)
        port = probe.addr[1]
        probe.close
        port
      end

      expect { client.get("http://127.0.0.1:#{closed_port}/") }.
        to raise_error(LoginGov::OidcSinatra::Loadtest::Error, /failed/)
    end
  end

  describe '#absolutize' do
    it 'resolves a relative path against a base URL' do
      base = URI.parse('http://localhost:3000/sign_up/verify_email')

      expect(client.absolutize('/sign_up/email/confirm?t=1', base: base)).
        to eq('http://localhost:3000/sign_up/email/confirm?t=1')
    end

    it 'leaves an absolute URL alone, as the cross-host handoff requires' do
      base = URI.parse('http://localhost:3000/openid_connect/authorize')

      expect(client.absolutize('http://localhost:9292/auth/result?code=a', base: base)).
        to eq('http://localhost:9292/auth/result?code=a')
    end
  end
end

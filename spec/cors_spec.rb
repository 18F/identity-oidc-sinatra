# CORS on the resource server routes (Fetch standard,
# https://fetch.spec.whatwg.org/#http-cors-protocol). The reference service provider is a browser
# public client, so the browser enforces these headers on its calls to /records.
require 'spec_helper'

RSpec.describe LoginGov::OidcSinatra::OpenidConnectRelyingParty, 'CORS on /records' do
  let(:host) { 'http://localhost:3000' }
  let(:introspection_endpoint) { "#{host}/api/openid_connect/introspect" }
  let(:sp_origin) { 'http://localhost:9292' }
  let(:token) { 'opaque-delegated-token-abc123' }
  let(:discovery) do
    {
      token_endpoint: "#{host}/api/openid_connect/token",
      jwks_uri: "#{host}/api/openid_connect/certs",
      introspection_endpoint: introspection_endpoint,
    }
  end
  let(:active_introspection) do
    {
      active: true,
      sub: 'agency-pairwise-sub-1',
      email: 'demo.user@example.com',
      aud: 'https://records-api.agency.localdev',
      scope: 'token_exchange:housing_records',
      act: { sub: 'urn:gov:gsa:openidconnect:sp:sinatra_sts' },
      delegation_id: 'a1b2c3d4-0000-4000-8000-000000000001',
      token_type: 'Bearer',
    }
  end

  before do
    ENV.delete('CORS_ALLOWED_ORIGINS')
    allow_any_instance_of(LoginGov::OidcSinatra::Config).to receive(:cache_oidc_config?).and_return(false)
    stub_request(:get, "#{host}/.well-known/openid-configuration").to_return(body: discovery.to_json)
    stub_request(:post, introspection_endpoint).to_return(body: active_introspection.to_json)
    LoginGov::OidcSinatra::IntrospectionCache.instance.clear
    LoginGov::OidcSinatra::DecisionLog.instance.clear
    LoginGov::OidcSinatra::DemoRecords.instance.clear
  end

  after do
    ENV.delete('CORS_ALLOWED_ORIGINS')
    ENV.delete('DELEGATION_ACCESS_TYPE')
  end

  describe 'preflight (OPTIONS)' do
    it 'allows GET and POST with Authorization, DPoP and Content-Type from the configured origin' do
      header 'Origin', sp_origin
      header 'Access-Control-Request-Method', 'GET'
      header 'Access-Control-Request-Headers', 'authorization, dpop'
      options '/records'

      expect(last_response.status).to eq 204
      expect(last_response.headers['Access-Control-Allow-Origin']).to eq sp_origin
      expect(last_response.headers['Access-Control-Allow-Methods']).to eq 'GET, POST, OPTIONS'
      expect(last_response.headers['Access-Control-Allow-Headers']).to eq 'Authorization, DPoP, Content-Type'
      expect(last_response.headers['Vary']).to include 'Origin'
    end

    it 'offers no POST when the application is registered read-only' do
      ENV['DELEGATION_ACCESS_TYPE'] = 'read'
      header 'Origin', sp_origin
      header 'Access-Control-Request-Method', 'POST'
      options '/records'

      expect(last_response.headers['Access-Control-Allow-Methods']).to eq 'GET, OPTIONS'
    end

    it 'answers an origin that is not allowed without any CORS headers' do
      header 'Origin', 'https://evil.example'
      options '/records'

      expect(last_response.status).to eq 204
      expect(last_response.headers).not_to have_key('Access-Control-Allow-Origin')
    end

    it 'reads additional origins from CORS_ALLOWED_ORIGINS' do
      ENV['CORS_ALLOWED_ORIGINS'] = 'https://sp.example.gov, http://localhost:9292'
      header 'Origin', 'https://sp.example.gov'
      options '/records'

      expect(last_response.headers['Access-Control-Allow-Origin']).to eq 'https://sp.example.gov'
    end
  end

  describe 'actual requests' do
    it 'carries the CORS headers and exposes WWW-Authenticate on a 401 challenge' do
      header 'Origin', sp_origin
      get '/records'

      expect(last_response.status).to eq 401
      expect(last_response.headers['WWW-Authenticate']).to start_with('Bearer realm=')
      expect(last_response.headers['Access-Control-Allow-Origin']).to eq sp_origin
      expect(last_response.headers['Access-Control-Expose-Headers']).to eq 'WWW-Authenticate'
    end

    it 'carries the CORS headers on a successful call from the allowed origin' do
      header 'Origin', sp_origin
      header 'Authorization', "Bearer #{token}"
      get '/records'

      expect(last_response.status).to eq(200), last_response.body
      expect(last_response.headers['Access-Control-Allow-Origin']).to eq sp_origin
    end

    it 'accepts a cross-origin POST with a JSON body from the allowed origin' do
      header 'Origin', sp_origin
      header 'Authorization', "Bearer #{token}"
      header 'Content-Type', 'application/json'
      post '/records', { note: 'written from the browser' }.to_json

      expect(last_response.status).to eq(201), last_response.body
      expect(last_response.headers['Access-Control-Allow-Origin']).to eq sp_origin
    end

    it 'adds no CORS headers to routes outside the API' do
      header 'Origin', sp_origin
      get '/decisions.json'

      expect(last_response.headers).not_to have_key('Access-Control-Allow-Origin')
    end
  end
end

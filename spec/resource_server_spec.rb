require 'spec_helper'
require 'nokogiri'

RSpec.describe LoginGov::OidcSinatra::OpenidConnectRelyingParty, 'resource server' do
  let(:host) { 'http://localhost:3000' }
  let(:introspection_endpoint) { "#{host}/api/openid_connect/introspect" }
  let(:resource_identifier) { 'https://records-api.agency.localdev' }
  let(:actor) { 'urn:gov:gsa:openidconnect:sp:sinatra_sts' }
  let(:delegation_id) { 'a1b2c3d4-0000-4000-8000-000000000001' }
  let(:token) { 'opaque-delegated-token-abc123' }
  let(:discovery) do
    {
      authorization_endpoint: "#{host}/openid_connect/authorize",
      token_endpoint: "#{host}/api/openid_connect/token",
      userinfo_endpoint: "#{host}/api/openid_connect/userinfo",
      end_session_endpoint: "#{host}/openid_connect/logout",
      jwks_uri: "#{host}/api/openid_connect/certs",
      introspection_endpoint: introspection_endpoint,
    }
  end
  let(:active_introspection) do
    {
      active: true,
      aud: resource_identifier,
      scope: 'token_exchange:records_read',
      sub: 'agency-pairwise-sub-1',
      act: { sub: actor },
      client_id: actor,
      acr: 'urn:acr.login.gov:verified',
      iat: Time.now.to_i - 5,
      exp: Time.now.to_i + 800,
      delegation_id: delegation_id,
    }
  end
  let(:rs_public_key) { OpenSSL::PKey::RSA.new(File.read('config/rs_demo.key')).public_key }

  before do
    allow_any_instance_of(LoginGov::OidcSinatra::Config).to receive(:cache_oidc_config?).and_return(false)
    stub_request(:get, "#{host}/.well-known/openid-configuration").to_return(body: discovery.to_json)
    LoginGov::OidcSinatra::IntrospectionCache.instance.clear
    LoginGov::OidcSinatra::DecisionLog.instance.clear
    LoginGov::OidcSinatra::DemoRecords.instance.clear
  end

  def stub_introspection(response, status: 200)
    stub_request(:post, introspection_endpoint).
      with(body: hash_including(
        'token' => token,
        'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
      )).
      to_return(status:, body: response.is_a?(String) ? response : response.to_json)
  end

  def get_records(bearer: token)
    header 'Authorization', "Bearer #{bearer}" if bearer
    get '/records'
  end

  def decisions
    LoginGov::OidcSinatra::DecisionLog.instance.entries
  end

  describe 'GET /records' do
    context 'with an active token carrying records_read' do
      let!(:stub) { stub_introspection(active_introspection) }

      it 'serves fictional records for sub and echoes the introspection result' do
        get_records

        expect(last_response.status).to eq 200
        expect(last_response.content_type).to include('application/json')
        body = JSON.parse(last_response.body)
        expect(body['records']).not_to be_empty
        expect(body['records']).to all(include('fictional' => true))
        expect(body['_introspection']).to include('sub' => 'agency-pairwise-sub-1', 'delegation_id' => delegation_id)
        expect(stub).to have_been_requested.once
      end

      it 'sends an RFC 7523 client assertion signed by the resource server key' do
        get_records

        assertion = nil
        expect(a_request(:post, introspection_endpoint).with { |req|
          assertion = Rack::Utils.parse_nested_query(req.body)['client_assertion']
          true
        }).to have_been_made.once

        payload, header = JWT.decode(assertion, rs_public_key, true, algorithm: 'RS256')
        expect(header['alg']).to eq 'RS256'
        expect(payload['iss']).to eq resource_identifier
        expect(payload['sub']).to eq resource_identifier
        expect(payload['aud']).to eq introspection_endpoint
        expect(payload['jti']).to match(/\A[0-9a-f-]{36}\z/)
        expect(payload['exp'] - payload['iat']).to be <= 300
        expect(payload['exp']).to be > Time.now.to_i
      end

      it 'uses a fresh jti for every introspection call' do
        jtis = []
        stub_request(:post, introspection_endpoint).with { |req|
          assertion = Rack::Utils.parse_nested_query(req.body)['client_assertion']
          jtis << JWT.decode(assertion, nil, false).first['jti']
          true
        }.to_return(body: active_introspection.to_json)

        get_records
        LoginGov::OidcSinatra::IntrospectionCache.instance.clear
        get_records

        expect(jtis.length).to eq 2
        expect(jtis.uniq.length).to eq 2
      end

      it 'logs an allowed decision with sub, actor, delegation_id and scope' do
        get_records

        expect(decisions.length).to eq 1
        expect(decisions.first).to include(
          'route' => 'GET /records',
          'decision' => 'allowed',
          'required_scope' => 'token_exchange:records_read',
          'sub' => 'agency-pairwise-sub-1',
          'actor' => actor,
          'delegation_id' => delegation_id,
          'scope' => 'token_exchange:records_read',
        )
        expect(decisions.first.to_json).not_to include(token)
      end

      it 'reuses the cached introspection within the cache window' do
        get_records
        get_records

        expect(last_response.status).to eq 200
        expect(stub).to have_been_requested.once
        expect(decisions.length).to eq 2
      end

      it 're-introspects once the cache window has passed' do
        get_records
        later = Time.now + 61
        allow(Time).to receive(:now).and_return(later)
        get_records

        expect(stub).to have_been_requested.twice
      end
    end

    context 'without a bearer token' do
      it 'returns 401 with a bare Bearer challenge and does not call Login.gov' do
        get_records(bearer: nil)

        expect(last_response.status).to eq 401
        expect(last_response.headers['WWW-Authenticate']).to start_with('Bearer realm=')
        expect(last_response.headers['WWW-Authenticate']).not_to include('error=')
        expect(a_request(:post, introspection_endpoint)).not_to have_been_made
        expect(decisions.first).to include('decision' => 'denied', 'reason' => 'missing_token')
      end

      it 'ignores tokens sent as a query parameter' do
        get "/records?access_token=#{token}"

        expect(last_response.status).to eq 401
      end
    end

    context 'when Login.gov says the token is not active (expired, revoked, unknown)' do
      before { stub_introspection({ active: false }) }

      it 'returns 401 invalid_token' do
        get_records

        expect(last_response.status).to eq 401
        expect(last_response.headers['WWW-Authenticate']).to include('error="invalid_token"')
        expect(JSON.parse(last_response.body)['error']).to eq 'invalid_token'
        expect(decisions.first).to include('decision' => 'denied', 'reason' => 'invalid_token')
      end

      it 'does not cache the negative answer' do
        get_records
        get_records

        expect(a_request(:post, introspection_endpoint)).to have_been_made.twice
      end
    end

    context 'when the token was issued for a different resource server' do
      before do
        stub_introspection(active_introspection.merge(aud: 'https://records-api-same-agency.agency.localdev'))
      end

      it 'returns 401 invalid_token' do
        get_records

        expect(last_response.status).to eq 401
        expect(last_response.headers['WWW-Authenticate']).to include('error="invalid_token"')
        expect(decisions.first).to include('decision' => 'denied', 'reason' => 'wrong_audience')
      end
    end

    context 'when the token has no act claim' do
      before { stub_introspection(active_introspection.except(:act)) }

      it 'returns 401 invalid_token' do
        get_records

        expect(last_response.status).to eq 401
        expect(decisions.first).to include('decision' => 'denied', 'reason' => 'missing_act')
      end
    end

    context 'when the token lacks the required scope' do
      before { stub_introspection(active_introspection.merge(scope: 'token_exchange:records_write')) }

      it 'returns 403 insufficient_scope naming the scope' do
        get_records

        expect(last_response.status).to eq 403
        expect(last_response.headers['WWW-Authenticate']).to include('error="insufficient_scope"')
        expect(last_response.headers['WWW-Authenticate']).to include('scope="token_exchange:records_read"')
        expect(JSON.parse(last_response.body)['error']).to eq 'insufficient_scope'
        expect(decisions.first).to include('decision' => 'denied', 'reason' => 'insufficient_scope')
      end

      it 'does not match on a prefix or substring of the scope value' do
        stub_introspection(active_introspection.merge(scope: 'token_exchange:records_readonly records_read'))

        get_records

        expect(last_response.status).to eq 403
      end
    end

    context 'when an ID token is presented instead of a delegated token' do
      let(:token) do
        JWT.encode({ iss: host, aud: 'urn:gov:gsa:openidconnect:sp:sinatra_sts', sub: 'x', nonce: 'n' }, 'secret', 'HS256')
      end

      it 'returns 401 without introspecting' do
        get_records

        expect(last_response.status).to eq 401
        expect(last_response.headers['WWW-Authenticate']).to include('error="invalid_token"')
        expect(a_request(:post, introspection_endpoint)).not_to have_been_made
        expect(decisions.first).to include('reason' => 'id_token_presented')
      end
    end

    context 'when introspection fails' do
      it 'fails closed with 503 on a 500 from Login.gov' do
        stub_introspection('', status: 500)

        get_records

        expect(last_response.status).to eq 503
        expect(JSON.parse(last_response.body)['error']).to eq 'temporarily_unavailable'
        expect(decisions.first).to include('decision' => 'unavailable', 'reason' => 'introspection_failed')
      end

      it 'fails closed with 503 on a 401 (this resource server is not registered)' do
        stub_introspection({ error: 'invalid_client' }, status: 401)

        get_records

        expect(last_response.status).to eq 503
      end

      it 'fails closed with 503 on a timeout' do
        stub_request(:post, introspection_endpoint).to_timeout

        get_records

        expect(last_response.status).to eq 503
        expect(decisions.first).to include('decision' => 'unavailable')
      end

      it 'fails closed with 503 on a non-JSON body' do
        stub_introspection('<html>oops</html>')

        get_records

        expect(last_response.status).to eq 503
      end
    end

    context 'when discovery does not advertise introspection_endpoint (IdP flag off)' do
      let(:discovery) { super().except(:introspection_endpoint) }

      it 'returns 503 with a clear message' do
        get_records

        expect(last_response.status).to eq 503
        body = JSON.parse(last_response.body)
        expect(body['error']).to eq 'temporarily_unavailable'
        expect(body['error_description']).to include('introspection_endpoint')
        expect(decisions.first).to include('reason' => 'introspection_not_advertised')
      end
    end

    context 'when the IdP discovery document is unreachable' do
      before do
        stub_request(:get, "#{host}/.well-known/openid-configuration").to_return(status: 500, body: '')
      end

      it 'returns 503 and says discovery, not the feature flag, is the problem' do
        get_records

        expect(last_response.status).to eq 503
        expect(JSON.parse(last_response.body)['error_description']).to include('discovery')
        expect(decisions.first).to include('decision' => 'unavailable', 'reason' => 'discovery_unavailable')
      end
    end
  end

  describe 'POST /records' do
    it 'creates a record when the token carries records_write' do
      stub_introspection(
        active_introspection.merge(scope: 'token_exchange:records_read token_exchange:records_write'),
      )
      header 'Authorization', "Bearer #{token}"
      header 'Content-Type', 'application/json'
      post '/records', { title: 'Fictional filing', note: 'demo' }.to_json

      expect(last_response.status).to eq 201
      body = JSON.parse(last_response.body)
      expect(body['record']).to include('title' => 'Fictional filing', 'fictional' => true)
      expect(body['_introspection']['act']['sub']).to eq actor
      expect(decisions.first).to include('route' => 'POST /records', 'decision' => 'allowed',
                                          'required_scope' => 'token_exchange:records_write')

      header 'Content-Type', nil
      get_records
      expect(JSON.parse(last_response.body)['records'].map { |r| r['title'] }).to include('Fictional filing')
    end

    it 'refuses a read-only delegation with 403 insufficient_scope' do
      stub_introspection(active_introspection)
      header 'Authorization', "Bearer #{token}"
      post '/records', title: 'Should not be written'

      expect(last_response.status).to eq 403
      expect(JSON.parse(last_response.body)['error']).to eq 'insufficient_scope'
    end

    it 'rejects a malformed JSON body with 400' do
      stub_introspection(active_introspection.merge(scope: 'token_exchange:records_write'))
      header 'Authorization', "Bearer #{token}"
      header 'Content-Type', 'application/json'
      post '/records', '{not json'

      expect(last_response.status).to eq 400
    end
  end

  describe 'GET /decisions' do
    it 'shows every decision with actor and delegation_id' do
      stub_introspection(active_introspection)
      get_records
      stub_request(:post, introspection_endpoint).
        with(body: hash_including('token' => 'some-other-token')).
        to_return(body: { active: false }.to_json)
      get_records(bearer: 'some-other-token')

      get '/decisions'

      expect(last_response).to be_ok
      doc = Nokogiri::HTML(last_response.body)
      rows = doc.css('tbody tr')
      expect(rows.length).to eq 2
      expect(last_response.body).to include(actor)
      expect(last_response.body).to include(delegation_id)
      expect(last_response.body).to include('allowed')
      expect(last_response.body).to include('invalid_token')
      expect(last_response.body).not_to include(token)
    end

    it 'exposes the same log as JSON' do
      stub_introspection(active_introspection)
      get_records

      get '/decisions.json'

      expect(JSON.parse(last_response.body)['decisions'].first).to include('decision' => 'allowed')
    end
  end
end

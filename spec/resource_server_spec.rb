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
  let(:userinfo_endpoint) { "#{host}/api/openid_connect/userinfo" }
  # The identity claims Login.gov puts in an active introspection response for a
  # delegated token: the same names and formats userinfo returns for a direct
  # sign-in, limited to the agency's attribute bundle.
  let(:identity_claims) do
    {
      sub: 'agency-pairwise-sub-1',
      iss: host,
      email: 'demo.user@example.com',
      email_verified: true,
      all_emails: ['demo.user@example.com'],
      given_name: 'Fakey',
      family_name: 'McFakerson',
      birthdate: '1938-10-06',
      social_security_number: '900-12-3456',
      address: {
        formatted: "1 Fictional Way\nWashington, DC 20001",
        street_address: '1 Fictional Way',
        locality: 'Washington',
        region: 'DC',
        postal_code: '20001',
      },
      phone: '+12025550123',
      phone_verified: true,
      verified_at: 1_700_000_000,
      ial: 'urn:acr.login.gov:verified',
      aal: 'urn:gov:gsa:ac:classes:sp:PasswordProtectedTransport:duo',
    }
  end
  let(:token_members) do
    {
      active: true,
      aud: resource_identifier,
      scope: 'token_exchange:records_read',
      act: { sub: actor },
      client_id: actor,
      acr: 'urn:acr.login.gov:verified',
      iat: Time.now.to_i - 5,
      exp: Time.now.to_i + 800,
      delegation_id: delegation_id,
      token_type: 'Bearer',
    }
  end
  let(:active_introspection) { token_members.merge(identity_claims) }
  # After the user's Login.gov session ends Login.gov releases identifiers and
  # email only and says so.
  let(:identifiers_only_introspection) do
    token_members.merge(
      identity_claims.slice(:sub, :iss, :email, :email_verified, :all_emails),
      attributes: 'identifiers_only',
    )
  end
  let(:rs_public_key) { OpenSSL::PKey::RSA.new(File.read('config/rs_demo.key')).public_key }

  before do
    allow_any_instance_of(LoginGov::OidcSinatra::Config).to receive(:cache_oidc_config?).and_return(false)
    stub_request(:get, "#{host}/.well-known/openid-configuration").to_return(body: discovery.to_json)
    # Userinfo would answer if asked; the resource server must never ask with a
    # delegated token.
    stub_request(:get, userinfo_endpoint).to_return(body: identity_claims.to_json)
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

  def get_records(bearer: token, scheme: 'Bearer', dpop: nil)
    header 'Authorization', "#{scheme} #{bearer}" if bearer
    header 'DPoP', dpop if dpop
    get '/records'
  end

  # --- RFC 9449 DPoP fixtures: a key the token is bound to, and proofs for this request ---
  let(:dpop_key) { OpenSSL::PKey::EC.generate('prime256v1') }
  let(:dpop_jwk) { JWT::JWK.new(dpop_key).export.transform_keys(&:to_s).except('kid') }
  let(:dpop_jkt) { LoginGov::OidcSinatra::DpopVerifier.thumbprint(dpop_jwk) }
  let(:bound_introspection) do
    active_introspection.merge(token_type: 'DPoP', cnf: { jkt: dpop_jkt })
  end
  let(:records_url) { 'http://example.org/records' }

  def dpop_proof(htm: 'GET', htu: records_url, iat: Time.now.to_i, jti: SecureRandom.uuid,
                 ath: LoginGov::OidcSinatra::DpopVerifier.access_token_hash(token),
                 key: dpop_key, jwk: dpop_jwk, alg: 'ES256')
    JWT.encode({ jti:, htm:, htu:, iat:, ath: }.compact, key, alg, { typ: 'dpop+jwt', jwk: })
  end

  def dpop_challenge
    last_response.headers['WWW-Authenticate']
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

      it 'returns the identity claims from introspection as userinfo would return them for a direct sign-in' do
        get_records

        claims = JSON.parse(last_response.body)['claims']
        expect(claims).to include(
          'sub' => 'agency-pairwise-sub-1',
          'iss' => host,
          'email' => 'demo.user@example.com',
          'email_verified' => true,
          'all_emails' => ['demo.user@example.com'],
          'given_name' => 'Fakey',
          'family_name' => 'McFakerson',
          'birthdate' => '1938-10-06',
          'address' => include('street_address' => '1 Fictional Way', 'postal_code' => '20001'),
          'phone' => '+12025550123',
          'phone_verified' => true,
          'verified_at' => 1_700_000_000,
          'ial' => 'urn:acr.login.gov:verified',
        )
        expect(claims.keys).not_to include('active', 'aud', 'scope', 'act', 'client_id', 'acr',
                                           'iat', 'exp', 'delegation_id', 'token_type')
      end

      it 'redacts the SSN the same way the direct sign-in page does' do
        get_records

        body = JSON.parse(last_response.body)
        expect(body['claims']['social_security_number']).to eq '###-##-####'
        expect(last_response.body).not_to include('900-12-3456')
      end

      it 'shows the SSN when redaction is turned off, like the direct sign-in page' do
        allow_any_instance_of(LoginGov::OidcSinatra::Config).to receive(:redact_ssn?).and_return(false)

        get_records

        expect(JSON.parse(last_response.body)['claims']['social_security_number']).to eq '900-12-3456'
      end

      it 'keeps identity attributes out of the echoed _introspection (identifiers only)' do
        get_records

        echoed = JSON.parse(last_response.body)['_introspection']
        expect(echoed.keys).to match_array(
          %w[active aud scope sub act client_id acr iat exp delegation_id token_type],
        )
        expect(echoed.keys).not_to include('email', 'given_name', 'social_security_number', 'address')
      end

      it 'does not mark a full response as identifiers only' do
        get_records

        body = JSON.parse(last_response.body)
        expect(body).not_to have_key('attributes')
        expect(body).not_to have_key('notice')
      end

      it 'never calls userinfo with a delegated token' do
        get_records

        expect(last_response.status).to eq 200
        expect(a_request(:get, userinfo_endpoint)).not_to have_been_made
        expect(a_request(:any, userinfo_endpoint)).not_to have_been_made
      end

      it 'serves the cached claims within the cache window without asking Login.gov again' do
        get_records
        first = JSON.parse(last_response.body)['claims']
        get_records
        second = JSON.parse(last_response.body)['claims']

        expect(first).to include('given_name' => 'Fakey', 'email' => 'demo.user@example.com')
        expect(second).to eq first
        expect(stub).to have_been_requested.once
        expect(a_request(:get, userinfo_endpoint)).not_to have_been_made
      end

      it 'logs the redacted claims with the decision' do
        get_records

        expect(decisions.first['claims']).to include(
          'given_name' => 'Fakey', 'social_security_number' => '###-##-####',
        )
        expect(decisions.first['claims'].keys).not_to include('scope', 'act', 'delegation_id')
        expect(decisions.first['attributes']).to be_nil
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

    context "when the user's Login.gov session has ended (attributes: identifiers_only)" do
      let!(:stub) { stub_introspection(identifiers_only_introspection) }

      it 'serves the records with identifiers and email only and says why' do
        get_records

        expect(last_response.status).to eq 200
        body = JSON.parse(last_response.body)
        expect(body['records']).not_to be_empty
        expect(body['claims']).to include(
          'sub' => 'agency-pairwise-sub-1', 'iss' => host, 'email' => 'demo.user@example.com',
        )
        expect(body['claims'].keys).not_to include('given_name', 'family_name', 'birthdate',
                                                   'social_security_number', 'address', 'phone')
        expect(body['attributes']).to eq 'identifiers_only'
        expect(body['notice']).to include('Login.gov session has ended')
        expect(body['notice']).to include('send the user back through Login.gov')
        expect(body['_introspection']).to include('attributes' => 'identifiers_only')
      end

      it 'does not try userinfo to fill in the missing attributes' do
        get_records

        expect(a_request(:any, userinfo_endpoint)).not_to have_been_made
      end

      it 'records identifiers_only with the decision' do
        get_records

        expect(decisions.first).to include('decision' => 'allowed', 'attributes' => 'identifiers_only')
        expect(decisions.first['claims'].keys).to match_array(%w[sub iss email email_verified all_emails])
      end
    end

    context 'without a bearer token' do
      it 'returns 401 with a bare Bearer challenge and does not call Login.gov' do
        get_records(bearer: nil)

        expect(last_response.status).to eq 401
        expect(last_response.headers['WWW-Authenticate']).to start_with('Bearer realm=')
        expect(last_response.headers['WWW-Authenticate']).not_to include('error=')
        # RFC 9449 §7.1: the challenge also says key-bound tokens are accepted and with which algs.
        expect(last_response.headers['WWW-Authenticate']).to include('DPoP algs="ES256 RS256"')
        expect(a_request(:post, introspection_endpoint)).not_to have_been_made
        expect(decisions.first).to include('decision' => 'denied', 'reason' => 'missing_token')
      end

      it 'ignores tokens sent as a query parameter' do
        get "/records?access_token=#{token}"

        expect(last_response.status).to eq 401
      end
    end


    # RFC 9449 — a token Login.gov bound to a key (introspection carries cnf.jkt).
    context 'with a key-bound token (introspection returns cnf.jkt)' do
      before do
        stub_introspection(bound_introspection)
        LoginGov::OidcSinatra::DpopReplayCache.instance.clear
      end

      it 'serves the records when presented as DPoP with a valid proof for this request' do
        get_records(scheme: 'DPoP', dpop: dpop_proof)

        expect(last_response.status).to eq 200
        expect(decisions.first).to include('decision' => 'allowed', 'bound_key' => dpop_jkt)
      end

      it 'verifies the proof on every request, even when the introspection result is cached' do
        get_records(scheme: 'DPoP', dpop: dpop_proof)
        expect(last_response.status).to eq 200

        get_records(scheme: 'DPoP', dpop: dpop_proof(ath: 'wrong'))
        expect(last_response.status).to eq 401
        expect(dpop_challenge).to eq 'DPoP algs="ES256 RS256", error="invalid_dpop_proof"'
        expect(a_request(:post, introspection_endpoint)).to have_been_made.once
      end

      it 'refuses the token presented as Bearer: 401 invalid_token with a DPoP challenge' do
        get_records(scheme: 'Bearer')

        expect(last_response.status).to eq 401
        expect(dpop_challenge).to eq 'DPoP algs="ES256 RS256", error="invalid_token"'
        expect(JSON.parse(last_response.body)['error']).to eq 'invalid_token'
        expect(decisions.first).to include('decision' => 'denied', 'reason' => 'dpop_scheme_required')
      end

      it 'refuses the DPoP scheme without a DPoP header' do
        get_records(scheme: 'DPoP')

        expect(last_response.status).to eq 401
        expect(dpop_challenge).to eq 'DPoP algs="ES256 RS256", error="invalid_dpop_proof"'
        expect(JSON.parse(last_response.body)['error']).to eq 'invalid_dpop_proof'
        expect(decisions.first).to include('decision' => 'denied', 'reason' => 'invalid_dpop_proof')
      end

      {
        'ath for another token' => -> { dpop_proof(ath: LoginGov::OidcSinatra::DpopVerifier.access_token_hash('other')) },
        'htu for another URL' => -> { dpop_proof(htu: 'http://example.org/other') },
        'htm for another method' => -> { dpop_proof(htm: 'POST') },
        'stale iat' => -> { dpop_proof(iat: Time.now.to_i - 120) },
        'a key other than the one the token is bound to' => lambda {
          other = OpenSSL::PKey::EC.generate('prime256v1')
          dpop_proof(key: other, jwk: JWT::JWK.new(other).export.transform_keys(&:to_s).except('kid'))
        },
        'private members in jwk' => lambda {
          dpop_proof(jwk: JWT::JWK.new(dpop_key).export(include_private: true).transform_keys(&:to_s).except('kid'))
        },
        'alg none' => -> { dpop_proof(key: nil, alg: 'none') },
        'HS256' => -> { dpop_proof(key: 'secret', alg: 'HS256') },
      }.each do |description, build_proof|
        it "refuses a proof with #{description}: 401 invalid_dpop_proof" do
          get_records(scheme: 'DPoP', dpop: instance_exec(&build_proof))

          expect(last_response.status).to eq 401
          expect(dpop_challenge).to eq 'DPoP algs="ES256 RS256", error="invalid_dpop_proof"'
          expect(decisions.first).to include('reason' => 'invalid_dpop_proof')
        end
      end

      it 'refuses a replayed proof' do
        proof = dpop_proof
        get_records(scheme: 'DPoP', dpop: proof)
        expect(last_response.status).to eq 200

        get_records(scheme: 'DPoP', dpop: proof)
        expect(last_response.status).to eq 401
        expect(JSON.parse(last_response.body)['error_description']).to include('jti')
      end

      it 'still checks scope before the proof' do
        stub_introspection(bound_introspection.merge(scope: 'token_exchange:records_write'))
        get_records(scheme: 'DPoP', dpop: dpop_proof)

        expect(last_response.status).to eq 403
      end
    end

    context 'with an unbound token (no cnf) presented with the DPoP scheme' do
      before { stub_introspection(active_introspection) }

      it 'returns 401 invalid_token with a DPoP challenge' do
        get_records(scheme: 'DPoP', dpop: dpop_proof)

        expect(last_response.status).to eq 401
        expect(dpop_challenge).to eq 'DPoP algs="ES256 RS256", error="invalid_token"'
        expect(decisions.first).to include('decision' => 'denied', 'reason' => 'dpop_not_bound')
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

      it 'is observed, not rejected: the call proceeds on scope alone' do
        get_records

        expect(last_response.status).to eq 200
        expect(decisions.first).to include('decision' => 'allowed', 'actor' => nil)
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
      expect(body['claims']).to include('given_name' => 'Fakey', 'social_security_number' => '###-##-####')
      expect(body['_introspection']).not_to have_key('given_name')
      expect(a_request(:any, userinfo_endpoint)).not_to have_been_made
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

    it 'shows the identity claims from introspection with the SSN redacted' do
      stub_introspection(active_introspection)
      get_records

      get '/decisions'

      expect(last_response).to be_ok
      doc = Nokogiri::HTML(last_response.body)
      claims = doc.at_css('tbody tr .identity-claims')
      expect(claims).not_to be_nil
      expect(claims.text).to include('"given_name": "Fakey"')
      expect(claims.text).to include('"email": "demo.user@example.com"')
      expect(claims.text).to include('"social_security_number": "###-##-####"')
      expect(claims.text).to include('"address"')
      expect(last_response.body).not_to include('900-12-3456')
      expect(doc.at_css('tbody tr td:last-child').text).not_to include('identifiers_only')
      expect(a_request(:any, userinfo_endpoint)).not_to have_been_made
    end

    it 'renders the claims with the same partial the direct sign-in page uses' do
      stub_introspection(active_introspection)
      get_records
      get '/decisions'
      from_introspection = Nokogiri::HTML(last_response.body).at_css('.identity-claims ul').text.strip

      # Direct sign-in: the same claims arrive from userinfo (parsed JSON) and land in the session.
      get '/', {}, 'rack.session' => { userinfo: JSON.parse(identity_claims.to_json) }
      from_userinfo = Nokogiri::HTML(last_response.body).at_css('.identity-claims ul').text.strip

      expect(from_introspection).to eq from_userinfo
    end

    it "explains identifiers only when the user's Login.gov session had ended" do
      stub_introspection(identifiers_only_introspection)
      get_records

      get '/decisions'

      doc = Nokogiri::HTML(last_response.body)
      cell = doc.at_css('tbody tr td:last-child')
      expect(cell.text).to include('identifiers_only')
      expect(cell.text).to include('Login.gov session has ended')
      expect(cell.text).to include('send the user back through Login.gov')
      expect(cell.text).to include('"email": "demo.user@example.com"')
      expect(cell.text).not_to include('given_name')
    end

    it 'shows no claims for a decision made without an active token' do
      stub_introspection({ active: false })
      get_records

      get '/decisions'

      cell = Nokogiri::HTML(last_response.body).at_css('tbody tr td:last-child')
      expect(cell.text).to include('none')
    end

    it 'exposes the same log as JSON' do
      stub_introspection(active_introspection)
      get_records

      get '/decisions.json'

      decision = JSON.parse(last_response.body)['decisions'].first
      expect(decision).to include('decision' => 'allowed')
      expect(decision['claims']).to include('given_name' => 'Fakey', 'social_security_number' => '###-##-####')
    end
  end
end

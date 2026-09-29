require 'spec_helper'
require 'nokogiri'

RSpec.describe LoginGov::OidcSinatra::OpenidConnectRelyingParty, 'agency-role Attempts viewer' do
  let(:host) { 'http://localhost:3000' }
  let(:poll_url) { "#{host}/api/attempts/poll" }
  let(:agency_issuer) { 'urn:gov:gsa:openidconnect:sp:records_agency' }
  let(:shared_secret) { 'records-agency-attempts-secret' }
  let(:actor) { 'urn:gov:gsa:openidconnect:sp:sinatra_sts' }
  let(:delegation_id) { 'a1b2c3d4-0000-4000-8000-000000000001' }
  let(:other_delegation_id) { 'a1b2c3d4-0000-4000-8000-000000000002' }
  let(:rs_public_key) { OpenSSL::PKey::RSA.new(File.read('config/rs_demo.key')).public_key }
  let(:schema) { 'https://schemas.login.gov/secevent/attempts-api/event-type' }

  def event(jti:, iat:, type:, **data)
    {
      'jti' => jti,
      'iat' => iat,
      'iss' => "#{host}/",
      'aud' => agency_issuer,
      'events' => { "#{schema}/#{type}" => data },
    }
  end

  def encrypt(event)
    JWE.encrypt(event.to_json, rs_public_key, alg: 'RSA-OAEP', enc: 'A256GCM', zip: 'DEF')
  end

  let(:events) do
    [
      event(jti: 'jti-1', iat: 1_800_000_000, type: 'login-completed',
            user_uuid: 'agency-pairwise-sub-1', success: true, delegation_id: delegation_id,
            application_url: 'http://localhost:9292/auth/result'),
      event(jti: 'jti-2', iat: 1_800_000_010, type: 'delegated-access-consented',
            user_uuid: 'agency-pairwise-sub-1', actor_issuer: actor,
            scopes: ['token_exchange:records_read'],
            resources: ['https://records-api.agency.localdev'], remembered: false,
            delegation_id: delegation_id),
      event(jti: 'jti-3', iat: 1_800_000_020, type: 'delegated-access-token-issued',
            user_uuid: 'agency-pairwise-sub-1', actor_issuer: actor,
            resource: 'https://records-api.agency.localdev', scopes: ['token_exchange:records_read'],
            ial: 2, aal: 2, token_format: 'oauth', delegation_id: delegation_id),
      event(jti: 'jti-4', iat: 1_800_000_030, type: 'delegated-access-revoked',
            user_uuid: 'agency-pairwise-sub-2', reason: 'refresh_token_reuse',
            delegation_id: other_delegation_id),
      event(jti: 'jti-5', iat: 1_800_000_040, type: 'mfa-submission-code-verified',
            user_uuid: 'agency-pairwise-sub-3', success: true, email: 'direct-user@example.com'),
    ]
  end

  before do
    ENV['attempts_shared_secret'] = shared_secret
    ENV['allow_all_events_plaintext'] = 'false'
    ENV['signed_events'] = 'false'
    allow_any_instance_of(LoginGov::OidcSinatra::Config).to receive(:cache_oidc_config?).and_return(false)
    stub_request(:get, "#{host}/.well-known/openid-configuration").
      to_return(body: { end_session_endpoint: "#{host}/openid_connect/logout" }.to_json)
    LoginGov::OidcSinatra::DecisionLog.instance.clear

    sets = events.each_with_object({}) { |e, h| h[e['jti']] = encrypt(e) }
    stub_request(:post, poll_url).
      with(query: { maxEvents: 100 }, headers: { 'Authorization' => "Bearer #{agency_issuer} #{shared_secret}" }).
      to_return(body: { sets: }.to_json)
  end

  describe 'GET /attempts-api' do
    it 'polls once with the agency credentials and decrypts events with the agency key' do
      get '/attempts-api'

      expect(last_response).to be_ok
      expect(a_request(:post, poll_url).with(query: { maxEvents: 100 })).to have_been_made.once
      doc = Nokogiri::HTML(last_response.body)
      expect(doc.css('tbody tr').length).to eq 5
      expect(last_response.body).to include('delegated-access-consented')
      expect(last_response.body).to include('delegated-access-token-issued')
      expect(last_response.body).to include('delegated-access-revoked')
    end

    it 'shows the delegation fields in plaintext and redacts the rest' do
      get '/attempts-api'

      expect(last_response.body).to include(delegation_id)
      expect(last_response.body).to include(actor)
      expect(last_response.body).to include('token_exchange:records_read')
      expect(last_response.body).to include('refresh_token_reuse')
      expect(last_response.body).to include('&quot;token_format&quot;: &quot;oauth&quot;')
      expect(last_response.body).to include('&quot;remembered&quot;: false')
      expect(last_response.body).not_to include('direct-user@example.com')
      expect(last_response.body).not_to include('agency-pairwise-sub-1')
    end

    it 'marks delegated events' do
      get '/attempts-api'

      doc = Nokogiri::HTML(last_response.body)
      expect(doc.css('tbody tr').count { |tr| tr.text.include?('delegated') }).to eq 4
    end

    it 'renders an error when the Attempts API refuses the credentials' do
      stub_request(:post, poll_url).with(query: { maxEvents: 100 }).to_return(status: 401, body: 'unauthorized')

      get '/attempts-api'
      follow_redirect!

      expect(last_response.body).to include('Attempts API error')
    end
  end

  describe 'GET /attempts-api?tab=delegated' do
    before do
      introspection = {
        'active' => true, 'sub' => 'agency-pairwise-sub-1', 'act' => { 'sub' => actor },
        'client_id' => actor, 'scope' => 'token_exchange:records_read',
        'aud' => 'https://records-api.agency.localdev', 'delegation_id' => delegation_id,
      }
      LoginGov::OidcSinatra::DecisionLog.instance.record(
        introspection:, route: 'GET /records', decision: 'allowed', required_scope: 'token_exchange:records_read',
      )
      LoginGov::OidcSinatra::DecisionLog.instance.record(
        introspection: introspection.merge('scope' => 'token_exchange:records_read'),
        route: 'POST /records', decision: 'denied', reason: 'insufficient_scope',
        required_scope: 'token_exchange:records_write'
      )
      LoginGov::OidcSinatra::DecisionLog.instance.record(
        introspection: introspection.merge('delegation_id' => 'decision-only-delegation'),
        route: 'GET /records', decision: 'allowed'
      )
    end

    it 'groups events by delegation_id and lists the API decisions beneath each' do
      get '/attempts-api?tab=delegated'

      expect(last_response).to be_ok
      doc = Nokogiri::HTML(last_response.body)
      sessions = doc.css('.usa-summary-box')
      expect(sessions.length).to eq 3

      main = sessions.find { |s| s.at_css('h2').text.include?(delegation_id) }
      expect(main.text).to include(actor)
      expect(main.text).to include('3 event(s)')
      expect(main.text).to include('2 API decision(s)')
      expect(main.text).to include('login-completed')
      expect(main.text).to include('delegated-access-consented')
      expect(main.text).to include('GET /records')
      expect(main.text).to include('POST /records')
      expect(main.text).to include('insufficient_scope')
      expect(main.text).not_to include('delegated-access-revoked')

      revoked = sessions.find { |s| s.at_css('h2').text.include?(other_delegation_id) }
      expect(revoked.text).to include('delegated-access-revoked')
      expect(revoked.text).to include('No API calls yet')

      decision_only = sessions.find { |s| s.at_css('h2').text.include?('decision-only-delegation') }
      expect(decision_only.text).to include('No Attempts events received')
      expect(decision_only.text).to include('GET /records')
    end

    it 'leaves direct (non-delegated) events out of the delegated view' do
      get '/attempts-api?tab=delegated'

      expect(last_response.body).not_to include('mfa-submission-code-verified')
    end

    it 'explains the new event types' do
      get '/attempts-api?tab=delegated'

      expect(last_response.body).to include('remembered grant was reused')
      expect(last_response.body).to include('token family was revoked')
    end
  end

  describe 'POST /ack-events' do
    it 'acknowledges the given jtis' do
      ack_stub = stub_request(:post, poll_url).
        with(query: { maxEvents: 100, ack: %w[jti-1 jti-2] }).
        to_return(body: { sets: {} }.to_json)

      get '/attempts-api'
      post '/ack-events', jtis: 'jti-1,jti-2', authenticity_token: last_request.session[:csrf]

      expect(last_response).to be_redirect
      expect(ack_stub).to have_been_requested.once
    end
  end
end

require 'spec_helper'
require 'cgi'

# Relying-party side of OpenID Connect Third-Party-Initiated Login
# (OpenID Connect Core 1.0 §4,
# https://openid.net/specs/openid-connect-core-1_0.html#ThirdPartyInitiatedLogin):
# the /initiate_login endpoint and the return to target_link_uri after sign-in.
RSpec.describe LoginGov::OidcSinatra::OpenidConnectRelyingParty do
  let(:host) { 'http://localhost:3000' }
  let(:authorization_endpoint) { "#{host}/openid/authorize" }
  let(:token_endpoint) { "#{host}/api/openid/token" }
  let(:userinfo_endpoint) { "#{host}/api/openid/userinfo" }
  let(:jwks_endpoint) { "#{host}/api/openid_connect/certs" }
  let(:idp_private_key) { OpenSSL::PKey::RSA.new(read_fixture_file('idp.key')) }
  let(:client_id) { 'urn:gov:gsa:openidconnect:sp:records_agency' }

  # The third party in the reference setup is the America.gov app; its origin is
  # the default allow-list entry.
  let(:target_link_uri) { 'http://localhost:9292/third-party/return?task=passport' }
  let(:login_hint) { SecureRandom.uuid }
  let(:initiation) { { iss: host, login_hint:, target_link_uri: } }

  before do
    ENV['semantic_ial_values_enabled'] = 'false'
    ENV['PKCE'] = 'false'
    allow_any_instance_of(LoginGov::OidcSinatra::Config).to receive(:cache_oidc_config?).
      and_return(false)
    stub_request(:get, "#{host}/.well-known/openid-configuration").
      to_return(body: {
        authorization_endpoint:,
        token_endpoint:,
        userinfo_endpoint:,
        end_session_endpoint: "#{host}/openid/logout",
        jwks_uri: jwks_endpoint,
      }.to_json)
    stub_request(:get, jwks_endpoint).
      to_return(body: { keys: [{ alg: 'RS256', use: 'sig' }.merge(
        JWT::JWK.new(OpenSSL::PKey::RSA.new(read_fixture_file('idp.key.pub'))).export,
      )] }.to_json)
  end

  def query(url)
    CGI.parse(URI(url).query.to_s).transform_values(&:first)
  end

  describe 'GET /initiate_login' do
    it 'refuses a request without iss' do
      get '/initiate_login', initiation.except(:iss)

      expect(last_response.status).to eq(400)
      expect(last_response.body).to include('iss is required')
    end

    it 'refuses an iss other than the OpenID Provider this agency trusts' do
      get '/initiate_login', initiation.merge(iss: 'https://evil.example')

      expect(last_response.status).to eq(400)
      expect(last_response.body).to include('not the OpenID Provider this agency trusts')
      expect(last_request.session['third_party_target_link_uri']).to be_nil
    end

    it 'tolerates only a trailing slash difference on iss' do
      get '/initiate_login', initiation.merge(iss: "#{host}/")
      expect(last_response.status).to eq(302)
    end

    it 'refuses a target_link_uri outside the allow-list (open redirector)' do
      get '/initiate_login', initiation.merge(target_link_uri: 'https://evil.example/return')

      expect(last_response.status).to eq(400)
      expect(last_response.body).to include('not an allowed return location')
    end

    it 'matches the allow-list on origin only, not on a prefix of the host' do
      get '/initiate_login', initiation.merge(target_link_uri: 'http://localhost:9292.evil.example/')
      expect(last_response.status).to eq(400)

      get '/initiate_login', initiation.merge(target_link_uri: 'http://localhost:92920/')
      expect(last_response.status).to eq(400)
    end

    it 'refuses a relative or non-http target_link_uri' do
      get '/initiate_login', initiation.merge(target_link_uri: '/return')
      expect(last_response.status).to eq(400)

      get '/initiate_login', initiation.merge(target_link_uri: 'javascript:alert(1)')
      expect(last_response.status).to eq(400)
    end

    it 'refuses a missing target_link_uri' do
      get '/initiate_login', initiation.except(:target_link_uri)
      expect(last_response.status).to eq(400)
      expect(last_response.body).to include('target_link_uri is required')
    end

    it 'refuses an oversized login_hint' do
      get '/initiate_login', initiation.merge(login_hint: 'x' * 129)
      expect(last_response.status).to eq(400)
    end

    context 'with a valid request' do
      before { get '/initiate_login', initiation }

      it 'starts the agency’s own Login.gov sign-in with its usual parameters' do
        expect(last_response.status).to eq(302)
        location = last_response.location
        expect(location).to start_with(authorization_endpoint)

        params = query(location)
        expect(params['client_id']).to eq(client_id)
        expect(params['response_type']).to eq('code')
        expect(params['redirect_uri']).to eq('http://localhost:9393/auth/result')
        expect(params['state']).to eq(last_request.session['state'])
        expect(params['nonce']).to eq(last_request.session['nonce'])
        expect(params['prompt']).to eq('select_account')
        expect(params['scope'].split).to include('openid', 'email')
        # The agency signs the user in at its own level: identity-verified by default.
        expect(params['acr_values']).to include('ial/2')
      end

      it 'does not forward the hint to Login.gov; the hint has no meaning there' do
        expect(last_response.location).not_to include('login_hint')
        expect(last_response.location).not_to include(login_hint)
      end

      it 'remembers the hand-off in the session for this sign-in' do
        expect(last_request.session['third_party_login_hint']).to eq(login_hint)
        expect(last_request.session['third_party_target_link_uri']).to eq(target_link_uri)
      end
    end

    it 'accepts a request without a login_hint (it is optional in §4)' do
      get '/initiate_login', initiation.except(:login_hint)
      expect(last_response.status).to eq(302)
      expect(last_request.session['third_party_login_hint']).to be_nil
    end
  end

  describe 'returning the user after sign-in' do
    let(:code) { 'abc-code' }
    let(:bearer_token) { 'tok' }
    let(:email) { 'jane@example.gov' }

    def stub_token_response(id_token:)
      stub_request(:post, token_endpoint).
        with(body: hash_including(grant_type: 'authorization_code', code:)).
        to_return(body: { access_token: bearer_token, id_token: }.to_json)
    end

    def stub_userinfo_response
      stub_request(:get, userinfo_endpoint).
        with(headers: { 'Authorization' => "Bearer #{bearer_token}" }).
        to_return(body: { email: }.to_json)
    end

    def id_token_for(nonce)
      JWT.encode({ nonce: }, idp_private_key, 'RS256', kid: JWT::JWK.new(idp_private_key))
    end

    def complete_sign_in
      stub_token_response(id_token: id_token_for(last_request.session['nonce']))
      stub_userinfo_response
      get '/auth/result', { code:, state: last_request.session['state'] },
          'rack.session' => last_request.session
    end

    context 'after a third-party-initiated sign-in succeeds' do
      before do
        get '/initiate_login', initiation
        complete_sign_in
      end

      it 'sends the user to target_link_uri with the hint, this agency’s identifier and the status' do
        expect(last_response.status).to eq(302)
        returned = URI(last_response.location)
        expect("#{returned.scheme}://#{returned.host}:#{returned.port}#{returned.path}").
          to eq('http://localhost:9292/third-party/return')

        params = query(last_response.location)
        expect(params['task']).to eq('passport') # the third party's own query is preserved
        expect(params['login_hint']).to eq(login_hint)
        expect(params['iss']).to eq(client_id)
        expect(params['status']).to eq('signed_in')
      end

      it 'establishes the agency’s own session from Login.gov, not from the hint' do
        expect(last_request.session['email']).to eq(email)
        expect(last_request.session['userinfo']).to include('email' => email)
      end

      it 'consumes the hand-off so it is honored once' do
        expect(last_request.session['third_party_target_link_uri']).to be_nil
        expect(last_request.session['third_party_login_hint']).to be_nil

        # A second, ordinary sign-in in the same browser ends on the agency page.
        get '/auth/request', {}, 'rack.session' => last_request.session
        complete_sign_in
        expect(URI(last_response.location).path).to eq('/')
        expect(last_response.location).not_to include('status=')
      end

      it 'shows on the agency page that the session was third-party initiated' do
        get '/', {}, 'rack.session' => last_request.session
        expect(last_response.body).to include('third-party-initiated login')
        expect(last_response.body).to include('localhost')
        expect(last_response.body).to include(email)
      end
    end

    context 'when the third-party-initiated sign-in fails' do
      before { get '/initiate_login', initiation }

      it 'returns the user to target_link_uri with status=failed when Login.gov denies' do
        get '/auth/result', { error: 'access_denied' }, 'rack.session' => last_request.session

        params = query(last_response.location)
        expect(URI(last_response.location).host).to eq('localhost')
        expect(params['status']).to eq('failed')
        expect(params['login_hint']).to eq(login_hint)
        expect(last_request.session['third_party_target_link_uri']).to be_nil
      end

      it 'returns with status=failed on a state mismatch' do
        get '/auth/result', { code:, state: 'wrong' }, 'rack.session' => last_request.session
        expect(query(last_response.location)['status']).to eq('failed')
      end
    end

    it 'leaves an ordinary sign-in untouched when no hand-off is pending' do
      get '/auth/request'
      complete_sign_in

      expect(URI(last_response.location).path).to eq('/')
      expect(last_response.location).not_to include('login_hint')
    end
  end
end

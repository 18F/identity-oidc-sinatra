require 'spec_helper'
require 'nokogiri'
require 'securerandom'
require 'pry'

RSpec.describe LoginGov::OidcSinatra::OpenidConnectRelyingParty do
  let(:host) { 'http://localhost:3000' }
  let(:authorization_endpoint) { "#{host}/openid/authorize" }
  let(:token_endpoint) { "#{host}/api/openid/token" }
  let(:jwks_uri) { "#{host}/api/openid/certs" }
  let(:end_session_endpoint) { "#{host}/openid/logout" }
  let(:client_id) { 'urn:gov:gsa:openidconnect:sp:sinatra' }

  before do
    stub_request(:get, "#{host}/.well-known/openid-configuration").
      to_return(body: {
        authorization_endpoint: authorization_endpoint,
        token_endpoint: token_endpoint,
        jwks_uri: jwks_uri,
        end_session_endpoint: end_session_endpoint,
      }.to_json)

    # use the default local dev config
    allow(LoginGov::Hostdata).to receive(:in_datacenter?).and_return(false)
  end

  context '/' do
    it 'renders a link to the authorize endpoint' do
      get '/'

      expect(last_response).to be_ok

      doc = Nokogiri::HTML(last_response.body)
      login_link = doc.at("a[href*='#{authorization_endpoint}']")

      auth_uri = URI(login_link[:href])
      auth_uri_params = Rack::Utils.parse_nested_query(auth_uri.query).with_indifferent_access

      expect(auth_uri_params[:redirect_uri]).to eq('http://localhost:9292/auth/result')
      expect(auth_uri_params[:client_id]).to_not be_empty
      expect(auth_uri_params[:client_id]).to eq(client_id)
      expect(auth_uri_params[:response_type]).to eq('code')
      expect(auth_uri_params[:prompt]).to eq('select_account')
      expect(auth_uri_params[:nonce].length).to be >= 32
      expect(auth_uri_params[:state].length).to be >= 32
    end

    it 'renders an error if basic auth credentials are wrong' do
      stub_request(:get, "#{host}/.well-known/openid-configuration").
        to_return(body: '', status: 401)

      get '/'

      expect(last_response.body).to include(
        'Perhaps we need to reimplement HTTP Basic Auth'
      )
    end

    it 'renders loa3 sign in link if loa param is 3' do
      get '/?loa=3'

      expect(last_response.body).to include(
        'scope=openid+email+profile+social_security_number+phone'
      )
    end

    it 'renders loa1 sign in link if loa param is 1' do
      get '/?loa=1'

      expect(last_response.body).to include(
        'scope=openid+email'
      )
      expect(last_response.body).to_not include(
        'scope=openid+email+profile+social_security_number+phone'
      )
    end

    it 'renders loa1 sign in link if loa param is nil' do
      get '/'

      expect(last_response.body).to include(
        'scope=openid+email'
      )
      expect(last_response.body).to_not include(
        'scope=openid+email+profile+social_security_number+phone'
      )
    end

    it 'renders an error if the app fails to get oidc configuration' do
      stub = stub_request(:get, "#{host}/.well-known/openid-configuration").
             to_return(body: '', status: 400)

      get '/'

      error_string = "Error: Unable to retrieve OIDC configuration from IdP. #{host} responded with 400."
      expect(last_response.body).to include(error_string)
      expect(stub).to have_been_requested.once
      expect(last_response.status).to eq 500
    end
  end

  context '/auth/result' do
    let(:code) { SecureRandom.uuid }

    let(:email) { 'foobar@bar.com' }
    let(:id_token) {
      JWT.encode(
        { email: email, acr: 'http://idmanagement.gov/ns/assurance/loa/1' },
        idp_private_key,
        'RS256'
      )
    }

    let(:idp_private_key) { OpenSSL::PKey::RSA.new(2048) }
    let(:idp_public_key) { idp_private_key.public_key }

    before do
      stub_request(:get, jwks_uri).
        to_return(body: {
          keys: [JSON::JWK.new(idp_public_key)],
        }.to_json)

      stub_request(:post, token_endpoint).
        with(
          body: {
            grant_type: 'authorization_code',
            code: code,
            client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            client_assertion: kind_of(String),
          }
        ).
        to_return(
          body: {
            id_token: id_token,
          }.to_json
        )
    end

    it 'takes an authorization code and gets a token, and renders the email from the token' do
      get '/auth/result', code: code

      expect(last_response.body).to include(email)
      expect(last_response.body).to include('LOA1')
    end

    context 'with dangerous input' do
      let(:email) { '<script>alert("hi")</script> mallory@bar.com' }

      it 'escapes dangerous HTML' do
        get '/auth/result', code: code

        expect(last_response.body).to_not include(email)
        expect(last_response.body).to include('&lt;script&gt;alert(&quot;hi&quot;)&lt;/script&gt; mallory@bar.com')
      end
    end

    it 'has a logout link back to the SP-initiated logout URL' do
      get '/auth/result', code: code

      doc = Nokogiri::HTML(last_response.body)

      logout_link = doc.at_xpath("//a[text()='Log out']")
      expect(logout_link).to be

      href = logout_link[:href]
      expect(href).to start_with(end_session_endpoint)
      expect(href).to include("id_token_hint=#{id_token}")
    end

    it 'renders an error message when there is one' do
      get '/auth/result', error: 'access_denied'

      doc = Nokogiri::HTML(last_response.body)

      expect(doc.text).to include('access_denied')
    end

    it 'renders a default error message when no code or explicit error code' do
      get '/auth/result'

      doc = Nokogiri::HTML(last_response.body)

      expect(doc.text).to include('missing callback param: code')
    end

    context 'LOA3 /auth/result' do
      let(:id_token) {
        JWT.encode(
          {
            email: email,
            acr: 'http://idmanagement.gov/ns/assurance/loa/3',
            social_security_number: '012-34-5678',
            phone: '0125551212',
          },
          idp_private_key,
          'RS256'
        )
      }

      it 'renders expected LOA3 data when redaction is not enabled' do
        # disable redaction
        expect_any_instance_of(LoginGov::OidcSinatra::Config).to receive(:redact_ssn?).at_least(:once).and_return(false)

        get '/auth/result', code: code

        expect(last_response.body).to include('012-34-5678')
        expect(last_response.body).to include('0125551212')
        expect(last_response.body).to include('LOA3')
      end

      it 'renders redacted SSN LOA3 data when redaction is enabled' do
        # enable redaction
        expect_any_instance_of(LoginGov::OidcSinatra::Config).to receive(:redact_ssn?).at_least(:once).and_return(true)

        get '/auth/result', code: code

        expect(last_response.body).to_not include('012-34-5678')
        expect(last_response.body).to include('###-##-####')
        expect(last_response.body).to include('0125551212')
        expect(last_response.body).to include('LOA3')
      end
    end

    context 'LOA3 /auth/result without SSN' do
      let(:id_token) {
        JWT.encode(
          {
            email: email,
            acr: 'http://idmanagement.gov/ns/assurance/loa/3',
            phone: '0125551212',
          },
          idp_private_key,
          'RS256'
        )
      }

      it 'handles nil SSN when redaction is enabled' do
        # enable redaction
        expect_any_instance_of(LoginGov::OidcSinatra::Config).to receive(:redact_ssn?).at_least(:once).and_return(true)

        get '/auth/result', code: code

        expect(last_response.body).to_not include('012-34-5678')
        expect(last_response.body).to_not include('###-##-####')
        expect(last_response.body).to include('0125551212')
        expect(last_response.body).to include('LOA3')
      end
    end
  end
end

require 'spec_helper'
require 'nokogiri'
require 'securerandom'

RSpec.describe OpenidConnectRelyingParty do
  let(:host) { 'http://localhost:3000' }
  let(:authorization_endpoint) { "#{host}/openid/authorize" }
  let(:token_endpoint) { "#{host}/api/openid/token" }
  let(:jwks_uri) { "#{host}/api/openid/certs" }
  let(:end_session_endpoint) { "#{host}/openid/logout" }

  before do
    stub_request(:get, "#{host}/.well-known/openid-configuration").
      with(basic_auth: ENV.values_at('IDP_USER', 'IDP_PASSWORD')).
      to_return(body: {
        authorization_endpoint: authorization_endpoint,
        token_endpoint: token_endpoint,
        jwks_uri: jwks_uri,
        end_session_endpoint: end_session_endpoint,
      }.to_json)
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
      expect(auth_uri_params[:client_id]).to eq(ENV['CLIENT_ID'])
      expect(auth_uri_params[:response_type]).to eq('code')
      expect(auth_uri_params[:prompt]).to eq('select_account')
      expect(auth_uri_params[:nonce].length).to be >= 32
      expect(auth_uri_params[:state].length).to be >= 32
    end

    it 'renders an error if basic auth credentials are wrong' do
      stub_request(:get, "#{host}/.well-known/openid-configuration").
        with(basic_auth: ENV.values_at('IDP_USER', 'IDP_PASSWORD')).
        to_return(body: '', status: 401)

      get '/'

      expect(last_response.body).to include(
        'Check basic authentication in IDP_USER and IDP_PASSSWORD environment variables.'
      )
    end

    it 'renders an error if the app fails to get oidc configuration' do
      stub_request(:get, "#{host}/.well-known/openid-configuration").
        with(basic_auth: ENV.values_at('IDP_USER', 'IDP_PASSWORD')).
        to_return(body: '', status: 400)

      get '/'
      error_string = "Error: #{ENV['IDP_SP_URL']} responded with 400."
      expect(last_response.body).to include(error_string)
    end
  end

  context '/auth/result' do
    let(:code) { SecureRandom.uuid }

    let(:email) { 'foobar@bar.com' }
    let(:id_token) { JWT.encode({ email: email }, idp_private_key, 'RS256') }

    let(:idp_private_key) { OpenSSL::PKey::RSA.new(2048) }
    let(:idp_public_key) { idp_private_key.public_key }

    before do
      stub_request(:get, jwks_uri).
        with(basic_auth: ENV.values_at('IDP_USER', 'IDP_PASSWORD')).
        to_return(body: {
          keys: [JSON::JWK.new(idp_public_key)],
        }.to_json)

      stub_request(:post, token_endpoint).
        with(
          basic_auth: ENV.values_at('IDP_USER', 'IDP_PASSWORD'),
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
  end
end

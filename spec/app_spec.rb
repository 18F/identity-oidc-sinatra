require 'spec_helper'
require 'nokogiri'
require 'securerandom'

RSpec.describe OpenidConnectRelyingParty do
  let(:host) { 'http://localhost:3000' }
  let(:authorization_endpoint) { "#{host}/openid/authorize" }
  let(:token_endpoint) { "#{host}/openid/token" }
  let(:jwks_uri) { "#{host}/openid/certs" }

  before do
    stub_request(:get, "#{host}/.well-known/openid-configuration").
      to_return(body: {
        authorization_endpoint: authorization_endpoint,
        token_endpoint: token_endpoint,
        jwks_uri: jwks_uri,
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
      expect(auth_uri_params[:response_type]).to eq('code')
      expect(auth_uri_params[:prompt]).to eq('select_account')
      expect(auth_uri_params[:nonce]).to be
      expect(auth_uri_params[:state]).to be
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
        to_return(body: {
          keys: [JSON::JWK.new(idp_public_key)],
        }.to_json)

      stub_request(:post, token_endpoint).
        with(body: {
          grant_type: 'authorization_code',
          code: code,
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
          client_assertion: kind_of(String),
        }).to_return(body: {
          id_token: id_token,
        }.to_json)
    end

    it 'takes an authorization code and gets a token, and renders the email from the token' do
      get '/auth/result', code: code

      expect(last_response.body).to include(email)
    end

    it 'has a logout link back to root, clicking it logs the user out' do
      get '/auth/result', code: code

      doc = Nokogiri::HTML(last_response.body)

      logout_link = doc.at('a[href="/"]')
      expect(logout_link.text.strip).to eq('Log out')

      get logout_link[:href]
      expect(last_response.body).to_not include(email)
    end
  end
end

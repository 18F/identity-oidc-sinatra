require 'spec_helper'

RSpec.describe LoginGov::OidcSinatra::OpenidConfiguration do
  let(:host) { 'http://localhost:3000' }
  let(:authorization_endpoint) { "#{host}/openid/authorize" }
  let(:token_endpoint) { "#{host}/api/openid/token" }
  let(:jwks_uri) { "#{host}/api/openid/certs" }
  let(:end_session_endpoint) { "#{host}/openid/logout" }
  let(:client_id) { 'urn:gov:gsa:openidconnect:sp:sinatra' }

  let(:configuration_uri) { "#{host}/.well-known/openid-configuration" }

  before do
    stub_request(:get, "#{host}/.well-known/openid-configuration").
      to_return(body: {
        authorization_endpoint: authorization_endpoint,
        token_endpoint: token_endpoint,
        jwks_uri: jwks_uri,
        end_session_endpoint: end_session_endpoint,
      }.to_json)
  end

  describe '#live' do
    it 'raises error if request fails' do
      stub_request(:get, "#{host}/.well-known/openid-configuration").
        to_return(body: '', status: 401)

      expect { LoginGov::OidcSinatra::OpenidConfiguration.live }.
        to raise_error(LoginGov::OidcSinatra::AppError)
    end
  end

  describe '#cached' do
    it 'does not make more than one HTTP request' do
      oidc_config = LoginGov::OidcSinatra::OpenidConfiguration.cached
      cached_oidc_config = LoginGov::OidcSinatra::OpenidConfiguration.cached
      expect(oidc_config).to eq cached_oidc_config
      expect(a_request(:get, configuration_uri)).to have_been_made.once
    end
  end
end

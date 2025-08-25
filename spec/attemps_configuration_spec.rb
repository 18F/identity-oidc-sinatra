require 'spec_helper'

RSpec.describe LoginGov::OidcSinatra::AttemptsConfiguration do
  let(:host) { 'http://localhost:3000' }
  let(:jwks_uri) { "#{host}/api/openid/certs" }

  let(:configuration_uri) { "#{host}/.well-known/ssf-configuration" }

  before do
    stub_request(:get, configuration_uri).
      to_return(body: {
        jwks_uri:,
      }.to_json)
  end

  describe '#live' do
    it 'raises error if request fails' do
      stub_request(:get, configuration_uri).
        to_return(body: '', status: 401)

      expect { LoginGov::OidcSinatra::AttemptsConfiguration.live }.
        to raise_error(LoginGov::OidcSinatra::AppError)
    end
  end

  describe '#cached' do
    it 'does not make more than one HTTP request' do
      oidc_config = LoginGov::OidcSinatra::AttemptsConfiguration.cached
      cached_oidc_config = LoginGov::OidcSinatra::AttemptsConfiguration.cached
      expect(oidc_config).to eq cached_oidc_config
      expect(a_request(:get, configuration_uri)).to have_been_made.once
    end
  end
end

require 'spec_helper'

RSpec.describe LoginGov::OidcSinatra::Config do
  describe '#session_cookie_key' do
    around do |example|
      previous_redirect_uri = ENV['redirect_uri']
      previous_session_cookie_key = ENV['session_cookie_key']
      example.run
    ensure
      ENV['redirect_uri'] = previous_redirect_uri
      ENV['session_cookie_key'] = previous_session_cookie_key
    end

    it 'uses the localhost port in the default cookie name' do
      ENV.delete('session_cookie_key')
      ENV['redirect_uri'] = 'http://localhost:9293/'

      expect(described_class.new.session_cookie_key).to eq('rack.session.9293')
    end

    it 'uses the default cookie name outside localhost' do
      ENV.delete('session_cookie_key')
      ENV['redirect_uri'] = 'https://agency.example.gov/'

      expect(described_class.new.session_cookie_key).to eq('rack.session')
    end

    it 'allows an explicit cookie name' do
      ENV['session_cookie_key'] = 'agency.session'
      ENV['redirect_uri'] = 'http://localhost:9293/'

      expect(described_class.new.session_cookie_key).to eq('agency.session')
    end
  end
end

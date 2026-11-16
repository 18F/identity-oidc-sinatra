require 'spec_helper'

RSpec.describe LoginGov::OidcSinatra::Target do
  describe '.from_config' do
    it 'builds a target from token exchange config' do
      target = described_class.from_config(
        'issuer' => 'state',
        'api' => 'https://api.example.gov/records',
      )

      expect(target.issuer).to eq('state')
      expect(target.api).to eq('https://api.example.gov/records')
      expect(target.resource).to eq('https://api.example.gov/records')
    end
  end
end

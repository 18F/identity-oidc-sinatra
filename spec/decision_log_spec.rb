require 'spec_helper'

RSpec.describe LoginGov::OidcSinatra::DecisionLog do
  subject(:log) { described_class.new(capacity: 3) }
  let(:introspection) do
    {
      'active' => true, 'sub' => 'sub-1', 'act' => { 'sub' => 'urn:sp' },
      'client_id' => 'urn:sp', 'delegation_id' => 'd-1', 'scope' => 'token_exchange:housing_records',
      'aud' => 'https://records-api.agency.localdev',
    }
  end

  it 'records the join fields from the introspection result' do
    entry = log.record(introspection:, route: 'GET /records', decision: 'allowed',
                       required_scope: 'token_exchange:housing_records')

    expect(entry).to include(
      'sub' => 'sub-1', 'actor' => 'urn:sp', 'delegation_id' => 'd-1',
      'scope' => 'token_exchange:housing_records', 'route' => 'GET /records', 'decision' => 'allowed'
    )
    expect(entry['time']).to match(/\A\d{4}-\d{2}-\d{2}T/)
  end

  it 'tolerates a nil introspection' do
    entry = log.record(introspection: nil, route: 'GET /records', decision: 'denied', reason: 'missing_token')

    expect(entry).to include('sub' => nil, 'actor' => nil, 'reason' => 'missing_token')
  end

  it 'keeps only the newest entries and returns them newest first' do
    4.times { |i| log.record(introspection: nil, route: "GET /#{i}", decision: 'denied') }

    expect(log.entries.map { |e| e['route'] }).to eq ['GET /3', 'GET /2', 'GET /1']
  end

  it 'finds decisions by delegation_id' do
    log.record(introspection:, route: 'GET /records', decision: 'allowed')
    log.record(introspection: introspection.merge('delegation_id' => 'd-2'), route: 'POST /records', decision: 'denied')

    expect(log.for_delegation('d-1').map { |e| e['route'] }).to eq ['GET /records']
    expect(log.for_delegation(nil)).to eq []
  end
end

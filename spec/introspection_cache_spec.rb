require 'spec_helper'

RSpec.describe LoginGov::OidcSinatra::IntrospectionCache do
  let(:now) { Time.at(1_800_000_000) }
  let(:clock) { -> { now } }
  subject(:cache) { described_class.new(clock: clock) }
  let(:active) { { 'active' => true, 'sub' => 'abc', 'exp' => now.to_i + 900 } }

  it 'returns nil for an unknown token' do
    expect(cache.fetch('tok')).to be_nil
  end

  it 'stores active results keyed by digest, never the plaintext token' do
    cache.store('tok', active, ttl_seconds: 60)

    expect(cache.fetch('tok')).to eq active
    expect(cache.instance_variable_get(:@entries).keys).to eq [Digest::SHA256.hexdigest('tok')]
  end

  it 'does not store inactive results' do
    cache.store('tok', { 'active' => false }, ttl_seconds: 60)

    expect(cache.fetch('tok')).to be_nil
    expect(cache.size).to eq 0
  end

  it 'expires entries after the ttl' do
    cache.store('tok', active, ttl_seconds: 60)
    later = now + 61
    later_cache = described_class.new(clock: -> { later })
    later_cache.instance_variable_set(:@entries, cache.instance_variable_get(:@entries))

    expect(later_cache.fetch('tok')).to be_nil
  end

  it 'never caches past the token exp' do
    soon = active.merge('exp' => now.to_i + 10)
    cache.store('tok', soon, ttl_seconds: 60)
    later = now + 11
    later_cache = described_class.new(clock: -> { later })
    later_cache.instance_variable_set(:@entries, cache.instance_variable_get(:@entries))

    expect(later_cache.fetch('tok')).to be_nil
  end

  it 'skips already-expired tokens' do
    cache.store('tok', active.merge('exp' => now.to_i - 1), ttl_seconds: 60)

    expect(cache.size).to eq 0
  end
end

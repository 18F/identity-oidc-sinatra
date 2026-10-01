require_relative 'spec_helper'
require_relative '../../lib/loadtest/cookie_jar'

RSpec.describe LoginGov::OidcSinatra::Loadtest::CookieJar do
  subject(:jar) { described_class.new }

  it 'returns nil when no cookies have been stored for a host' do
    expect(jar.header_for(host: 'localhost')).to be_nil
  end

  it 'replays a stored cookie back to the same host' do
    jar.store(host: 'localhost', set_cookie_values: ['_session=abc; path=/; HttpOnly'])

    expect(jar.header_for(host: 'localhost')).to eq('_session=abc')
  end

  it 'keeps the IdP and relying party sessions separate' do
    # Both applications name their session cookie independently and are reached
    # on different hosts; sharing a single namespace would let one clobber the
    # other mid-flow.
    jar.store(host: 'idp.example', set_cookie_values: ['_session=idp-value; path=/'])
    jar.store(host: 'rp.example', set_cookie_values: ['_session=rp-value; path=/'])

    expect(jar.header_for(host: 'idp.example')).to eq('_session=idp-value')
    expect(jar.header_for(host: 'rp.example')).to eq('_session=rp-value')
  end

  it 'overwrites a cookie when the server reissues it' do
    jar.store(host: 'localhost', set_cookie_values: ['_session=first; path=/'])
    jar.store(host: 'localhost', set_cookie_values: ['_session=second; path=/'])

    expect(jar.header_for(host: 'localhost')).to eq('_session=second')
  end

  it 'drops a cookie the server clears with an empty value' do
    jar.store(host: 'localhost', set_cookie_values: ['_session=abc; path=/'])
    jar.store(host: 'localhost', set_cookie_values: ['_session=; path=/; Max-Age=0'])

    expect(jar.header_for(host: 'localhost')).to be_nil
  end

  it 'sends every cookie a host has set' do
    jar.store(
      host: 'localhost',
      set_cookie_values: ['_session=abc; path=/', 'device=xyz; path=/'],
    )

    expect(jar.header_for(host: 'localhost')).to eq('_session=abc; device=xyz')
  end

  it 'tolerates a missing Set-Cookie header' do
    expect { jar.store(host: 'localhost', set_cookie_values: nil) }.not_to raise_error
    expect(jar.header_for(host: 'localhost')).to be_nil
  end

  it 'ignores malformed cookie strings rather than storing junk' do
    jar.store(host: 'localhost', set_cookie_values: ['', '   ', '; path=/'])

    expect(jar.header_for(host: 'localhost')).to be_nil
  end
end

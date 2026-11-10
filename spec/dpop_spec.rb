require 'spec_helper'

RSpec.describe LoginGov::OidcSinatra::Dpop do
  let(:key) { described_class.generate_key }
  let(:url) { 'https://api.agency-b.gov/records' }
  let(:token) { 'the-delegated-token' }
  let(:thumbprint) { described_class.thumbprint(key) }

  def verify(proof, **overrides)
    described_class.verify_proof(
      **{ proof:, method: 'GET', url:, access_token: token, expected_thumbprint: thumbprint }.merge(overrides),
    )
  end

  it 'builds a proof the verifier accepts and returns the key thumbprint' do
    proof = described_class.proof(key:, method: 'GET', url:, access_token: token)
    header = JWT.decode(proof, nil, false).last

    expect(header).to include('typ' => 'dpop+jwt', 'alg' => 'ES256')
    expect(header['jwk']).not_to have_key('d')
    expect(verify(proof)).to eq(thumbprint)
  end

  it 'matches htu without query, fragment, default port or trailing slash' do
    proof = described_class.proof(key:, method: 'GET', url: 'HTTPS://API.AGENCY-B.GOV:443/records/', access_token: token)
    expect(verify(proof, url: "#{url}?page=2#top")).to eq(thumbprint)
  end

  it 'refuses a proof signed by a key other than the bound one' do
    proof = described_class.proof(key: described_class.generate_key, method: 'GET', url:, access_token: token)
    expect { verify(proof) }.to raise_error(described_class::ProofError, /other than the one the token is bound to/)
  end

  it 'refuses a proof for another method, URL or token' do
    expect { verify(described_class.proof(key:, method: 'POST', url:, access_token: token)) }.
      to raise_error(described_class::ProofError, /htm/)
    expect { verify(described_class.proof(key:, method: 'GET', url: 'https://other.example.gov/records', access_token: token)) }.
      to raise_error(described_class::ProofError, /htu/)
    expect { verify(described_class.proof(key:, method: 'GET', url:, access_token: 'another-token')) }.
      to raise_error(described_class::ProofError, /ath/)
  end

  it 'refuses a stale proof' do
    proof = JWT.encode(
      { jti: 'x', htm: 'GET', htu: url, iat: Time.now.to_i - 600, ath: described_class.token_hash(token) },
      key, 'ES256', typ: 'dpop+jwt', jwk: described_class.public_jwk(key)
    )
    expect { verify(proof) }.to raise_error(described_class::ProofError, /iat/)
  end

  it 'refuses a missing proof, a wrong typ and a symmetric algorithm' do
    expect { verify(nil) }.to raise_error(described_class::ProofError, /missing/)
    wrong_typ = JWT.encode({ jti: 'x', htm: 'GET', htu: url, iat: Time.now.to_i }, key, 'ES256', typ: 'JWT', jwk: described_class.public_jwk(key))
    expect { verify(wrong_typ) }.to raise_error(described_class::ProofError, /typ/)
    hmac = JWT.encode({ jti: 'x', htm: 'GET', htu: url, iat: Time.now.to_i }, 'secret', 'HS256', typ: 'dpop+jwt')
    expect { verify(hmac) }.to raise_error(described_class::ProofError, /alg/)
  end
end

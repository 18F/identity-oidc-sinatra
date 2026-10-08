require 'spec_helper'

RSpec.describe LoginGov::OidcSinatra::DpopVerifier do
  let(:now) { Time.at(1_800_000_000) }
  let(:key) { OpenSSL::PKey::EC.generate('prime256v1') }
  let(:public_jwk) { JWT::JWK.new(key).export.transform_keys(&:to_s).except('kid') }
  let(:jkt) { described_class.thumbprint(public_jwk) }
  let(:method) { 'GET' }
  let(:url) { 'https://records-api.agency.localdev/records' }
  let(:access_token) { 'opaque-delegated-token-abc123' }
  let(:replay_cache) { LoginGov::OidcSinatra::DpopReplayCache.new(clock: -> { now }) }

  def claims(overrides = {})
    {
      jti: SecureRandom.uuid,
      htm: 'GET',
      htu: url,
      iat: now.to_i,
      ath: described_class.access_token_hash(access_token),
    }.merge(overrides)
  end

  def proof(claim_overrides = {}, header_overrides = {}, signing_key: key, alg: 'ES256')
    headers = { typ: 'dpop+jwt', jwk: public_jwk }.merge(header_overrides)
    JWT.encode(claims(claim_overrides).compact, signing_key, alg, headers)
  end

  # `proof(key: value)` reads as keyword arguments to Ruby; route claim overrides through a hash.
  def proof_with(**claim_overrides)
    proof(claim_overrides)
  end

  def verify(proof_value, **overrides)
    described_class.new(
      **{
        proof: proof_value,
        method: method,
        url: url,
        access_token: access_token,
        expected_jkt: jkt,
        replay_cache: replay_cache,
        now: now,
      }.merge(overrides),
    ).verify!
  end

  it 'accepts a proof signed by the bound key for this request and token' do
    expect(verify(proof)).to be_a(described_class)
  end

  it 'accepts an RS256 proof when the token is bound to an RSA key' do
    rsa = OpenSSL::PKey::RSA.new(2048)
    rsa_jwk = JWT::JWK.new(rsa).export.transform_keys(&:to_s).except('kid')
    p = JWT.encode(claims, rsa, 'RS256', { typ: 'dpop+jwt', jwk: rsa_jwk })

    expect(verify(p, expected_jkt: described_class.thumbprint(rsa_jwk))).to be_a(described_class)
  end

  it 'computes the RFC 7638 thumbprint the same way the jwt gem does' do
    expect(jkt).to eq JWT::JWK::Thumbprint.new(JWT::JWK.new(key)).to_s
  end

  it 'treats the request URL query string and scheme/host case as irrelevant to htu' do
    expect(verify(proof, url: 'HTTPS://Records-API.agency.localdev:443/records?page=2')).to be_a(described_class)
  end

  describe 'refusals' do
    it 'with no header' do
      expect { verify(nil) }.to raise_error(described_class::InvalidProof, /missing/)
    end

    it 'with more than one DPoP header (folded into one comma-separated value)' do
      expect { verify("#{proof}, #{proof}") }.to raise_error(described_class::InvalidProof, /single/)
    end

    it 'with the wrong typ' do
      expect { verify(proof({}, { typ: 'JWT' })) }.to raise_error(described_class::InvalidProof, /typ/)
    end

    it 'without an embedded jwk' do
      p = JWT.encode(claims, key, 'ES256', { typ: 'dpop+jwt' })
      expect { verify(p) }.to raise_error(described_class::InvalidProof, /jwk/)
    end

    it 'with alg none' do
      p = JWT.encode(claims, nil, 'none', { typ: 'dpop+jwt', jwk: public_jwk })
      expect { verify(p) }.to raise_error(described_class::InvalidProof, /alg/)
    end

    it 'with a symmetric algorithm, even when allowed_algs names it' do
      p = JWT.encode(claims, 'shared-secret', 'HS256', { typ: 'dpop+jwt', jwk: public_jwk })
      expect { verify(p, allowed_algs: %w[HS256]) }.to raise_error(described_class::InvalidProof, /alg/)
    end

    it 'with an algorithm outside the allow-list' do
      expect { verify(proof, allowed_algs: %w[RS256]) }.to raise_error(described_class::InvalidProof, /alg/)
    end

    it 'when the jwk carries private key members' do
      private_jwk = JWT::JWK.new(key).export(include_private: true).transform_keys(&:to_s).except('kid')
      expect { verify(proof({}, { jwk: private_jwk })) }.
        to raise_error(described_class::InvalidProof, /private/)
    end

    it 'when the signature does not verify with the embedded key' do
      other = OpenSSL::PKey::EC.generate('prime256v1')
      expect { verify(proof({}, {}, signing_key: other)) }.
        to raise_error(described_class::InvalidProof, /signature/)
    end

    it 'when the key verifies but is not the key the token is bound to' do
      other = OpenSSL::PKey::EC.generate('prime256v1')
      other_jwk = JWT::JWK.new(other).export.transform_keys(&:to_s).except('kid')
      p = JWT.encode(claims, other, 'ES256', { typ: 'dpop+jwt', jwk: other_jwk })
      expect { verify(p) }.to raise_error(described_class::InvalidProof, /bound/)
    end

    it 'when htm does not match the request method' do
      expect { verify(proof_with(htm: 'POST')) }.to raise_error(described_class::InvalidProof, /htm/)
    end

    it 'when htu names another URL' do
      expect { verify(proof_with(htu: 'https://records-api.agency.localdev/other')) }.
        to raise_error(described_class::InvalidProof, /htu/)
    end

    it 'when htu is not absolute' do
      expect { verify(proof_with(htu: '/records')) }.to raise_error(described_class::InvalidProof, /htu/)
    end

    it 'when iat is stale' do
      expect { verify(proof_with(iat: now.to_i - 61)) }.to raise_error(described_class::InvalidProof, /iat/)
    end

    it 'when iat is in the future beyond the leeway' do
      expect { verify(proof_with(iat: now.to_i + 61)) }.to raise_error(described_class::InvalidProof, /iat/)
    end

    it 'when iat is not an integer (a float, for example)' do
      expect { verify(proof_with(iat: now.to_f + 0.5)) }.to raise_error(described_class::InvalidProof, /iat/)
    end

    it 'when the jti was already used' do
      p = proof
      verify(p)
      expect { verify(p) }.to raise_error(described_class::InvalidProof, /jti/)
    end

    it 'when jti is missing' do
      expect { verify(proof_with(jti: nil)) }.to raise_error(described_class::InvalidProof, /jti/)
    end

    it 'when ath is for a different token' do
      expect { verify(proof_with(ath: described_class.access_token_hash('other-token'))) }.
        to raise_error(described_class::InvalidProof, /ath/)
    end

    it 'when ath is missing' do
      expect { verify(proof_with(ath: nil)) }.to raise_error(described_class::InvalidProof, /ath/)
    end
  end

  describe LoginGov::OidcSinatra::DpopReplayCache do
    it 'forgets a jti once its proof could no longer be accepted' do
      cache = described_class.new(clock: -> { now })
      expect(cache.first_use?('a', expires_at: now + 60)).to eq true
      expect(cache.first_use?('a', expires_at: now + 60)).to eq false

      later = described_class.new(clock: -> { now + 61 })
      later.instance_variable_set(:@seen, { 'a' => now + 60 })
      expect(later.first_use?('a', expires_at: now + 120)).to eq true
    end
  end
end

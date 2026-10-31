require 'spec_helper'
require 'cgi'

RSpec.describe LoginGov::OidcSinatra::OpenidConnectRelyingParty do
  let(:store) { LoginGov::OidcSinatra::DocumentTestSession }
  let(:token) { 'private-test-bearer' }
  let(:id) { store.put(token) }

  before do
    get '/document-artifacts'
    last_request.session[:document_test_id] = id
  end

  after { store.delete(id) }

  let(:sp_public_key) { OpenSSL::PKey::RSA.new(File.read('config/demo_sp.key')).public_key }

  def check(kind: 'userinfo', mode: 'current')
    post '/document-artifacts/check', {
      kind: kind, token_mode: mode, authenticity_token: last_request.session[:csrf],
    }, 'rack.session' => last_request.session
  end

  # A client assertion for exactly this URL, signed with the client's key, in the POST body.
  def with_client_assertion_for(url)
    lambda do |request|
      body = request.body.is_a?(Hash) ? request.body : CGI.parse(request.body)
      payload, = JWT.decode(Array(body['client_assertion']).first.to_s, sp_public_key, true, algorithm: 'RS256')
      Array(body['client_assertion_type']) == ['urn:ietf:params:oauth:client-assertion-type:jwt-bearer'] &&
        payload['aud'] == url && payload['iss'] == 'urn:gov:gsa:openidconnect:sp:sinatra'
    end
  end

  def encrypted_image(bytes, content_type:, public_key: sp_public_key)
    JWE.encrypt(
      bytes, public_key,
      alg: 'RSA-OAEP', enc: 'A256GCM', zip: 'DEF', cty: content_type, kid: JWT::JWK.new(public_key).kid
    )
  end

  it 'renders the test page without discovery or a token in the HTML' do
    expect(last_response).to be_ok
    expect(last_response.body).to include('Test document artifacts', 'Identity verified with selfie')
    expect(last_response.body).not_to include(token)
  end

  it 'distinguishes empty and absent claims without exposing the bearer token' do
    stub_request(:get, 'http://localhost:3000/api/openid_connect/userinfo').
      with(headers: { 'Authorization' => "Bearer #{token}" }).
      to_return(body: '{"document_images":{}}')
    check
    expect(last_response).to be_ok
    expect(last_response.body).to include('empty object', 'absent')
    expect(last_response.body).not_to include(token)
    expect(last_response.headers['cache-control']).to eq('no-store')
  end

  it 'uses the configured IdP host for userinfo and selfie checks' do
    allow_any_instance_of(LoginGov::OidcSinatra::Config).to receive(:idp_url).
      and_return('https://configured-idp.example')
    info = stub_request(:get, 'https://configured-idp.example/api/openid_connect/userinfo').
      with(headers: { 'Authorization' => "Bearer #{token}" }).
      to_return(body: {
        document_images: {
          selfie: 'https://configured-idp.example/api/openid_connect/document_images/selfie',
        },
        document_metadata: {
          document_number: 'TEST',
        },
      }.to_json)
    selfie_url = 'https://configured-idp.example/api/openid_connect/document_images/selfie'
    selfie = stub_request(:post, selfie_url).
      with(headers: { 'Authorization' => "Bearer #{token}" }, &with_client_assertion_for(selfie_url)).
      to_return(
        body: encrypted_image('synthetic-selfie', content_type: 'image/jpeg'),
        headers: { 'Content-Type' => 'application/jose' },
      )
    check
    expect(last_response.body).to include('present', 'TEST')
    check(kind: 'selfie')
    body = CGI.unescapeHTML(last_response.body)
    expect(body).to include('"encrypted": true', '"content_type": "image/jpeg"', '"bytes": 16')
    expect(body).not_to include('synthetic-selfie')
    expect(info).to have_been_requested.once
    expect(selfie).to have_been_requested.once
  end

  context 'when the userinfo response is encrypted to the client certificate' do
    let(:sp_private_key) { OpenSSL::PKey::RSA.new(File.read('config/demo_sp.key')) }
    let(:selfie_url) { 'http://localhost:3000/api/openid_connect/document_images/selfie' }
    let(:claims) do
      { document_images: { selfie: selfie_url }, document_metadata: { document_number: 'TEST' } }
    end

    # The shape Login.gov uses: one compact JWE of the claims JSON, RSA-OAEP and A256GCM,
    # served as application/jwt.
    def stub_encrypted_userinfo(public_key)
      jwe = JWE.encrypt(
        claims.to_json, public_key,
        alg: 'RSA-OAEP', enc: 'A256GCM', zip: 'DEF', typ: 'JWT', kid: JWT::JWK.new(public_key).kid
      )
      stub_request(:get, 'http://localhost:3000/api/openid_connect/userinfo').
        with(headers: { 'Authorization' => "Bearer #{token}" }).
        to_return(body: jwe, headers: { 'Content-Type' => 'application/jwt' })
    end

    it 'decrypts the claims with the client private key and reports the response as encrypted' do
      stub_encrypted_userinfo(sp_private_key.public_key)
      check
      expect(last_response).to be_ok
      body = CGI.unescapeHTML(last_response.body)
      expect(body).to include('"encrypted": true', 'present', selfie_url, 'TEST')
      expect(body).not_to include(token)
      expect(a_request(:get, selfie_url)).not_to have_been_made
    end

    it 'reports a response encrypted to some other key as an error' do
      stub_encrypted_userinfo(OpenSSL::PKey::RSA.new(2048).public_key)
      check
      expect(last_response.status).to eq(502)
      expect(last_response.body).to include('Could not decrypt the encrypted response')
    end
  end

  it 'reports a plain userinfo response as not encrypted' do
    stub_request(:get, 'http://localhost:3000/api/openid_connect/userinfo').
      with(headers: { 'Authorization' => "Bearer #{token}" }).
      to_return(body: '{"document_images":{}}')
    check
    expect(CGI.unescapeHTML(last_response.body)).to include('"encrypted": false')
  end

  it 'reports an unencrypted image response as not encrypted, without emitting image bytes' do
    stub_request(:post, 'http://localhost:3000/api/openid_connect/document_images/front').
      to_return(body: 'synthetic-image-bytes', headers: {
        'Content-Type' => 'image/jpeg', 'Cache-Control' => 'no-store',
      })
    check(kind: 'front')
    body = CGI.unescapeHTML(last_response.body)
    expect(body).to include('image/jpeg', 'no-store', '"encrypted": false')
    expect(body).not_to include('synthetic-image-bytes')
  end

  it 'reports an image encrypted to some other key as an error' do
    stub_request(:post, 'http://localhost:3000/api/openid_connect/document_images/front').
      to_return(
        body: encrypted_image('x', content_type: 'image/jpeg', public_key: OpenSSL::PKey::RSA.new(2048).public_key),
        headers: { 'Content-Type' => 'application/jose' },
      )
    check(kind: 'front')
    expect(last_response.status).to eq(502)
    expect(last_response.body).to include('Could not decrypt the encrypted response')
  end

  it 'sends the client assertion but no Authorization header for the missing-token case' do
    url = 'http://localhost:3000/api/openid_connect/document_images/front'
    request = stub_request(:post, url).
      with { |req| !req.headers.key?('Authorization') && with_client_assertion_for(url).call(req) }.
      to_return(status: 401, body: { error: 'invalid_client' }.to_json)
    check(kind: 'front', mode: 'missing')
    expect(request).to have_been_requested.once
    expect(last_response.body).to include('401')
  end

  it 'reports a refused assertion from the endpoint' do
    stub_request(:post, 'http://localhost:3000/api/openid_connect/document_images/front').
      to_return(status: 401, body: { error: 'invalid_client' }.to_json)
    check(kind: 'front')
    expect(last_response).to be_ok
    expect(last_response.body).to include('401')
  end

  it 'reports unauthorized userinfo even without a JSON body' do
    stub_request(:get, 'http://localhost:3000/api/openid_connect/userinfo').
      to_return(status: 401, body: '')
    check(mode: 'invalid')
    expect(last_response).to be_ok
    expect(last_response.body).to include('401')
  end

  it 'does not follow redirects with the bearer token' do
    stub_request(:post, 'http://localhost:3000/api/openid_connect/document_images/front').
      to_return(status: 302, headers: { 'Location' => 'https://other.example/image' })
    check(kind: 'front')
    expect(last_response.body).to include('302')
    expect(a_request(:get, 'https://other.example/image')).not_to have_been_made
  end

  it 'rejects arbitrary URLs' do
    check(kind: 'https://other.example/image')
    expect(last_response.status).to eq(400)
  end

  it 'rejects expired sessions' do
    store.delete(id)
    check
    expect(last_response.status).to eq(409)
  end

  it 'requires CSRF protection' do
    post '/document-artifacts/check', kind: 'front', token_mode: 'current'
    expect(last_response.status).to eq(403)
  end

  it 'expires tokens after fifteen minutes' do
    allow(Time).to receive(:now).and_return(Time.now + 901)
    expect(store.get(id)).to be_nil
  end

  it 'clears the stored token and session ID, then redirects to the test page' do
    post '/document-artifacts/clear', {
      authenticity_token: last_request.session[:csrf],
    }, 'rack.session' => last_request.session

    expect(store.get(id)).to be_nil
    expect(last_request.session[:document_test_id]).to be_nil
    expect(last_response).to be_redirect
    expect(last_response.location).to end_with('/document-artifacts')
  end
end

require 'spec_helper'

RSpec.describe LoginGov::OidcSinatra::OpenidConnectRelyingParty do
  let(:store) { LoginGov::OidcSinatra::DocumentTestSession }
  let(:token) { 'private-test-bearer' }
  let(:id) { store.put(token) }

  before do
    get '/document-artifacts'
    last_request.session[:document_test_id] = id
  end

  after { store.delete(id) }

  def check(kind: 'userinfo', mode: 'current')
    post '/document-artifacts/check', {
      kind: kind, token_mode: mode, authenticity_token: last_request.session[:csrf],
    }, 'rack.session' => last_request.session
  end

  it 'renders the guide without discovery or a token in the HTML' do
    expect(last_response).to be_ok
    expect(last_response.body).to include('Test document artifacts')
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

  it 'reports image response headers and size without emitting image bytes' do
    stub_request(:get, 'http://localhost:3000/api/openid_connect/document_images/front').
      to_return(body: 'synthetic-image-bytes', headers: {
        'Content-Type' => 'image/jpeg', 'Cache-Control' => 'no-store',
      })
    check(kind: 'front')
    expect(last_response.body).to include('image/jpeg', 'no-store')
    expect(last_response.body).not_to include('synthetic-image-bytes')
  end

  it 'sends no Authorization header for the missing-token case' do
    request = stub_request(:get, 'http://localhost:3000/api/openid_connect/document_images/front').
      with { |req| !req.headers.key?('Authorization') }.
      to_return(status: 401)
    check(kind: 'front', mode: 'missing')
    expect(request).to have_been_requested.once
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
    stub_request(:get, 'http://localhost:3000/api/openid_connect/document_images/front').
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
end

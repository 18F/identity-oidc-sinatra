require 'spec_helper'
require 'nokogiri'
require 'securerandom'
require 'cgi'

RSpec.describe LoginGov::OidcSinatra::OpenidConnectRelyingParty do
  let(:host) { 'http://localhost:3000' }
  let(:authorization_endpoint) { "#{host}/openid/authorize" }
  let(:token_endpoint) { "#{host}/api/openid/token" }
  let(:userinfo_endpoint) { "#{host}/api/openid/userinfo" }
  let(:end_session_endpoint) { "#{host}/openid/logout" }
  let(:jwks_endpoint) { "#{host}/api/openid_connect/certs" }
  let(:client_id) { 'urn:gov:gsa:openidconnect:sp:sinatra' }
  let(:vtr_disabled) { false }
  let(:idp_private_key) { OpenSSL::PKey::RSA.new(read_fixture_file('idp.key')) }
  let(:nonce) { 'abc' }

  before do
    allow_any_instance_of(LoginGov::OidcSinatra::Config).to receive(:cache_oidc_config?).and_return(false)
    allow_any_instance_of(LoginGov::OidcSinatra::Config).to receive(:vtr_disabled?).and_return(vtr_disabled)
    stub_request(:get, "#{host}/.well-known/openid-configuration").
      to_return(body: {
        authorization_endpoint: authorization_endpoint,
        token_endpoint: token_endpoint,
        userinfo_endpoint: userinfo_endpoint,
        end_session_endpoint: end_session_endpoint,
        jwks_uri: jwks_endpoint,
      }.to_json)

    stub_request(:get, jwks_endpoint).
      to_return(body: { keys: [{
        alg: 'RS256',
        use: 'sig',}.merge(JWT::JWK.new(OpenSSL::PKey::RSA.new(read_fixture_file('idp.key.pub'))).export)],
      }.to_json,
    )
  end

  context '/' do
    it 'pre-fills IAL2 if the URL has ?ial=2 (used in smoke tests)' do
      get '/?ial=2'

      expect(last_response).to be_ok

      doc = Nokogiri::HTML(last_response.body)
      ial2_option = doc.at('select[name=ial] option[value=2]')
      expect(ial2_option[:selected]).to be
    end

    it 'pre-fills HSPD12 if the URL has ?aal=2-hspd12' do
      get '/?aal=2-hspd12'

      expect(last_response).to be_ok

      doc = Nokogiri::HTML(last_response.body)
      aal3_option = doc.at('select[name=aal] option[value="2-hspd12"]')
      expect(aal3_option[:selected]).to be
    end

    it 'renders an error if basic auth credentials are wrong' do
      stub_request(:get, "#{host}/.well-known/openid-configuration").
        to_return(body: '', status: 401)

      get '/'

      expect(last_response.body).to include(
        'Perhaps we need to reimplement HTTP Basic Auth',
      )
    end

    it 'renders an error if the app fails to get oidc configuration' do
      stub = stub_request(:get, "#{host}/.well-known/openid-configuration").
             to_return(body: '', status: 400)

      get '/'

      error_string = "Error: Unable to retrieve OIDC configuration from IdP. #{host} responded with 400."
      expect(last_response.body).to include(error_string)
      expect(stub).to have_been_requested.once
      expect(last_response.status).to eq 500
    end
  end

  context '/auth/request' do
    context 'with vtr disabled' do
      let(:vtr_disabled) { true }

      it 'redirects to an ial1 sign in link if loa param is nil' do
        get '/auth/request'

        expect(last_response).to be_redirect
        expect(last_response.location).to include(
          'scope=openid+email',
        )
        expect(last_response.location).to_not include(
          'scope=openid+email+profile+social_security_number+phone+address',
        )
        expect(last_response.location).to include(
          CGI.escape('http://idmanagement.gov/ns/assurance/ial/1'),
        )
      end

      it 'redirects to an ial2 signin if the ial is 2' do
        get '/auth/request?ial=2'

        expect(last_response).to be_redirect
        expect(last_response.location).to include(
          'scope=openid+email+profile+social_security_number+phone+address',
        )
        expect(last_response.location).to include(
          CGI.escape('http://idmanagement.gov/ns/assurance/ial/2'),
        )
      end

      it 'redirects to an ial1 sign in link if ial param is 1' do
        get '/auth/request?ial=1'

        expect(last_response).to be_redirect
        expect(last_response.location).to include(
          'scope=openid+email',
        )
        expect(last_response.location).to_not include(
          'scope=openid+email+profile+social_security_number+phone+address',
        )
        expect(last_response.location).to include(
          CGI.escape('http://idmanagement.gov/ns/assurance/ial/1'),
        )
      end

      it 'redirects to an ialmax sign in link if ial param is 0' do
        get '/auth/request?ial=0'

        expect(last_response).to be_redirect
        expect(last_response.location).to include(
          'scope=openid+email+social_security_number',
        )
        expect(last_response.location).to include(
          CGI.escape('http://idmanagement.gov/ns/assurance/ial/0'),
        )
      end

      it 'redirects to an ial1 sign in link if ial param is step-up' do
        get '/auth/request?ial=step-up'

        expect(last_response).to be_redirect
        expect(last_response.location).to include('scope=openid+email')
        expect(last_response.location).to_not include(
          'scope=openid+email+profile+social_security_number+phone+address',
        )
        expect(last_response.location).to include(
          CGI.escape('http://idmanagement.gov/ns/assurance/ial/1'),
        )
      end

      it 'redirects to a phishing-resistant AAL2 sign in link if aal param is 2-phishing_resistant' do
        get '/auth/request?aal=2-phishing_resistant'

        expect(last_response).to be_redirect
        expect(last_response.location).to include(
          CGI.escape('http://idmanagement.gov/ns/assurance/aal/2'),
        )
        expect(CGI.unescape(last_response.location)).to include(
          '/aal/2?phishing_resistant=true',
        )
      end

      it 'redirects to an HSPD12 AAL2 sign in link if aal param is 2-hspd12' do
        get '/auth/request?aal=2-hspd12'

        expect(last_response).to be_redirect
        expect(last_response.location).to include(
          CGI.escape('http://idmanagement.gov/ns/assurance/aal/2'),
        )
        expect(CGI.unescape(last_response.location)).to include(
          '/aal/2?hspd12=true',
        )
      end

      it 'redirects to ial2 with the flag if the ial param is biometric-comparison-required' do
        get '/auth/request?ial=biometric-comparison-required'

        expect(last_response).to be_redirect
        expect(last_response.location).to include(
          CGI.escape('http://idmanagement.gov/ns/assurance/ial/2?bio=required'),
        )
        expect(last_response.location).to include(
          'scope=openid+email+profile+social_security_number+phone+address',
        )
      end

      it 'redirects to ial2 with the flag if the ial param is biometric-comparison-preferred' do
        get '/auth/request?ial=biometric-comparison-preferred'

        expect(last_response).to be_redirect
        expect(last_response.location).to include(
          CGI.escape('http://idmanagement.gov/ns/assurance/ial/2?bio=preferred'),
        )
        expect(last_response.location).to include(
          'scope=openid+email+profile+social_security_number+phone+address',
        )
      end
    end

    context 'with vtr enabled' do
      let(:vtr_disabled) { false }

      context 'when the ial is enhanced-ipp-required' do

        it 'redirects to a default sign in link if ial param is nil' do
          get '/auth/request?ial=enhanced-ipp-required'

          expect(last_response).to be_redirect
          expect(last_response.location).to include(
            'scope=openid+email',
          )

          expect(last_response.location).to include(
            'scope=openid+email+profile+social_security_number+phone+address',
          )
          expect(CGI.unescape(last_response.location)).to include('vtr=["C1.P1.Pe"]')
        end
      end

      context 'when the ial is biometric-comparison-vot' do

        it 'redirects to a default sign in link if ial param is nil' do
          get '/auth/request?ial=biometric-comparison-vot'

          expect(last_response).to be_redirect
          expect(last_response.location).to include(
            'scope=openid+email',
          )

          expect(last_response.location).to include(
            'scope=openid+email+profile+social_security_number+phone+address',
          )
          expect(CGI.unescape(last_response.location)).to include('vtr=["C1.P1.Pb"]')
        end
      end

      context 'all other ials' do
        it 'redirects to an ial2 signin if the ial is 2' do
          get '/auth/request?ial=2'

          expect(last_response).to be_redirect
          expect(last_response.location).to include(
            'scope=openid+email+profile+social_security_number+phone+address',
          )
          expect(last_response.location).to include(
            CGI.escape('http://idmanagement.gov/ns/assurance/ial/2'),
          )
        end

        it 'redirects to ial2 with the flag if the ial param is biometric-comparison-required' do
          get '/auth/request?ial=biometric-comparison-required'

          expect(last_response).to be_redirect
          expect(last_response.location).to include(
            CGI.escape('http://idmanagement.gov/ns/assurance/ial/2'),
          )
          expect(last_response.location).to include(
            'scope=openid+email+profile+social_security_number+phone+address',
          )
        end

        it 'redirects to ial2 with the flag if the ial param is biometric-comparison-preferred' do
          get '/auth/request?ial=biometric-comparison-preferred'

          expect(last_response).to be_redirect
          expect(last_response.location).to include(
            CGI.escape('http://idmanagement.gov/ns/assurance/ial/2?bio=preferred'),
          )
          expect(last_response.location).to include(
            'scope=openid+email+profile+social_security_number+phone+address',
          )
        end
      end
    end
  end

  context '/auth/result' do
    context 'errors happen before the auth token exchange' do
      it 'redirects to root with an error param when there is an access denied' do
        get '/auth/result', error: 'access_denied'

        expect(last_response).to be_redirect
        uri = URI.parse(last_response.location)
        expect(uri.path).to eq('/')
        expect(uri.query).to eq('error=access_denied')
        follow_redirect!
        expect(last_response.body).to include('You chose to exit before signing in')
      end

      it 'renders a default error message when no code or explicit error code' do
        get '/auth/result'

        doc = Nokogiri::HTML(last_response.body)

        expect(doc.text).to include('missing callback param: code')
      end
    end

    context 'the token exchange moved forward' do
      let(:code) { 'abc-code' }
      let(:connection) { double Faraday }

      let(:email) { 'foobar@bar.com' }
      let(:bearer_token) { 'abc' }

      context 'with valid token' do
        it 'takes an authorization code and gets a token, and renders the email from the token' do
          get '/auth/request'

          stub_token_response(
            code: code,
            bearer_token: bearer_token,
            id_token: generate_id_token(nonce: last_request.session['nonce']),
          )
          stub_userinfo_response(bearer_token: bearer_token, email: email)

          get '/auth/result', { code: code, state: last_request.session['state'] }, 'rack.session' => last_request.session

          expect(last_response).to be_redirect
          follow_redirect!
          expect(last_response.body).to include(email)
        end

        context 'with dangerous input' do
          let(:email) { '<script>alert("hi")</script> mallory@bar.com' }

          it 'escapes dangerous HTML' do
            get '/auth/request'
            stub_token_response(
              code: code,
              bearer_token: bearer_token,
              id_token: generate_id_token(nonce: last_request.session['nonce']),
            )
            stub_userinfo_response(bearer_token: bearer_token, email: email)
            get '/auth/result', { code: code, state: last_request.session['state'] }, 'rack.session' => last_request.session

            follow_redirect!

            expect(last_response.body).to_not include(email)
            expect(last_response.body).to include('&lt;script&gt;alert(&quot;hi&quot;)&lt;/script&gt; mallory@bar.com')
          end
        end

        it 'has a logout link to the handle-logout endpoint' do
          get '/auth/request'
          stub_token_response(
            code: code,
            bearer_token: bearer_token,
            id_token: generate_id_token(nonce: last_request.session['nonce']),
          )
          stub_userinfo_response(bearer_token: bearer_token, email: email)
          get '/auth/result', { code: code, state: last_request.session['state'] }, 'rack.session' => last_request.session
          follow_redirect!
          doc = Nokogiri::HTML(last_response.body)


          logout_form = doc.at_css('form')
          expect(logout_form).not_to be_nil

          expect(logout_form[:action]).to eq '/handle-logout'
          expect(logout_form[:method]).to eq 'post'
        end
      end

      context 'with invalid state' do
        it 'fails auth and shows error message' do
          get '/auth/request'
          get '/auth/result', { code: code, state: 'fake-state' }, 'rack.session' => last_request.session

          expect(last_response.body).to include('invalid state')
          expect(last_response.body).to_not include(email)
        end
      end

      context 'with invalid nonce' do
        it 'fails auth and shows error message' do
          get '/auth/request'
          stub_token_response(
            code: code,
            bearer_token: bearer_token,
            id_token: generate_id_token(nonce: 'fake-nonce'),
          )
          get '/auth/result', { code: code, state: last_request.session['state'] }, 'rack.session' => last_request.session

          expect(last_response.body).to include('invalid nonce')
          expect(last_response.body).to_not include(email)
        end
      end
    end
  end

  context 'POST /handle-logout' do
    let(:redirect_uri) { 'localhost:9292/logout' }

    before do
      get '/'
      last_request.session[:userinfo] = 'userinfo'
      last_request.session[:email] = 'user@example.com'
      last_request.session[:step_up_enabled] = false
      last_request.session[:step_up_aal] = false
      last_request.session[:irs] = false
      last_request.session[:state] = 'abc123'

      post '/handle-logout', authenticity_token: last_request.session[:csrf]
    end

    it 'deletes the session objects' do
      expect(last_request.session.keys).to_not include('userinfo')
      expect(last_request.session.keys).to_not include('email')
      expect(last_request.session.keys).to_not include('step_up_enabled')
      expect(last_request.session.keys).to_not include('step_up_aal')
      expect(last_request.session.keys).to_not include('irs')
    end

    it 'redirects to Login.gov logout' do
      expect(last_response.location).to include(end_session_endpoint)
      expect(last_response.location).to include("client_id=#{CGI.escape(client_id)}")
      expect(last_response.location).to include(CGI.escape(redirect_uri))
    end
  end

  def generate_id_token(nonce:)
    JWT.encode({ nonce: nonce }, idp_private_key, 'RS256', kid: JWT::JWK.new(idp_private_key))
  end

  def stub_token_response(code:, bearer_token:, id_token: )
    stub_request(:post, token_endpoint).
      with(body: {
        grant_type: 'authorization_code',
        code: code,
        client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        client_assertion: kind_of(String),
      }).
      to_return(body: { access_token: bearer_token, id_token: id_token }.to_json)
  end

  def stub_userinfo_response(bearer_token:, email: )
    stub_request(:get, userinfo_endpoint).
      with(headers: {'Authorization' => "Bearer #{bearer_token}" }).
      to_return(body: { email: email }.to_json)
  end
end

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
  let(:client_id) { 'urn:gov:gsa:openidconnect:sp:sinatra' }
  let(:vtr_enabled) { false }

  before do
    allow_any_instance_of(LoginGov::OidcSinatra::Config).to receive(:cache_oidc_config?).and_return(false)
    allow_any_instance_of(LoginGov::OidcSinatra::Config).to receive(:vtr_enabled?).and_return(vtr_enabled)
    stub_request(:get, "#{host}/.well-known/openid-configuration").
      to_return(body: {
        authorization_endpoint: authorization_endpoint,
        token_endpoint: token_endpoint,
        userinfo_endpoint: userinfo_endpoint,
        end_session_endpoint: end_session_endpoint,
      }.to_json)
  end

  context '/' do
    it 'renders a link to the authorize endpoint' do
      get '/'

      expect(last_response).to be_ok

      doc = Nokogiri::HTML(last_response.body)
      login_link = doc.at("a[href*='#{authorization_endpoint}']")

      auth_uri = URI(login_link[:href])
      auth_uri_params = Rack::Utils.parse_nested_query(auth_uri.query).with_indifferent_access

      expect(auth_uri_params[:redirect_uri]).to eq('http://localhost:9292/auth/result')
      expect(auth_uri_params[:client_id]).to_not be_empty
      expect(auth_uri_params[:client_id]).to eq(client_id)
      expect(auth_uri_params[:response_type]).to eq('code')
      expect(auth_uri_params[:prompt]).to eq('select_account')
      expect(auth_uri_params[:nonce].length).to be >= 32
      expect(auth_uri_params[:state].length).to be >= 32
    end

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
    context 'with acr_values enabled' do
      let(:vtr_enabled) { false }

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
        expect(last_response.location).to include(
          'biometric_comparison_required=false',
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
        expect(last_response.location).to include(
          'biometric_comparison_required=false',
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
        expect(last_response.location).to include(
          'biometric_comparison_required=false',
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
          CGI.escape('http://idmanagement.gov/ns/assurance/ial/2'),
        )
        expect(last_response.location).to include(
          'scope=openid+email+profile+social_security_number+phone+address',
        )
        expect(last_response.location).to include(
          'biometric_comparison_required=true',
        )
      end
    end

    context 'with vtr enabled' do
      let(:vtr_enabled) { true }

      it 'redirects to a default sign in link if ial param is nil' do
        get '/auth/request'

        expect(last_response).to be_redirect
        expect(last_response.location).to include(
          'scope=openid+email',
        )
        expect(last_response.location).to_not include(
          'scope=openid+email+profile+social_security_number+phone+address',
        )
        expect(CGI.unescape(last_response.location)).to include('vtr=["C1"]')
      end

      it 'redirects to an identity-proofing signin if the ial is 2' do
        get '/auth/request?ial=2'

        expect(last_response).to be_redirect
        expect(last_response.location).to include(
          'scope=openid+email+profile+social_security_number+phone+address',
        )
        expect(CGI.unescape(last_response.location)).to include('vtr=["C1.P1"]')
      end

      it 'redirects to an default sign in link if ial param is 1' do
        get '/auth/request?ial=1'

        expect(last_response).to be_redirect
        expect(last_response.location).to include(
          'scope=openid+email',
        )
        expect(last_response.location).to_not include(
          'scope=openid+email+profile+social_security_number+phone+address',
        )
        expect(CGI.unescape(last_response.location)).to include('vtr=["C1"]')
      end

      xit 'redirects to an ialmax sign in link if ial param is 0' do
        get '/auth/request?ial=0'

        expect(last_response).to be_redirect
        expect(last_response.location).to include(
          'scope=openid+email+social_security_number',
        )
        expect(CGI.unescape(last_response.location)).to include('vtr=["C1.P1"]')
      end

      it 'redirects to a default sign in link if ial param is step-up' do
        get '/auth/request?ial=step-up'

        expect(last_response).to be_redirect
        expect(last_response.location).to include('scope=openid+email')
        expect(last_response.location).to_not include(
          'scope=openid+email+profile+social_security_number+phone+address',
        )
        expect(CGI.unescape(last_response.location)).to include('vtr=["C1"]')
      end

      it 'redirects to a phishing-resistant AAL2 sign in link if aal param is 2-phishing_resistant' do
        get '/auth/request?aal=2-phishing_resistant'

        expect(last_response).to be_redirect
        expect(CGI.unescape(last_response.location)).to include('vtr=["C1.C2.Ca"]')
      end

      it 'redirects to an HSPD12 AAL2 sign in link if aal param is 2-hspd12' do
        get '/auth/request?aal=2-hspd12'

        expect(last_response).to be_redirect
        expect(CGI.unescape(last_response.location)).to include('vtr=["C1.C2.Cb"]')
      end

      it 'redirects to ial2 with the flag if the ial param is biometric-comparison-required' do
        get '/auth/request?ial=biometric-comparison-required'

        expect(last_response).to be_redirect
        expect(last_response.location).to include(
          'scope=openid+email+profile+social_security_number+phone+address',
        )
        expect(CGI.unescape(last_response.location)).to include('vtr=["C1.P1.Pb"]')
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
      let(:code) { SecureRandom.uuid }
      let(:connection) { double Faraday }

      let(:email) { 'foobar@bar.com' }
      let(:bearer_token) { SecureRandom.hex(10)}

      before do
        expect(Faraday).to receive(:post).with(token_endpoint,
          grant_type: 'authorization_code',
          code: code,
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
          client_assertion: kind_of(String),
        ) { Faraday::Response.new({body: { access_token: bearer_token}.to_json }) }

        expect(Faraday).to receive(:new).with(url: userinfo_endpoint,
          headers: {'Authorization' => "Bearer #{bearer_token}" },
        ) { connection }

        expect(connection).to receive(:get).with('') { Faraday::Response.new({body: { email: email}.to_json }) }
      end

      it 'takes an authorization code and gets a token, and renders the email from the token' do
        get '/auth/result', code: code

        expect(last_response).to be_redirect
        follow_redirect!
        expect(last_response.body).to include(email)
      end

      context 'with dangerous input' do
        let(:email) { '<script>alert("hi")</script> mallory@bar.com' }

        it 'escapes dangerous HTML' do
          get '/auth/result', code: code
          follow_redirect!

          expect(last_response.body).to_not include(email)
          expect(last_response.body).to include('&lt;script&gt;alert(&quot;hi&quot;)&lt;/script&gt; mallory@bar.com')
        end
      end

      it 'has a logout link back to the SP-initiated logout URL' do
        get '/auth/result', code: code
        follow_redirect!
        doc = Nokogiri::HTML(last_response.body)

        # logout_link = doc.at_xpath("//div[@class='sign-in-wrap']/a[text()='\n              Log out\n            ']")
        logout_link = doc.at_css("div.sign-in-wrap a:contains('Log out')")
        expect(logout_link).to be

        href = logout_link[:href]
        expect(href).to start_with(end_session_endpoint)
        expect(href).to include("client_id=#{CGI.escape(client_id)}")
      end
    end
  end
end

require_relative 'spec_helper'
require_relative '../../lib/loadtest/config'
require_relative '../../lib/loadtest/flows/auth_only'
require_relative '../../lib/loadtest/flows/idv'
require_relative '../../lib/loadtest/flows/idv_facial_match'
require_relative '../../lib/loadtest/flows/signup'
require_relative '../../lib/loadtest/http_client'
require_relative '../../lib/loadtest/results'

# These specs drive the flows against a scripted fake transport instead of a live
# IdP. They verify the step sequence, the exact parameters the harness submits,
# and the failure messages -- the things most likely to break when the IdP
# changes -- without needing a running Rails app, Postgres, or Redis.
#
# The page fixtures mirror the structure of the real identity-idp views
# (form actions, field names, hidden inputs) rather than their full markup.
RSpec.describe 'load test flows' do
  # Stands in for HttpClient, answering requests from a scripted route table.
  #
  # Redirects are modelled rather than collapsed, because the IdP relies on them
  # heavily and the harness's redirect handling is part of what needs testing.
  # Any request that matches no route raises, so a flow cannot quietly skip a
  # step or hit an endpoint the test did not anticipate.
  class FakeHttp
    Recorded = Struct.new(:method, :url, :params, keyword_init: true)

    attr_reader :requests

    def initialize(routes)
      @routes = routes
      @requests = []
    end

    def get(url, headers: {})
      respond(:get, url, {})
    end

    def post(url, params: {}, headers: {})
      respond(:post, url, params)
    end

    def patch(url, params: {}, headers: {})
      respond(:patch, url, params)
    end

    def follow_redirects(response, limit: 10)
      chain = [response]
      while chain.last.redirect? && chain.last.location
        raise 'too many redirects' if chain.length > limit

        chain << get(absolutize(chain.last.location, base: chain.last.uri))
      end
      chain
    end

    def absolutize(location, base:)
      URI.join(base.to_s, location.to_s).to_s
    end

    # @return [Recorded, nil] the first request whose URL contains the fragment
    def request_for(fragment)
      @requests.find { |request| request.url.include?(fragment) }
    end

    # @return [Recorded, nil] the last request carrying the named parameter
    def request_with_param(name)
      @requests.reverse.find { |request| request.params.key?(name) }
    end

    def urls
      @requests.map(&:url)
    end

    private

    def respond(method, url, params)
      @requests << Recorded.new(method: method, url: url, params: params)
      response = route_for(method, url, params)

      if response.is_a?(Array)
        if response.first == :redirect
          return build(302, '', url, 'location' => response.last)
        else
          status, body = response
          return build(status, body, url)
        end
      end

      build(200, response, url)
    end

    # Longest match wins, so a specific path like "/login/two_factor" is not
    # shadowed by a broad one like "localhost:3000/".
    def route_for(method, url, params)
      key = @routes.keys.select { |fragment| url.include?(fragment) }.max_by(&:length)
      raise "unexpected #{method.to_s.upcase} #{url}" if key.nil?

      value = @routes.fetch(key)
      value.respond_to?(:call) ? value.call(method, params) : value
    end

    def build(status, body, url, headers = {})
      LoginGov::OidcSinatra::Loadtest::Response.new(
        status: status,
        headers: headers,
        body: body,
        uri: URI.parse(url),
        duration_ms: 1.0,
      )
    end
  end

  # identity-idp renders the sign-in form at the IdP root and posts back to it
  # (routes.rb: `post '/' => 'users/sessions#create'`).
  SIGN_IN_PAGE = <<~HTML
    <form action="/" method="post">
      <input type="hidden" name="authenticity_token" value="signin-token">
      <input name="user[email]"><input name="user[password]">
    </form>
  HTML

  # The one-time-code field carries the real code as its value whenever
  # FeatureManagement.prefill_otp_codes? is true.
  OTP_PAGE = <<~HTML
    <form action="/login/two_factor/sms" method="post">
      <input type="hidden" name="authenticity_token" value="otp-token">
      <input type="text" name="code" id="code" value="123456">
    </form>
  HTML

  HANDOFF = [:redirect, 'http://localhost:9292/auth/result?code=abc&state=xyz'].freeze

  RP_SUCCESS_PAGE = '<span>Received user info:</span>'

  let(:config) do
    LoginGov::OidcSinatra::Loadtest::Config.new(
      env: {},
      overrides: { 'flow_runs' => { 'auth_only' => 1, 'idv_legacy' => 1, 'idv_facial_match' => 1, 'signup' => 1 } },
    )
  end
  let(:recorder) { LoginGov::OidcSinatra::Loadtest::StepRecorder.new }

  def build_flow(flow_class, routes, config: self.config)
    http = FakeHttp.new(routes)
    [flow_class.new(config: config, http: http, recorder: recorder), http]
  end

  # Config with signup.short_circuit_to_registration flipped on, for specs
  # covering that path specifically. Everything else uses the default config,
  # which exercises the sign-in-page path.
  def config_with_short_circuit
    LoginGov::OidcSinatra::Loadtest::Config.new(
      env: {},
      overrides: {
        'flow_runs' => { 'signup' => 1 },
        'flows' => { 'signup' => { 'short_circuit_to_registration' => true } },
      },
    )
  end

  # The happy path for both sign-in flows: the relying party redirects to the
  # IdP, the IdP serves sign-in then OTP, then hands back to the relying party.
  def sign_in_routes(after_otp: HANDOFF)
    {
      'localhost:9292/auth/request' => [:redirect, 'http://localhost:3000/openid_connect/authorize'],
      'localhost:3000/openid_connect/authorize' => [:redirect, 'http://localhost:3000/'],
      'localhost:3000/' => SIGN_IN_PAGE,
      'localhost:3000/login/two_factor' => after_otp,
      'localhost:9292/auth/result' => RP_SUCCESS_PAGE,
    }
  end

  def sign_in_user
    { email: 'testuser0@example.com', password: 'salty pickles' }
  end

  describe LoginGov::OidcSinatra::Loadtest::Flows::AuthOnly do
    # The sign-in POST lands on the OTP page; everything else is the happy path.
    let(:routes) do
      sign_in_routes.merge(
        'localhost:3000/' => ->(method, _params) { method == :post ? OTP_PAGE : SIGN_IN_PAGE },
      )
    end

    it 'starts the flow at the relying party, not the IdP' do
      _flow, http = run_flow(described_class, routes)

      expect(http.urls.first).to start_with('http://localhost:9292/auth/request')
    end

    it 'requests the authentication-only assurance level' do
      _flow, http = run_flow(described_class, routes)

      expect(http.urls.first).to include('ial=1')
    end

    it 'sends scopes with the bracket-suffixed key for Rack array parsing' do
      _flow, http = run_flow(described_class, routes)

      first_url = http.urls.first
      expect(first_url).to include('requested_scopes%5B%5D=')
      expect(first_url).not_to match(/[?&]requested_scopes=/)
    end

    it 'submits the credentials with the per-form token scraped from the page' do
      # Rails uses per-form CSRF tokens, so the token must come from the form
      # being submitted rather than from any earlier page.
      _flow, http = run_flow(described_class, routes, user: sign_in_user)

      expect(http.request_with_param('user[email]').params).to include(
        'user[email]' => 'testuser0@example.com',
        'user[password]' => 'salty pickles',
        'authenticity_token' => 'signin-token',
      )
    end

    it 'submits the one-time code the IdP prefilled on the page' do
      _flow, http = run_flow(described_class, routes)

      expect(http.request_with_param('code').params).to include('code' => '123456')
    end

    it 'posts the code to the two-factor route' do
      _flow, http = run_flow(described_class, routes)

      expect(http.request_with_param('code').url).to include('/login/two_factor/sms')
    end

    it 'declines to remember the device, so every run exercises the OTP path' do
      _flow, http = run_flow(described_class, routes)

      expect(http.request_with_param('code').params).to include('remember_device' => '0')
    end

    it 'follows the handoff back to the relying party' do
      _flow, http = run_flow(described_class, routes)

      expect(http.urls.last).to include('localhost:9292/auth/result')
    end

    it 'records a timing for every step' do
      run_flow(described_class, routes)

      expect(recorder.steps.map { |step| step.fetch(:name) }).to eq(
        %w[rp_auth_request sign_in_submit otp_submit interstitials handoff rp_result],
      )
    end

    it 'completes without error on the happy path' do
      flow, = build_flow(described_class, routes)

      expect { flow.run(user: sign_in_user) }.not_to raise_error
    end
  end

  describe LoginGov::OidcSinatra::Loadtest::Flows::IdvLegacy do
    let(:routes) do
      sign_in_routes.merge(
        'localhost:3000/' => ->(method, _params) { method == :post ? OTP_PAGE : SIGN_IN_PAGE },
      )
    end

    it 'requests the legacy identity-verified assurance level' do
      _flow, http = run_flow(described_class, routes)

      expect(http.urls.first).to include('ial=2')
    end

    it 'sends scopes with the bracket-suffixed key' do
      _flow, http = run_flow(described_class, routes)

      first_url = http.urls.first
      expect(first_url).to include('requested_scopes%5B%5D=')
      expect(first_url).not_to match(/[?&]requested_scopes=/)
    end

    it 'otherwise follows the same authentication steps as auth_only' do
      run_flow(described_class, routes)

      expect(recorder.steps.map { |step| step.fetch(:name) }).to eq(
        %w[rp_auth_request sign_in_submit otp_submit interstitials handoff rp_result],
      )
    end
  end

  describe LoginGov::OidcSinatra::Loadtest::Flows::IdvFacialMatch do
    let(:routes) do
      sign_in_routes.merge(
        'localhost:3000/' => ->(method, _params) { method == :post ? OTP_PAGE : SIGN_IN_PAGE },
      )
    end

    it 'requests facial match required' do
      _flow, http = run_flow(described_class, routes)

      expect(http.urls.first).to include('ial=facial-match-required')
    end

    it 'sends scopes with the bracket-suffixed key' do
      _flow, http = run_flow(described_class, routes)

      first_url = http.urls.first
      expect(first_url).to include('requested_scopes%5B%5D=')
      expect(first_url).not_to match(/[?&]requested_scopes=/)
    end

    it 'otherwise follows the same authentication steps as auth_only' do
      run_flow(described_class, routes)

      expect(recorder.steps.map { |step| step.fetch(:name) }).to eq(
        %w[rp_auth_request sign_in_submit otp_submit interstitials handoff rp_result],
      )
    end
  end

  describe 'handoff modes' do
    it 'follows a server-side redirect handoff' do
      routes = sign_in_routes.merge(
        'localhost:3000/' => ->(method, _params) { method == :post ? OTP_PAGE : SIGN_IN_PAGE },
      )
      _flow, http = run_flow(LoginGov::OidcSinatra::Loadtest::Flows::AuthOnly, routes)

      expect(http.request_for('/auth/result').url).to include('code=abc')
    end

    it 'follows the client-side JavaScript handoff page' do
      # openid_connect_redirect defaults to client_side_js outside production, so
      # the handoff arrives as an HTML page with a data-click-immediate anchor
      # rather than a 302. Supporting both means no IdP change is required.
      js_handoff = <<~HTML
        <a href="http://localhost:9292/auth/result?code=js&state=xyz" data-click-immediate>Go</a>
      HTML
      routes = sign_in_routes(after_otp: js_handoff).merge(
        'localhost:3000/' => ->(method, _params) { method == :post ? OTP_PAGE : SIGN_IN_PAGE },
      )
      _flow, http = run_flow(LoginGov::OidcSinatra::Loadtest::Flows::AuthOnly, routes)

      expect(http.request_for('/auth/result').url).to include('code=js')
    end
  end

  describe 'interstitial screens' do
    def routes_with_interstitial(page, path, after: HANDOFF)
      pages = [OTP_PAGE]
      sign_in_routes.merge(
        'localhost:3000/' => ->(method, _p) { method == :post ? pages.shift : SIGN_IN_PAGE },
        'localhost:3000/login/two_factor' => page,
        "localhost:3000#{path}" => after,
      )
    end

    it 'clears the consent screen by replaying its form' do
      consent_page = <<~HTML
        <form action="/sign_up/completed" method="post">
          <input type="hidden" name="authenticity_token" value="consent-token">
        </form>
      HTML
      _flow, http = run_flow(
        LoginGov::OidcSinatra::Loadtest::Flows::AuthOnly,
        routes_with_interstitial(consent_page, '/sign_up/completed'),
      )

      expect(http.request_for('/sign_up/completed').params).
        to include('authenticity_token' => 'consent-token')
    end

    it 'clears the already-signed-in confirmation screen' do
      confirmation_page = <<~HTML
        <form action="/user_authorization_confirmation" method="post">
          <input type="hidden" name="authenticity_token" value="confirm-token">
        </form>
      HTML
      _flow, http = run_flow(
        LoginGov::OidcSinatra::Loadtest::Flows::AuthOnly,
        routes_with_interstitial(confirmation_page, '/user_authorization_confirmation'),
      )

      expect(http.request_for('/user_authorization_confirmation')).not_to be_nil
    end

    it 'chooses the skip button on a second-factor reminder' do
      # The screen renders two forms to the same route; the one carrying
      # add_method enrolls another method, which a load test does not want.
      reminder_page = <<~HTML
        <form action="/second_mfa_reminder" method="post">
          <input type="hidden" name="authenticity_token" value="t">
          <input type="hidden" name="add_method" value="true">
        </form>
        <form action="/second_mfa_reminder" method="post">
          <input type="hidden" name="authenticity_token" value="skip-token">
        </form>
      HTML
      _flow, http = run_flow(
        LoginGov::OidcSinatra::Loadtest::Flows::AuthOnly,
        routes_with_interstitial(reminder_page, '/second_mfa_reminder'),
      )

      params = http.request_for('/second_mfa_reminder').params
      expect(params).to include('authenticity_token' => 'skip-token')
      expect(params).not_to have_key('add_method')
    end

    it 'clears several interstitials in sequence' do
      consent_page = <<~HTML
        <form action="/sign_up/completed" method="post">
          <input type="hidden" name="authenticity_token" value="consent-token">
        </form>
      HTML
      reminder_page = <<~HTML
        <form action="/second_mfa_reminder" method="post">
          <input type="hidden" name="authenticity_token" value="skip-token">
        </form>
      HTML
      pages = [OTP_PAGE]
      routes = sign_in_routes.merge(
        'localhost:3000/' => ->(method, _p) { method == :post ? pages.shift : SIGN_IN_PAGE },
        'localhost:3000/login/two_factor' => reminder_page,
        'localhost:3000/second_mfa_reminder' => consent_page,
        'localhost:3000/sign_up/completed' => HANDOFF,
      )
      _flow, http = run_flow(LoginGov::OidcSinatra::Loadtest::Flows::AuthOnly, routes)

      expect(http.request_for('/second_mfa_reminder')).not_to be_nil
      expect(http.request_for('/sign_up/completed')).not_to be_nil
    end
  end

  describe 'failure reporting' do
    it 'names the prefill requirement when no code is on the page' do
      # The likeliest misconfiguration: the IdP is not running in development
      # with the test telephony adapter, so the field renders empty.
      no_code_page = <<~HTML
        <form action="/login/two_factor/sms" method="post">
          <input type="hidden" name="authenticity_token" value="t">
          <input type="text" name="code" id="code" value="">
        </form>
      HTML
      routes = sign_in_routes.merge(
        'localhost:3000/' => ->(method, _p) { method == :post ? no_code_page : SIGN_IN_PAGE },
      )
      flow, = build_flow(LoginGov::OidcSinatra::Loadtest::Flows::AuthOnly, routes)

      expect { flow.run(user: sign_in_user) }.
        to raise_error(LoginGov::OidcSinatra::Loadtest::Error, /prefill_otp_codes/)
    end

    it 'surfaces IdP error copy when the relying party does not sign in' do
      routes = sign_in_routes.merge(
        'localhost:3000/' => ->(method, _p) { method == :post ? OTP_PAGE : SIGN_IN_PAGE },
        'localhost:9292/auth/result' =>
          '<div class="usa-alert--error"><p>Invalid credentials.</p></div>',
      )
      flow, = build_flow(LoginGov::OidcSinatra::Loadtest::Flows::AuthOnly, routes)

      expect { flow.run(user: sign_in_user) }.
        to raise_error(LoginGov::OidcSinatra::Loadtest::Error, /Invalid credentials/)
    end

    it 'records which step failed' do
      routes = sign_in_routes.merge('localhost:3000/' => '<p>nothing here</p>')
      flow, = build_flow(LoginGov::OidcSinatra::Loadtest::Flows::AuthOnly, routes)

      expect { flow.run(user: sign_in_user) }.
        to raise_error(LoginGov::OidcSinatra::Loadtest::Error)
      expect(recorder.failed_step).to eq('sign_in_submit')
    end

    it 'stops rather than looping when an interstitial will not clear' do
      stuck_page = <<~HTML
        <form action="/sign_up/completed" method="post">
          <input type="hidden" name="authenticity_token" value="t">
        </form>
      HTML
      routes = sign_in_routes.merge(
        'localhost:3000/' => ->(method, _p) { method == :post ? OTP_PAGE : SIGN_IN_PAGE },
        'localhost:3000/login/two_factor' => stuck_page,
        'localhost:3000/sign_up/completed' => stuck_page,
      )
      flow, = build_flow(LoginGov::OidcSinatra::Loadtest::Flows::AuthOnly, routes)

      expect { flow.run(user: sign_in_user) }.
        to raise_error(LoginGov::OidcSinatra::Loadtest::Error, /did not clear/)
    end
  end

  describe LoginGov::OidcSinatra::Loadtest::Flows::Signup do
    # identity-idp renders this at the IdP root for an unauthenticated,
    # non-prompt=create request (OpenidConnect::AuthorizationController
    # #redirect_to_sign_in_or_create -> new_user_session_url), with a "Create
    # an account" link pointing at /sign_up/enter_email (devise/sessions/new).
    let(:sign_in_page) do
      <<~HTML
        <form action="/" method="post">
          <input type="hidden" name="authenticity_token" value="signin-token">
          <input name="user[email]"><input name="user[password]">
        </form>
        <a href="/sign_up/enter_email">Create an account</a>
      HTML
    end
    let(:email_page) do
      <<~HTML
        <form action="/sign_up/enter_email" method="post">
          <input type="hidden" name="authenticity_token" value="email-token">
          <input type="hidden" name="user[recaptcha_token]" value="mock_token">
        </form>
      HTML
    end
    let(:verify_page) do
      '<a id="confirm-now" href="/sign_up/email/confirm?confirmation_token=tok">CONFIRM NOW</a>'
    end
    let(:password_page) do
      <<~HTML
        <form action="/sign_up/create_password" method="post">
          <input type="hidden" name="authenticity_token" value="pw-token">
          <input type="hidden" name="password_form[confirmation_token]" value="tok">
        </form>
      HTML
    end
    let(:mfa_page) do
      <<~HTML
        <form action="/authentication_methods_setup" method="post">
          <input type="hidden" name="_method" value="patch">
          <input type="hidden" name="authenticity_token" value="mfa-token">
        </form>
      HTML
    end
    let(:phone_page) do
      <<~HTML
        <form action="/phone_setup" method="post">
          <input type="hidden" name="authenticity_token" value="phone-token">
        </form>
      HTML
    end

    # Default routes: the RP sends no prompt, so the IdP lands the harness on
    # the sign-in page first, matching an unregistered real user.
    let(:routes) do
      {
        'localhost:9292/auth/request' =>
          [:redirect, 'http://localhost:3000/openid_connect/authorize'],
        'localhost:3000/openid_connect/authorize' =>
          [:redirect, 'http://localhost:3000/'],
        'localhost:3000/' => sign_in_page,
        'localhost:3000/sign_up/enter_email' =>
          ->(method, _p) { method == :post ? verify_page : email_page },
        'localhost:3000/sign_up/email/confirm' => password_page,
        'localhost:3000/sign_up/create_password' => mfa_page,
        'localhost:3000/authentication_methods_setup' => phone_page,
        'localhost:3000/phone_setup' => OTP_PAGE,
        'localhost:3000/login/two_factor' => HANDOFF,
        'localhost:9292/auth/result' => RP_SUCCESS_PAGE,
      }
    end

    # Routes for short_circuit_to_registration: true, where the RP sends
    # prompt=create and the IdP redirects straight to /sign_up/enter_email,
    # skipping the sign-in page entirely.
    let(:short_circuit_routes) do
      routes.merge(
        'localhost:9292/auth/request' =>
          [:redirect, 'http://localhost:3000/openid_connect/authorize?prompt=create'],
        'localhost:3000/openid_connect/authorize' =>
          [:redirect, 'http://localhost:3000/sign_up/enter_email'],
      )
    end

    let(:user) do
      {
        email: 'loadtest+abc@example.com',
        password: 'loadtest sturdy pass w0rd',
        phone: '202-555-1212',
      }
    end

    def run_signup(overrides = {})
      flow, http = build_flow(described_class, routes.merge(overrides))
      flow.run(user: user)
      http
    end

    def run_short_circuit_signup(overrides = {})
      flow, http = build_flow(
        described_class,
        short_circuit_routes.merge(overrides),
        config: config_with_short_circuit,
      )
      flow.run(user: user)
      http
    end

    describe 'the default path, via the sign-in page' do
      it 'lands on the sign-in page before registering, like a real unregistered user' do
        expect(run_signup.urls).to include(a_string_matching(%r{localhost:3000/\z}))
      end

      it 'does not send prompt=create' do
        expect(run_signup.urls.first).not_to include('initiate_registration=1')
      end

      it 'clicks through to registration via the "Create an account" link' do
        expect(run_signup.request_for('/sign_up/enter_email')).not_to be_nil
      end

      it 'names what is missing when the sign-in page has no create-account link' do
        flow, = build_flow(
          described_class,
          routes.merge('localhost:3000/' => '<form action="/" method="post"></form>'),
        )

        expect { flow.run(user: user) }.to raise_error(
          LoginGov::OidcSinatra::Loadtest::Error,
          /"Create an account" link/,
        )
      end
    end

    describe 'short_circuit_to_registration: true' do
      it 'asks the relying party to initiate registration' do
        expect(run_short_circuit_signup.urls.first).to include('initiate_registration=1')
      end

      it 'never visits the sign-in page' do
        expect(run_short_circuit_signup.urls).not_to include(a_string_matching(%r{localhost:3000/\z}))
      end

      it 'sends scopes with the bracket-suffixed key' do
        first_url = run_short_circuit_signup.urls.first
        expect(first_url).to include('requested_scopes%5B%5D=')
        expect(first_url).not_to match(/[?&]requested_scopes=/)
      end
    end

    it 'sends scopes with the bracket-suffixed key' do
      first_url = run_signup.urls.first
      expect(first_url).to include('requested_scopes%5B%5D=')
      expect(first_url).not_to match(/[?&]requested_scopes=/)
    end

    it 'accepts the terms of service, which registration requires' do
      expect(run_signup.request_with_param('user[email]').params).
        to include('user[terms_accepted]' => '1')
    end

    it 'registers the synthetic email address' do
      expect(run_signup.request_with_param('user[email]').params).
        to include('user[email]' => 'loadtest+abc@example.com')
    end

    it 'satisfies the mock captcha validator when the form renders its fields' do
      expect(run_signup.request_with_param('user[email]').params).
        to include('user[recaptcha_token]' => 'mock_token')
    end

    it 'follows the CONFIRM NOW link instead of waiting for email' do
      expect(run_signup.request_for('/sign_up/email/confirm').url).
        to include('confirmation_token=tok')
    end

    it 'sets the password and its confirmation to the same value' do
      expect(run_signup.request_with_param('password_form[password]').params).to include(
        'password_form[password]' => 'loadtest sturdy pass w0rd',
        'password_form[password_confirmation]' => 'loadtest sturdy pass w0rd',
      )
    end

    it 'carries the confirmation token scraped from the password form' do
      expect(run_signup.request_with_param('password_form[password]').params).
        to include('password_form[confirmation_token]' => 'tok')
    end

    # Submitted as a one-element array because the IdP renders the methods as a
    # checkbox group and permits `selection` as an array; HttpClient expands it
    # into a repeated `selection[]` pair on the wire.
    it 'selects phone as the authentication method' do
      expect(run_signup.request_with_param('two_factor_options_form[selection][]').params).
        to include('two_factor_options_form[selection][]' => ['phone'])
    end

    # The route is PATCH-only, but Rails reaches it by tunneling: the form is
    # POSTed with a hidden `_method=patch` that Rack::MethodOverride rewrites.
    # A genuine PATCH is rejected with 405, so the wire verb must be POST.
    it 'tunnels the MFA selection as a POST carrying _method=patch' do
      selection = run_signup.request_with_param('two_factor_options_form[selection][]')

      expect(selection.method).to eq(:post)
      expect(selection.params).to include('_method' => 'patch')
    end

    it 'submits the configured phone number for SMS delivery' do
      expect(run_signup.request_with_param('new_phone_form[phone]').params).to include(
        'new_phone_form[phone]' => '202-555-1212',
        'new_phone_form[otp_delivery_preference]' => 'sms',
      )
    end

    it 'confirms the phone with the prefilled code' do
      expect(run_signup.request_with_param('code').params).to include('code' => '123456')
    end

    it 'ends by handing off to the relying party' do
      expect(run_signup.urls.last).to include('localhost:9292/auth/result')
    end

    it 'walks the whole account creation sequence in order' do
      run_signup

      expect(recorder.steps.map { |step| step.fetch(:name) }).to eq(
        %w[
          rp_auth_request submit_email confirm_email create_password
          select_mfa submit_phone otp_submit interstitials handoff rp_result
        ],
      )
    end

    it 'names the load testing flag when the CONFIRM NOW link is missing' do
      flow, = build_flow(
        described_class,
        routes.merge(
          'localhost:3000/sign_up/enter_email' =>
            ->(method, _p) { method == :post ? '<p>Check your email</p>' : email_page },
        ),
      )

      expect { flow.run(user: user) }.to raise_error(
        LoginGov::OidcSinatra::Loadtest::Error,
        /enable_load_testing_mode/,
      )
    end
  end

  # Run a sign-in flow and return the flow and transport for inspection.
  def run_flow(flow_class, routes, user: sign_in_user)
    flow, http = build_flow(flow_class, routes)
    flow.run(user: user)
    [flow, http]
  end

  describe 'error handling' do
    it 'raises a clear error when the RP returns a 500' do
      error_routes = {
        'localhost:9292/auth/request' => lambda do |_method, _params|
          [500, 'Internal Server Error']
        end,
      }

      flow, = build_flow(LoginGov::OidcSinatra::Loadtest::Flows::AuthOnly, error_routes)

      expect { flow.run(user: sign_in_user) }.to raise_error(
        LoginGov::OidcSinatra::Loadtest::Error,
        /RP returned 500 for \/auth\/request/,
      )
    end
  end
end

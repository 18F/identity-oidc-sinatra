# frozen_string_literal: true

require 'dotenv/load'
require 'active_support/core_ext/hash/indifferent_access'
require 'active_support/core_ext/object/to_query'
require 'erubi'
require 'faraday'
require 'json'
require 'json/jwt'
require 'jwe'
require 'jwt'
require 'openssl'
require 'securerandom'
require 'sinatra/base'
require 'time'
require 'logger'
if ENV['NEW_RELIC_LICENSE_KEY'] && ENV['NEW_RELIC_APP_NAME']
  require 'newrelic_rpm'
  puts 'enabling newrelic'
end

require_relative './config'
require_relative './openid_configuration'
require_relative './attempts_configuration'
require_relative './lib/dpop'
require_relative './third_party_login'
require_relative './document_test_session'

module LoginGov::OidcSinatra
  JWT_CLIENT_ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
  ALLOWED_PLAINTEXT_KEYS = %w[
    application_url
    aws_region
    client_port
    client_user_agent
    email_already_registered
    failure_reason
    language
    mfa_device_type
    occurred_at
    otp_delivery_method
    rate_limit_type
    reauthentication
    reproof
    resend
    success
    unique_session_id
    user_agent
  ]

  class AppError < StandardError; end

  class OpenidConnectRelyingParty < Sinatra::Base
    DOCUMENT_TEST_KINDS = %w[userinfo front back passport selfie].freeze
    set :erb, escape_html: true
    set :logger, proc { Logger.new(ENV['RACK_ENV'] == 'test' ? nil : $stdout) }

    if ENV['ENABLE_LOGGING'] == 'true'
        enable :logging, :dump_errors, :raise_errors, :show_exceptions
        settings.logger.info('enabling logging')
    end

    enable :sessions
    use Rack::Protection
    use Rack::Protection::AuthenticityToken

    configure :development do
      require 'byebug'
    end

    # rubocop:disable Metrics/BlockLength
    helpers ThirdPartyLogin

    helpers do
      def ial_select_options
        options = [
          ['1', 'Authentication only (default)'],
          ['2', 'Identity-verified'],
          ['0', 'IALMax'],
          ['step-up', 'Step-up Flow'],
          ['facial-match-preferred', 'Facial Match Preferred (ACR)'],
          ['facial-match-required', 'Facial Match Required (ACR)'],
        ]

        if config.eipp_allowed?
          options << [
            'enhanced-ipp-required', 'Enhanced In-Person Proofing (Enabled in dev & staging only)',
          ]
        end

        options
      end

      def scope_options
        # https://developers.login.gov/attributes/
        %w[
          sub
          email
          all_emails
          locale
          ial
          aal
          profile
          given_name
          family_name
          address
          phone
          birthdate
          social_security_number
          verified_at
          x509
          x509_issuer
          x509_subject
          x509_presented
        ] + target_options
      end

      def target_options
        config.targets.map do |target|
          "token_exchange:#{target['scope']}"
        end
      end

      def default_scopes_by_ial
        ial2_options = [
          '2',
          'facial-match-preferred',
          'facial-match-required',
          'enhanced-ipp-required',
        ]

        default_scopes_by_ial = {
          nil => %w[openid email x509],
          '0' => %w[openid email social_security_number x509],
          '1' => %w[openid email x509],
        }

        ial2_options.each do |ial2_option|
          default_scopes_by_ial[ial2_option] = %w[
            openid
            email
            profile
            social_security_number
            phone
            address
            x509
          ]
        end

        default_scopes_by_ial
      end

      def csrf_tag
        "<input type='hidden' name='authenticity_token' value='#{session[:csrf]}' />"
      end

      def attempts_events(ack: nil)
        auth = "Bearer #{client_id} #{config.attempts_shared_secret}"

        params = {
          maxEvents: 100,
          ack:,
        }

        connection = Faraday.new(
          url: config.attempts_url,
          params: params.compact,
          headers:{'Authorization' => auth },
        )

        response = connection.post
        if response.status != 200 && ENV['ENABLE_LOGGING'] == 'true'
          # rubocop:disable Layout/LineLength
          settings.logger.info("got !200 trying to query #{config.attempts_url} ")
          # rubocop:enable Layout/LineLength
        end
        raise AppError.new(response.body) if response.status != 200

        sets = JSON.parse(connection.post.body)['sets']

        sets.values.map do |jwe|
          jwe = JWE.decrypt(jwe, config.sp_private_key)
          if config.signed_events?
            jwe = JWT.decode(
              jwe,
              attempts_public_key,
              true,
              { algorithm: 'ES256' },
            ).first
          end

          jwe
        end
      end

      def event_data(event)
        return event.first if config.allow_all_events_plaintext

        redact_data(event.first, {})
      end

      def redact_data(event_data, hash)
        event_data.each_with_object(hash) do |(k, v), hash|
          if v.is_a?(Hash)
            hash[k] = redact_data(v, {})
          else
            if ALLOWED_PLAINTEXT_KEYS.include?(k)
              hash[k] = v
            else
              hash[k] = 'REDACTED'  
            end
          end
        end
      end
    end
    # rubocop:enable Metrics/BlockLength

    def config
      @config ||= Config.new
    end

    def document_test_response(kind:, mode:, token_value:)
      path = kind == 'userinfo' ? '/api/openid_connect/userinfo' :
        "/api/openid_connect/document_images/#{kind}"
      request_headers = {}
      
      if mode == 'current'
        request_headers['Authorization'] = "Bearer #{token_value}" 
      elsif mode == 'invalid'
        request_headers['Authorization'] = 'Bearer intentionally-invalid-test-token'
      end
      # Fixed paths on the configured IdP only; never follow claim URLs or redirects.
      Faraday.new(url: config.idp_url, headers: request_headers) do |connection|
        connection.options.timeout = 15
        connection.options.open_timeout = 5
      end.get(path)
    end

    def document_test_report(response:, kind:)
      report = {
        status: response.status,
        content_type: response.headers['content-type'],
        cache_control: response.headers['cache-control'],
        pragma: response.headers['pragma'],
        nosniff: response.headers['x-content-type-options'],
        bytes: response.body.bytesize,
      }
      if kind == 'userinfo' && response.status == 200
        data = JSON.parse(response.body)
        halt 502, 'IdP returned a non-object userinfo response.' unless data.is_a?(Hash)
        report[:claims] = %w[document_images document_metadata].to_h do |claim|
          value = data[claim]
          state = 
            if !data.key?(claim)  
              'absent' 
            elsif value == {} 
              'empty object'
            else
              'present'
            end
          [claim, { state: state, value: value }]
        end
      end
      report
    end

    get '/document-artifacts' do
      headers 'Cache-Control' => 'no-store'
      test_token_available = !DocumentTestSession.get(session[:document_test_id]).nil?
      erb :document_artifacts, locals: { test_token_available: test_token_available }
    end

    post '/document-artifacts/check' do
      headers 'Cache-Control' => 'no-store'
      token_value = DocumentTestSession.get(session[:document_test_id])
      halt 409, 'Test session expired or missing. Start a new test sign-in.' unless token_value

      kind = params[:kind]
      halt 400, 'Unknown check' unless DOCUMENT_TEST_KINDS.include?(kind)
      mode = params[:token_mode]
      halt 400, 'Unknown token mode' unless %w[current missing invalid].include?(mode)
      response = document_test_response(kind: kind, mode: mode, token_value: token_value)
      report = document_test_report(response: response, kind: kind)
      erb :document_test_result, locals: { report: report, kind: kind }
    rescue Faraday::Error, JSON::ParserError
      halt 502, 'IdP unavailable or returned invalid JSON. No successful result recorded.'
    end

    post '/document-artifacts/clear' do
      DocumentTestSession.delete(session.delete(:document_test_id))
      redirect '/document-artifacts'
    end

    get '/' do
      login_msg = session.delete(:login_msg)
      logout_msg = session.delete(:logout_msg)
      user_email = session[:email]
      userinfo = session.delete(:userinfo)
      error = session.delete(:error)
      error_type = session.delete(:error_type)
      session.delete(:broker_request)
      session.delete(:selected_target)

      ial = prepare_step_up_flow(session:)

      erb :index, locals: {
        ial: ial,
        aal: params[:aal],
        login_msg: login_msg,
        logout_msg: logout_msg,
        user_email: user_email,
        logout_uri: error.present? ? nil : logout_uri,
        userinfo: userinfo,
        error:,
        error_type:,
        third_party_initiated_from: user_email ? session[:third_party_initiated_from] : nil,
      }
    rescue AppError => e
      render_error('Application', e)
    rescue Errno::ECONNREFUSED, Faraday::ConnectionFailed => e
      render_error('Connection', e)
    end

    get '/auth/request' do
      DocumentTestSession.delete(session.delete(:document_test_id))
      session[:document_test] = params[:document_test] == '1'
      simulate_csp_issue_if_selected(session: session, simulate_csp: params[:simulate_csp])
      prompt = params[:initiate_registration] ? 'create' : 'select_account'
      session[:broker_request] = params[:initiate_broker_token_exchange]
      session[:token_scope] = get_token_scope(params[:requested_scopes] || [])

      ial = prepare_step_up_flow(session:)
      auth_url = begin_login_gov_sign_in(
        ial:, aal: params[:aal], scopes: params[:requested_scopes] || [], prompt:,
      )

      settings.logger.info("Redirecting to #{auth_url}")

      redirect to(auth_url)
    rescue Errno::ECONNREFUSED, Faraday::ConnectionFailed => e
      render_error('Connection', e)
    end

    # The login-initiation address this agency registers (OpenID Connect Core 1.0 §4, Initiating
    # Login from a Third Party). A service provider that needs the person to hold an identity here
    # before delegation sends the browser with `iss`, `login_hint` and `target_link_uri`; after the
    # §4 checks pass, the agency runs its ordinary Login.gov sign-in and, once it completes, returns
    # the person to `target_link_uri`. Nothing is delegated here and no token is exchanged: this is
    # the agency's own sign-in, with its own consent, events and billing, and the person already
    # holds a Login.gov session, so Login.gov signs them in without asking for credentials again.
    get '/initiate_login' do
      handoff = validate_third_party_initiation!(params)
      remember_third_party_handoff(**handoff)

      # The hint is not forwarded: Login.gov identifies the person from its own session, and the
      # hint means nothing to it.
      auth_url = begin_login_gov_sign_in(
        ial: config.third_party_sign_in_ial,
        aal: nil,
        scopes: default_scopes_by_ial[config.third_party_sign_in_ial] - ['openid'],
        prompt: 'select_account',
      )

      settings.logger.info(
        "third-party-initiated login from #{handoff[:target_link_uri]}; redirecting to Login.gov",
      )
      redirect to(auth_url)
    rescue ThirdPartyLogin::InvalidInitiation => e
      # Refused before anything was stored or redirected; the person stays where they are.
      halt 400, { 'Content-Type' => 'text/plain' }, "Cannot start sign-in: #{e.message}"
    rescue Errno::ECONNREFUSED, Faraday::ConnectionFailed => e
      render_error('Connection', e)
    end

    # rubocop:disable Metrics/BlockLength
    get '/auth/result' do
      code = params[:code] 
      error = params[:error]

      if error.present?
        msg = (error == 'access_denied') ? 'You chose to exit before signing in' : error
        return sign_in_failed('Authentication', msg)
      end
      return sign_in_failed('Authentication', 'missing callback param: code') if code.nil?

      return sign_in_failed('Authentication', 'invalid state') if session[:state] != params[:state]

      token_response = token(code)
      access_token = token_response[:access_token]

      if session[:broker_request] == 'true'
        token_output = token_exchange(access_token)
        session[:access_token] = token_output['access_token']
        session[:access_token_type] = token_output['token_type']
        redirect to('/target')
      end

      id_token = token_response[:id_token]
      jwt = JWT.decode(id_token, idp_public_key, true, algorithm: 'RS256', leeway: 10).first

      return sign_in_failed('Authentication', 'invalid nonce') if jwt['nonce'] != session[:nonce]

      if session.delete(:document_test)
        session[:document_test_id] = DocumentTestSession.put(access_token)
        session.delete(:nonce)
        session.delete(:state)
        redirect '/document-artifacts'
      end

      userinfo_response = userinfo(access_token)
      session.delete(:nonce)
      session.delete(:state)

      if session.delete(:step_up_enabled)
        aal = session.delete(:step_up_aal)

        redirect to("/auth/request?aal=#{aal}&ial=2")
      elsif session.delete(:simulate_csp)
        redirect to('https://www.example.com/')
      else
        session[:login_msg] = 'ok'
        session[:userinfo] = userinfo_response
        session[:email] = session[:userinfo][:email]

        handoff = take_third_party_handoff
        if handoff
          # OpenID Connect Core 1.0 §4: the sign-in a third party started has completed, so the
          # person goes back to `target_link_uri`. The hand-off is consumed above, so a later
          # sign-in in this browser ends on this page as usual.
          session[:third_party_initiated_from] = URI.parse(handoff[:target_link_uri]).host
          redirect to(third_party_return_url(handoff, status: 'signed_in'))
        end

        redirect to('/')
      end
    rescue AppError => e
      sign_in_failed('Application', e.message)
    end


    get '/failure_to_proof' do
      render_error('Proofing', 'We were unable to verify your identity')
    end

    post '/handle-logout' do
      DocumentTestSession.delete(session.delete(:document_test_id))
      session.delete(:userinfo)
      session.delete(:email)
      session.delete(:third_party_initiated_from)
      session.delete(:step_up_enabled)
      session.delete(:step_up_aal)
      session.delete(:irs)

      redirect to(logout_uri)
    end

    get '/logout' do
      session[:logout_msg] = 'ok'
      redirect to('/')
    end

    get '/api/health' do

      content_type :json
      {
        authorization_endpoint: openid_configuration.fetch('authorization_endpoint'),
        private_key_fingerprint: Digest::SHA1.hexdigest(config.sp_private_key.to_der),
        healthy: true,
      }.to_json
    rescue StandardError => e
      halt 500, {
        error: e.inspect,
        healthy: false,
      }.to_json

    end

    get '/attempts-api' do
      erb :attempts, locals: {
        attempts_events: attempts_events,
      }
    end

    post '/ack-events' do
      ack = params[:jtis].split(',')
      attempts_events(ack:)

      redirect to('attempts-api')
    end

    get '/target' do
      erb :target, locals: {
        targets: config.targets,
        selected_target: session[:token_scope],
        token_type: session[:access_token_type],
        bound: session[:access_token_type] == 'DPoP',
      }
    end

    # A key-bound delegated token (token_type DPoP) must reach the agency API with a proof signed by
    # the key, which a browser redirect cannot carry; the sample calls the API itself and shows the
    # answer. A bearer token keeps the redirect.
    post '/send-access-token' do
      metadata = config.targets.find { |target| target['issuer'] == params['target'] }
      token = session[:access_token]

      if session[:access_token_type] == 'DPoP'
        proof = Dpop.proof(key: dpop_key, method: 'GET', url: metadata['api'], access_token: token)
        response = Faraday.get(
          metadata['api'], nil, 'Authorization' => "DPoP #{token}", 'DPoP' => proof
        )
        content_type :json
        halt response.status, response.body
      end

      redirect to("#{metadata['api']}?#{{ access_token: token }.to_query}")
    end

    # The agency API's side of a delegated token. The token is the JWE Login.gov sealed to this
    # service's certificate; its claims are signed by Login.gov. A token that carries cnf.jkt is
    # bound to the actor's key (RFC 9449 §6.1): it must arrive under the DPoP scheme with a proof
    # signed by that key for this request, and is refused as a Bearer token (§7.1). A token without
    # cnf is a bearer token and is accepted as such.
    get '/api/records' do
      content_type :json
      scheme, token = request.env['HTTP_AUTHORIZATION'].to_s.split(' ', 2)
      refuse_token('missing token') if token.nil?

      claims = decrypt_and_verify_delegated_token(token)
      jkt = claims.dig('cnf', 'jkt')

      if jkt
        unless scheme == 'DPoP'
          refuse_token('this token is bound to a key: present it with the DPoP scheme and a proof')
        end
        Dpop.verify_proof(
          proof: request.env['HTTP_DPOP'],
          method: request.request_method,
          url: request.url,
          access_token: token,
          expected_thumbprint: jkt,
        )
      elsif scheme != 'Bearer'
        refuse_token(
          'this token is not bound to a key: present it as a Bearer token', challenge: false
        )
      end

      { sub: claims['sub'], act: claims['act'], scope: claims['scope'], bound: !jkt.nil? }.to_json
    rescue Dpop::ProofError => e
      body = { error: 'invalid_dpop_proof', error_description: e.message }.to_json
      halt 401, dpop_challenge, body
    rescue JWT::DecodeError, JWE::DecodeError, OpenSSL::OpenSSLError => e
      halt 401, { error: 'invalid_token', error_description: e.message }.to_json
    end

    private

    # A sign-in that did not complete: the usual error page, or, when a third party started the
    # sign-in (OpenID Connect Core 1.0 §4), the return to `target_link_uri` with `status=failed` so
    # the third party shows its own message; the hand-off is consumed either way.
    def sign_in_failed(error_type, error)
      handoff = take_third_party_handoff
      return render_error(error_type, error) if handoff.nil?

      settings.logger.info("third-party-initiated login failed: #{error_type}: #{error}")
      redirect to(third_party_return_url(handoff, status: 'failed'))
    end

    # Starts the Login.gov authorization code flow: fresh `state` and `nonce`, the PKCE verifier and
    # the DPoP key when enabled, then the authorize URL. Shared by the sign-in button and by
    # third-party-initiated login so both produce the same request to Login.gov.
    def begin_login_gov_sign_in(ial:, aal:, scopes:, prompt:)
      session[:state] = random_value
      session[:nonce] = random_value
      session[:code_verifier] = random_value if use_pkce?
      session[:dpop_key] = Dpop.generate_key.to_pem if use_dpop?

      authorization_url(
        state: session[:state],
        nonce: session[:nonce],
        ial:,
        aal:,
        scopes:,
        code_verifier: session[:code_verifier],
        dpop_jkt: (Dpop.thumbprint(dpop_key) if use_dpop?),
        prompt:,
      )
    end

    def render_error(error_type, error=nil)
      session[:error] = error.to_s || 'Unknown error occurred'
      session[:error_type] = error_type
      
      redirect to('/')
    end

    def authorization_url(
      state:, nonce:, ial:, scopes:, aal:, code_verifier:, prompt:, dpop_jkt: nil
    )
      endpoint = openid_configuration[:authorization_endpoint]
      request_params = {
        client_id: client_id,
        response_type: 'code',
        acr_values: acr_values(ial: ial, aal: aal),
        scope: scopes.join(' ') + ' openid',
        redirect_uri: File.join(config.redirect_uri, '/auth/result'),
        state: state,
        nonce: nonce,
        attempts_api_session_id: SecureRandom.uuid,
        prompt:,
      }

      if code_verifier
        request_params[:code_challenge] = url_safe_code_challenge(code_verifier)
        request_params[:code_challenge_method] = 'S256'
      end

      # RFC 9449 §10: naming the key's thumbprint binds the authorization code to it, so an
      # intercepted code cannot be redeemed with another key.
      request_params[:dpop_jkt] = dpop_jkt if dpop_jkt

      "#{endpoint}?#{request_params.compact.to_query}"
    end

    def simulate_csp_issue_if_selected(session:, simulate_csp:)
      if simulate_csp
        session[:simulate_csp] = 'true'
      else
        session.delete(:simulate_csp)
      end
    end

    def prepare_step_up_flow(session:)
      ial = params[:ial]
      aal = params[:aal]
      if ial == 'step-up'
        ial = '1'
        session[:step_up_enabled] = 'true'
        session[:step_up_aal] = aal if /^\d$/.match?(aal)
      else
        session.delete(:step_up_enabled)
        session.delete(:step_up_aal)
      end

      ial
    end

    def acr_values(ial:, aal:)
      values = []

      values << (semantic_ial_values_enabled? ? semantic_ial_values[ial] : legacy_ial_values[ial])

      values << {
        '2' => 'http://idmanagement.gov/ns/assurance/aal/2',
        '2-phishing_resistant' => 'http://idmanagement.gov/ns/assurance/aal/2?phishing_resistant=true',
        '2-hspd12' => 'http://idmanagement.gov/ns/assurance/aal/2?hspd12=true',
      }[aal]

      values.compact.join(' ')
    end

    def legacy_ial_values
      {
        '0' => 'http://idmanagement.gov/ns/assurance/ial/0',
        '1' => 'http://idmanagement.gov/ns/assurance/ial/1',
        nil => 'http://idmanagement.gov/ns/assurance/ial/1',
        '2' => 'http://idmanagement.gov/ns/assurance/ial/2',
        'facial-match-preferred' => 'http://idmanagement.gov/ns/assurance/ial/2?bio=preferred',
        'facial-match-required' => 'http://idmanagement.gov/ns/assurance/ial/2?bio=required',
      }
    end

    def semantic_ial_values
      {
        '0' => 'http://idmanagement.gov/ns/assurance/ial/0',
        '1' => 'urn:acr.login.gov:auth-only',
        nil => 'urn:acr.login.gov:auth-only',
        '2' => 'urn:acr.login.gov:verified',
        'facial-match-required' => 'urn:acr.login.gov:verified-facial-match-required',
        'facial-match-preferred' => 'urn:acr.login.gov:verified-facial-match-preferred',
      }
    end

    def semantic_ial_values_enabled?
      ENV['semantic_ial_values_enabled'] == 'true'
    end

    def use_pkce?
      ENV['PKCE'] == 'true'
    end

    # Key binding applies to a public client only: it has no client secret, so the key it holds is
    # what makes a stolen token useless. Login.gov lists the clients it expects to bind.
    def use_dpop?
      use_pkce? && ENV['DPOP'] == 'true'
    end

    def dpop_key
      Dpop.key_from_pem(session[:dpop_key])
    end

    # The DPoP header for one request to Login.gov's token endpoint: a fresh proof for POST to that
    # URL, with ath over the token when one is presented.
    def dpop_headers(access_token: nil)
      return {} unless use_dpop?

      proof = Dpop.proof(
        key: dpop_key, method: 'POST', url: openid_configuration[:token_endpoint], access_token:,
      )
      { 'DPoP' => proof }
    end

    def dpop_challenge
      { 'WWW-Authenticate' => 'DPoP algs="ES256 RS256"' }
    end

    def refuse_token(description, challenge: true)
      body = { error: 'invalid_token', error_description: description }.to_json
      halt 401, (challenge ? dpop_challenge : {}), body
    end

    # The agency opens the JWE with its own private key and verifies Login.gov's signature against
    # the published keys. The claims are trusted only after both, and only when the token was
    # issued by this service's Login.gov (`iss`) for this service (`aud`, RFC 7519 §4.1.3): a
    # delegated token meant for another agency opens with the same demo key but is not accepted.
    def decrypt_and_verify_delegated_token(token)
      jwt = JWE.decrypt(token, config.sp_private_key)
      JWT.decode(
        jwt,
        idp_public_key,
        true,
        algorithm: 'RS256',
        leeway: 10,
        verify_iss: true,
        iss: idp_domain,
        verify_aud: true,
        aud: client_id,
      ).first
    end

    # Login.gov names itself by host in `iss`; the sample knows it by URL.
    def idp_domain
      uri = URI.parse(config.idp_url)
      uri.port == uri.default_port ? uri.host : "#{uri.host}:#{uri.port}"
    end

    def openid_configuration
      if config.cache_oidc_config?
        OpenidConfiguration.cached
      else
        OpenidConfiguration.live
      end
    end

    def idp_public_key
      if config.cache_oidc_config?
        OpenidConfiguration.cached_idp_public_key(openid_configuration)
      else
        OpenidConfiguration.live_idp_public_key(openid_configuration)
      end
    end

    def attempts_config
      AttemptsConfiguration.cached
    end

    def attempts_public_key
      AttemptsConfiguration.cached_attempts_public_key(attempts_config)
    end

    def get_token_scope(scopes)
      scope = scopes.find { |scope| scope.match(/token_exchange:(.+)/) }
      return unless scope 
      
      scope.delete_prefix('token_exchange:')
    end

    def token(code)
      token_params = {
        grant_type: 'authorization_code',
        code: code,
      }

      if use_pkce?
        token_params[:code_verifier] = session[:code_verifier]
      else
        token_params[:client_assertion_type] = JWT_CLIENT_ASSERTION_TYPE
        token_params[:client_assertion] = client_assertion_jwt
      end

      response = Faraday.post(
        openid_configuration[:token_endpoint],
        token_params,
        dpop_headers,
      )
      if response.status != 200 && ENV['ENABLE_LOGGING'] == 'true'
        # rubocop:disable Layout/LineLength
        settings.logger.info("got !200 trying to query #{openid_configuration[:token_endpoint]} with #{token_params}")
        # rubocop:enable Layout/LineLength
      end
      raise AppError.new(response.body) if response.status != 200
      json response.body
    end

    def client_assertion_jwt
      jwt_payload = {
        iss: client_id,
        sub: client_id,
        aud: openid_configuration[:token_endpoint],
        jti: random_value,
        exp: Time.now.to_i + 1000,
      }

      JWT.encode(jwt_payload, config.sp_private_key, 'RS256')
    end

    def userinfo(access_token)
      url = openid_configuration[:userinfo_endpoint]

      connection = Faraday.new(url: url, headers:{'Authorization' => "Bearer #{access_token}" })
      JSON.parse(connection.get('').body).with_indifferent_access
    end

    # RFC 8693: the subject token is the token the code exchange returned; the audience names the
    # agency application and the resource its API. For a key-bound client the proof carries ath over
    # the subject token, so the delegated token Login.gov issues is bound to the same key.
    def token_exchange(subject_token)
      token_metadata = config.targets.find { |target| target['scope'] == session[:token_scope] }

      token_params = {
        grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
        client_id:,
        subject_token:,
        subject_token_type: 'urn:ietf:params:oauth:token-type:access_token',
        audience: token_metadata['issuer'],
        resource: token_metadata['api'],
        requested_token_type: 'urn:ietf:params:oauth:token-type:access_token',
      }

      response = Faraday.post(
        openid_configuration[:token_endpoint],
        token_params,
        dpop_headers(access_token: subject_token),
      )
      raise AppError.new(response.body) if response.status != 200

      json response.body
    end

    def client_id
      use_pkce? ? config.client_id_pkce : config.client_id
    end

    def logout_uri
      endpoint = openid_configuration[:end_session_endpoint]
      request_params = {
        client_id: client_id,
        post_logout_redirect_uri: File.join(config.redirect_uri, 'logout'),
        state: SecureRandom.hex,
      }.to_query

      "#{endpoint}?#{request_params}"
    end

    def json(response)
      JSON.parse(response.to_s).with_indifferent_access
    end

    def random_value
      SecureRandom.hex
    end

    def url_safe_code_challenge(code_verifier)
      Base64.urlsafe_encode64(Digest::SHA256.digest(code_verifier))
    end

    def maybe_redact_ssn(ssn)
      if config.redact_ssn?
        # redact all characters since they're all sensitive
        ssn = ssn&.gsub(/\d/, '#')
      end

      ssn
    end
  end
end

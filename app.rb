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
require_relative './resource_server'
require_relative './demo_records'

module LoginGov::OidcSinatra
  JWT_CLIENT_ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
  ALLOWED_PLAINTEXT_KEYS = %w[
    aal
    actor_issuer
    application_url
    aws_region
    client_port
    client_user_agent
    delegation_id
    email_already_registered
    failure_reason
    ial
    language
    mfa_device_type
    occurred_at
    otp_delivery_method
    rate_limit_type
    reason
    reauthentication
    remembered
    reproof
    resend
    resource
    resources
    scopes
    success
    token_format
    unique_session_id
    user_agent
  ]

  # §8 — event types Login.gov delivers to a target agency for delegated access,
  # in addition to the re-mapped sign-in events (which carry `delegation_id`).
  DELEGATION_EVENT_TYPES = {
    'delegated-access-consented' =>
      'The user approved letting a service provider (actor_issuer) act for them at ' \
      'this agency\'s API(s) (scopes, resources). remembered: true means a remembered ' \
      'grant was reused without a new consent screen.',
    'delegated-access-token-issued' =>
      'The service provider exchanged its token for a delegated token bound to ' \
      'one resource (resource, scopes, ial, aal, token_format).',
    'delegated-access-token-refreshed' =>
      'The service provider refreshed the delegated token family; no new consent, ' \
      'no new billing row.',
    'delegated-access-revoked' =>
      'The grant or token family was revoked (reason: user revocation, ' \
      'refresh_token_reuse, account suspension, ...). Introspection now returns ' \
      'active: false for every token in the family.',
  }.freeze

  class AppError < StandardError; end

  class OpenidConnectRelyingParty < Sinatra::Base
    set :erb, escape_html: true
    set :logger, proc { Logger.new(ENV['RACK_ENV'] == 'test' ? nil : $stdout) }

    if ENV['ENABLE_LOGGING'] == 'true'
        enable :logging, :dump_errors, :raise_errors, :show_exceptions
        settings.logger.info('enabling logging')
    end

    enable :sessions
    # The resource server routes authenticate with a bearer token (RFC 6750)
    # and carry no session cookie, so browser CSRF protections do not apply.
    API_REQUEST = ->(env) { env['PATH_INFO'].to_s.start_with?('/records') }
    use Rack::Protection, allow_if: API_REQUEST
    use Rack::Protection::AuthenticityToken, allow_if: API_REQUEST

    configure :development do
      require 'byebug'
    end

    helpers ResourceServer

    # rubocop:disable Metrics/BlockLength
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
        ]
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

      # Poll the Attempts API in the agency role (§8.5, REF-IMPL-3).
      # Authorization is "Bearer <agency issuer> <shared secret>"; each event is
      # a JWE encrypted to the agency's SP certificate, so it is decrypted with
      # the same private key this app signs with (config/rs_demo.key). Events
      # arrive as a JWT (ES256) when the IdP signs them, otherwise as plain JSON.
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
          settings.logger.info("got !200 trying to query #{config.attempts_url} ")
        end
        raise AppError.new(response.body) if response.status != 200

        sets = JSON.parse(response.body)['sets'] || {}

        sets.values.map do |jwe|
          decrypted = JWE.decrypt(jwe, config.attempts_private_key)
          if config.signed_events?
            JWT.decode(
              decrypted,
              attempts_public_key,
              true,
              { algorithm: 'ES256' },
            ).first
          else
            JSON.parse(decrypted)
          end
        end
      end

      # "login-completed" from "https://schemas.login.gov/secevent/attempts-api/event-type/login-completed"
      def event_type(event)
        event['events'].keys.first.split('/').last
      end

      def event_property(event, key)
        event['events'].values.first&.[](key)
      end

      # §8.5 — any event carrying delegation_id or actor_issuer belongs to a
      # delegated session; its subject.session_id is the service provider's,
      # not one this agency started.
      def delegated_event?(event)
        !event_property(event, 'delegation_id').nil? ||
          !event_property(event, 'actor_issuer').nil?
      end

      # §8.5 — the join agencies implement: group Attempts events by
      # delegation_id and attach this API's decisions (from log_decision, keyed
      # by introspection's delegation_id, ATT-9/INT-4) with the same value.
      # Sessions that so far have only API decisions and no events are included
      # so a call is never invisible.
      # @return [Array<Hash>] newest activity first
      def delegated_sessions(events)
        by_id = events.group_by { |e| event_property(e, 'delegation_id') }
        by_id.delete(nil)

        decision_ids = DecisionLog.instance.entries.filter_map { |d| d['delegation_id'] }.uniq
        (by_id.keys | decision_ids).map do |delegation_id|
          session_events = (by_id[delegation_id] || []).sort_by { |e| e['iat'].to_i }
          decisions = DecisionLog.instance.for_delegation(delegation_id)
          actor_issuer = session_events.filter_map { |e| event_property(e, 'actor_issuer') }.first
          actor_issuer ||= decisions.filter_map { |d| d['actor'] }.first
          {
            delegation_id:,
            actor_issuer:,
            events: session_events,
            decisions:,
            last_activity: [
              session_events.map { |e| e['iat'].to_i }.max || 0,
              decisions.map { |d| Time.parse(d['time']).to_i }.max || 0,
            ].max,
          }
        end.sort_by { |s| -s[:last_activity] }
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

    get '/' do
      login_msg = session.delete(:login_msg)
      logout_msg = session.delete(:logout_msg)
      user_email = session[:email]
      userinfo = session.delete(:userinfo)
      error = session.delete(:error)
      error_type = session.delete(:error_type)

      ial = params[:ial]
      aal = params[:aal]

      ial = prepare_step_up_flow(session: session, ial: ial, aal: aal)

      erb :index, locals: {
        ial: ial,
        aal: aal,
        login_msg: login_msg,
        logout_msg: logout_msg,
        user_email: user_email,
        logout_uri: error.present? ? nil : logout_uri,
        userinfo: userinfo,
        error:,
        error_type:,
      }
    rescue AppError => e
      render_error('Application', e)
    rescue Errno::ECONNREFUSED, Faraday::ConnectionFailed => e
      render_error('Connection', e)
    end

    get '/auth/request' do
      simulate_csp_issue_if_selected(session: session, simulate_csp: params[:simulate_csp])
      prompt = params[:initiate_registration] ? 'create' : 'select_account'

      session[:state] = random_value
      session[:nonce] = random_value
      session[:code_verifier] = random_value if use_pkce?

      ial = prepare_step_up_flow(session: session, ial: params[:ial], aal: params[:aal])
      auth_url = authorization_url(
        state: session[:state],
        nonce: session[:nonce],
        ial: ial,
        aal: params[:aal],
        scopes: params[:requested_scopes] || [],
        code_verifier: session[:code_verifier],
        prompt:,
      )

      settings.logger.info("Redirecting to #{auth_url}")


      redirect to(auth_url)
    rescue Errno::ECONNREFUSED, Faraday::ConnectionFailed => e
      render_error('Connection', e)
    end

    # rubocop:disable Metrics/BlockLength
    get '/auth/result' do
      code = params[:code] 
      error = params[:error]

      if error.present?
        msg = (error == 'access_denied') ? 'You chose to exit before signing in' : error
        return render_error('Authentication', msg)
      end
      return render_error('Authentication', 'missing callback param: code') if code.nil?

      return render_error('Authentication', 'invalid state') if session[:state] != params[:state]

      token_response = token(code)
      access_token = token_response[:access_token]
      id_token = token_response[:id_token]
      jwt = JWT.decode(id_token, idp_public_key, true, algorithm: 'RS256', leeway: 10).first

      return render_error('Authentication', 'invalid nonce') if jwt['nonce'] != session[:nonce]

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

        redirect to('/')
      end
    rescue AppError => e
      render_error('Application', e.message)
    end

    get '/failure_to_proof' do
      render_error('Proofing', 'We were unable to verify your identity')
    end

    post '/handle-logout' do
      session.delete(:userinfo)
      session.delete(:email)
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
        resource_identifier: config.resource_identifier,
        introspection_endpoint: openid_configuration['introspection_endpoint'],
        healthy: true,
      }.to_json
    rescue StandardError => e
      halt 500, {
        error: e.inspect,
        healthy: false,
      }.to_json

    end

    # Agency-role Attempts API viewer. ?tab=events lists every event;
    # ?tab=delegated groups them by delegation_id with this API's decisions.
    get '/attempts-api' do
      events = attempts_events
      tab = params[:tab] == 'delegated' ? 'delegated' : 'events'
      erb :attempts, locals: {
        attempts_events: events,
        tab:,
        delegated_sessions: tab == 'delegated' ? delegated_sessions(events) : [],
      }
    rescue AppError => e
      render_error('Attempts API', e.message)
    rescue Errno::ECONNREFUSED, Faraday::ConnectionFailed => e
      render_error('Connection', e)
    end

    # ---------------------------------------------------------------------
    # Resource server routes (§14.4). Both require a delegated access token
    # obtained by a service provider through RFC 8693 token exchange, presented
    # per RFC 6750 §2.1. Scope decides which endpoint the token may reach.
    # ---------------------------------------------------------------------

    # Requires token_exchange:records_read (access_type read).
    get '/records' do
      authorize!('token_exchange:records_read')

      json_response(
        records: DemoRecords.instance.for_sub(@introspection['sub']),
        _introspection: @introspection,
      )
    end

    # Requires token_exchange:records_write (access_type read_write). A service
    # provider whose user approved only records_read gets 403 here.
    post '/records' do
      authorize!('token_exchange:records_write')

      record = DemoRecords.instance.create(@introspection['sub'], record_attributes)
      status 201
      json_response(record: record, _introspection: @introspection)
    end

    # Every authorization decision, newest first (REF-IMPL-2).
    get '/decisions' do
      erb :decisions, locals: { decisions: DecisionLog.instance.entries }
    end

    get '/decisions.json' do
      json_response(decisions: DecisionLog.instance.entries)
    end

    post '/ack-events' do
      ack = params[:jtis].split(',')
      attempts_events(ack:)

      redirect to('attempts-api')
    end

    private

    # Demo affordance (§14.4): API responses echo the introspection result under
    # `_introspection` so the service provider UI can show why a call was
    # allowed. It contains only identifiers. A production API would omit it.
    def json_response(payload)
      content_type :json
      JSON.pretty_generate(payload)
    end

    # POST /records accepts a JSON object or form fields (title, note).
    def record_attributes
      if request.media_type == 'application/json'
        body = JSON.parse(request.body.read.to_s.then { |b| b.empty? ? '{}' : b })
        halt 400, json_error_response('invalid_request', 'Body must be a JSON object.') unless
          body.is_a?(Hash)
        body
      else
        params.slice('title', 'note')
      end
    rescue JSON::ParserError
      halt 400, json_error_response('invalid_request', 'Body is not valid JSON.')
    end

    def render_error(error_type, error=nil)
      session[:error] = error.to_s || 'Unknown error occurred'
      session[:error_type] = error_type
      
      redirect to('/')
    end

    def authorization_url(state:, nonce:, ial:, scopes:, aal:, code_verifier:, prompt:)
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

      "#{endpoint}?#{request_params.compact.to_query}"
    end

    def simulate_csp_issue_if_selected(session:, simulate_csp:)
      if simulate_csp
        session[:simulate_csp] = 'true'
      else
        session.delete(:simulate_csp)
      end
    end

    def prepare_step_up_flow(session:, ial:, aal: nil)
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

    def client_id
      return config.mock_irs_client_id if session[:irs]

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

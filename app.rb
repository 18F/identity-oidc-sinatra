# frozen_string_literal: true

require 'dotenv/load'
require 'active_support/core_ext/hash/indifferent_access'
require 'active_support/core_ext/object/to_query'
require 'erubi'
require 'faraday'
require 'json'
require 'json/jwt'
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

module LoginGov::OidcSinatra
  JWT_CLIENT_ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'

  class AppError < StandardError; end

  class OpenidConnectRelyingParty < Sinatra::Base
    set :erb, escape_html: true
    set :logger, proc { Logger.new(ENV['RACK_ENV'] == 'test' ? nil : $stdout) }

    enable :sessions
    use Rack::Protection
    use Rack::Protection::AuthenticityToken

    configure :development do
      require 'byebug'
    end

    helpers do
      def ial_select_options
        options = [
          ['1', 'Authentication only (default)'],
          ['2', 'Identity-verified'],
          ['0', 'IALMax'],
          ['step-up', 'Step-up Flow'],
          ['biometric-comparison-vot', 'Biometric Comparison (VoT)'],
          ['biometric-comparison-preferred', 'Biometric Comparison Preferred (ACR)'],
          ['biometric-comparison-required', 'Biometric Comparison Required (ACR)'],
        ]

        if ENV.fetch('eipp_allowed', 'false') == 'true'
          options << [
            'enhanced-ipp-required', 'Enhanced In-Person Proofing (Enabled in staging only)',
          ]
        else
          options
        end
      end

      def csrf_tag
        "<input type='hidden' name='authenticity_token' value='#{session[:csrf]}' />"
      end
    end

    def config
      @config ||= Config.new
    end

    get '/' do
      login_msg = session.delete(:login_msg)
      logout_msg = session.delete(:logout_msg)
      user_email = session[:email]
      userinfo = session.delete(:userinfo)

      ial = params[:ial]
      aal = params[:aal]

      ial = prepare_step_up_flow(session: session, ial: ial, aal: aal)

      erb :index, locals: {
        ial: ial,
        aal: aal,
        login_msg: login_msg,
        logout_msg: logout_msg,
        user_email: user_email,
        logout_uri: logout_uri,
        userinfo: userinfo,
        access_denied: params[:error] == 'access_denied',
      }
    rescue AppError => e
      [500, erb(:errors, locals: { error: e.message })]
    rescue Errno::ECONNREFUSED, Faraday::ConnectionFailed => e
      [500, erb(:errors, locals: { error: e.inspect })]
    end

    get '/auth/request' do
      simulate_csp_issue_if_selected(session: session, simulate_csp: params[:simulate_csp])

      session[:state] = random_value
      session[:nonce] = random_value
      session[:code_verifier] = random_value if use_pkce?

      ial = prepare_step_up_flow(session: session, ial: params[:ial], aal: params[:aal])
      auth_url = authorization_url(
        state: session[:state],
        nonce: session[:nonce],
        ial: ial,
        aal: params[:aal],
        code_verifier: session[:code_verifier],
      )

      settings.logger.info("Redirecting to #{auth_url}")

      redirect to(auth_url)
    end

    # rubocop:disable Metrics/BlockLength
    get '/auth/result' do
      code = params[:code]
      error = params[:error]

      redirect to('/?error=access_denied') if error == 'access_denied'

      return render_error(error || 'missing callback param: code') unless code
      return render_error('invalid state') if session[:state] != params[:state]

      token_response = token(code)
      access_token = token_response[:access_token]
      id_token = token_response[:id_token]
      jwt = JWT.decode(id_token, idp_public_key, true, algorithm: 'RS256', leeway: 10).first

      return render_error('invalid nonce') if jwt['nonce'] != session[:nonce]

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
      [500, erb(:errors, locals: { error: e.message })]
    end

    get '/failure_to_proof' do
      erb :failure_to_proof
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
        healthy: true,
      }.to_json
    rescue StandardError => e
      halt 500, {
        error: e.inspect,
        healthy: false,
      }.to_json

    end




    private

    def render_error(error)
      erb :errors, locals: { error: error }
    end

    def authorization_url(state:, nonce:, ial:, aal:, code_verifier:)
      endpoint = openid_configuration[:authorization_endpoint]
      request_params = {
        client_id: client_id,
        response_type: 'code',
        acr_values: acr_values(ial: ial, aal: aal),
        vtr: vtr_value(ial: ial, aal: aal),
        vtm: vtm_value(ial:),
        scope: scopes_for(ial),
        redirect_uri: File.join(config.redirect_uri, '/auth/result'),
        state: state,
        nonce: nonce,
        prompt: 'select_account',
        enhanced_ipp_required: requires_enhanced_ipp?(ial),
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

    def scopes_for(ial)
      ial2_options = [
        '2',
        'biometric-comparison-preferred',
        'biometric-comparison-required',
        'biometric-comparison-vot',
        'enhanced-ipp-required',
      ]

      case ial
      when '0'
        'openid email social_security_number x509'
      when '1', nil
        'openid email x509'
      when *ial2_options
          'openid email profile social_security_number phone address x509'
      else
        raise ArgumentError.new("Unexpected IAL: #{ial.inspect}")
      end
    end

    def acr_values(ial:, aal:)
      return if requires_enhanced_ipp?(ial) || requires_biometric_vot?(ial)

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
        'biometric-comparison-preferred' => 'http://idmanagement.gov/ns/assurance/ial/2?bio=preferred',
        'biometric-comparison-required' => 'http://idmanagement.gov/ns/assurance/ial/2?bio=required',
      }
    end

    def semantic_ial_values
      {
        '0' => 'http://idmanagement.gov/ns/assurance/ial/0',
        '1' => 'urn:acr.login.gov:auth-only',
        nil => 'urn:acr.login.gov:auth-only',
        '2' => 'urn:acr.login.gov:verified',
        'biometric-comparison-required' => 'urn:acr.login.gov:verified-facial-match-required',
        'biometric-comparison-preferred' => 'urn:acr.login.gov:verified-facial-match-preferred',
      }
    end

    def vtr_value(ial:, aal:)
      return if does_not_require_enhanced_ipp?(ial) && does_not_require_biometric_vot?(ial)

      values = ['C1']

      values << {
        '2' => 'C2',
        '2-phishing_resistant' => 'C2.Ca',
        '2-hspd12' => 'C2.Cb',
      }[aal]

      values << {
        '2' => 'P1',
        'biometric-comparison-vot' => 'P1.Pb',
        'enhanced-ipp-required' => 'P1.Pe',
      }[ial]

      vtr_list = [values.compact.join('.')]

      if ial == '0'
        proofing_vector = values.dup + ['P1']
        vtr_list = [proofing_vector.compact.join('.'), *vtr_list]
      end

      vtr_list.to_json
    end

    def semantic_ial_values_enabled?
      ENV['semantic_ial_values_enabled'] == 'true'
    end

    def use_pkce?
      ENV['PKCE'] == 'true'
    end

    def vtm_value(ial)
      return if does_not_require_enhanced_ipp?(ial)
      'https://developer.login.gov/vot-trust-framework'
    end

    def requires_biometric_vot?(ial)
      return false if config.vtr_disabled?
      ial == 'biometric-comparison-vot'
    end

    def does_not_require_biometric_vot?(ial)
      !requires_biometric_vot?(ial)
    end

    def requires_enhanced_ipp?(ial)
      return false if config.vtr_disabled?
      ial == 'enhanced-ipp-required'
    end

    def does_not_require_enhanced_ipp?(ial)
      !requires_enhanced_ipp?(ial)
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

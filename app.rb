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
  class AppError < StandardError; end

  class OpenidConnectRelyingParty < Sinatra::Base
    set :erb, escape_html: true
    set :logger, proc { Logger.new(ENV['RACK_ENV'] == 'test' ? nil : $stdout) }

    enable :sessions

    configure :development do
      require 'byebug'
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
        ial_url: authorization_url(ial: ial, aal: aal),
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

      ial = prepare_step_up_flow(session: session, ial: params[:ial], aal: params[:aal])

      idp_url = authorization_url(
        ial: ial,
        aal: params[:aal],
      )

      settings.logger.info("Redirecting to #{idp_url}")

      redirect to(idp_url)
    end

    get '/auth/result' do
      code = params[:code]

      if code
        token_response = token(code)
        access_token = token_response[:access_token]
        userinfo_response = userinfo(access_token)

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
      else
        error = params[:error] || 'missing callback param: code'

        if error == 'access_denied'
          redirect to('/?error=access_denied')
        else
          erb :errors, locals: { error: error }
        end
      end
    end

    get '/failure_to_proof' do
      erb :failure_to_proof
    end

    get '/logout' do
      session[:logout_msg] = 'ok'
      session.delete(:userinfo)
      session.delete(:email)
      session.delete(:step_up_enabled)
      session.delete(:step_up_aal)
      session.delete(:irs)
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

    def authorization_url(ial:, aal: nil)
      endpoint = openid_configuration[:authorization_endpoint]
      request_params = {
        client_id: client_id,
        response_type: 'code',
        acr_values: acr_values(ial: ial, aal: aal),
        vtr: vtr_value(ial: ial, aal: aal),
        vtm: vtm_value,
        scope: scopes_for(ial),
        redirect_uri: File.join(config.redirect_uri, '/auth/result'),
        state: random_value,
        nonce: random_value,
        prompt: 'select_account',
        biometric_comparison_required: biometric_comparison_required_value(ial),
      }.compact.to_query

      "#{endpoint}?#{request_params}"
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
      case ial
      when '0'
        'openid email social_security_number x509'
      when '1', nil
        'openid email x509'
      when '2', 'biometric-comparison-required'
        'openid email profile social_security_number phone address x509'
      else
        raise ArgumentError.new("Unexpected IAL: #{ial.inspect}")
      end
    end

    def acr_values(ial:, aal:)
      return unless config.vtr_disabled?

      values = []

      values << {
        '0' => 'http://idmanagement.gov/ns/assurance/ial/0',
        nil => 'http://idmanagement.gov/ns/assurance/ial/1',
        '' => 'http://idmanagement.gov/ns/assurance/ial/1',
        '1' => 'http://idmanagement.gov/ns/assurance/ial/1',
        '2' => 'http://idmanagement.gov/ns/assurance/ial/2',
        'biometric-comparison-required' => 'http://idmanagement.gov/ns/assurance/ial/2',
      }[ial]

      values << {
        '2' => 'http://idmanagement.gov/ns/assurance/aal/2',
        '2-phishing_resistant' => 'http://idmanagement.gov/ns/assurance/aal/2?phishing_resistant=true',
        '2-hspd12' => 'http://idmanagement.gov/ns/assurance/aal/2?hspd12=true',
      }[aal]

      values.compact.join(' ')
    end

    def vtr_value(ial:, aal:)
      return if config.vtr_disabled?

      values = ['C1']

      values << {
        '2' => 'C2',
        '2-phishing_resistant' => 'C2.Ca',
        '2-hspd12' => 'C2.Cb',
      }[aal]

      values << {
        '2' => 'P1',
        'biometric-comparison-required' => 'P1.Pb',
      }[ial]

      [values.compact.join('.')].to_json
    end

    def vtm_value
      return if config.vtr_disabled?
      'https://developer.login.gov/vot-trust-framework'
    end

    def biometric_comparison_required_value(ial)
      return unless config.vtr_disabled?
      ial == 'biometric-comparison-required'
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
      json Faraday.post(
        openid_configuration[:token_endpoint],
        grant_type: 'authorization_code',
        code: code,
        client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        client_assertion: client_assertion_jwt,
      ).body
    end

    def client_assertion_jwt
      jwt_payload = {
        iss: client_id,
        sub: client_id,
        aud: openid_configuration[:token_endpoint],
        jti: random_value,
        nonce: random_value,
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

      config.client_id
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

    def maybe_redact_ssn(ssn)
      if config.redact_ssn?
        # redact all characters since they're all sensitive
        ssn = ssn&.gsub(/\d/, '#')
      end

      ssn
    end
  end
end
